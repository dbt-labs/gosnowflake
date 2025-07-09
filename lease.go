package gosnowflake

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	leaseSep       = '\n'                // field delimiter inside *.lck
	pollInterval   = 200 * time.Millisecond
	defaultTTL     = 5 * time.Minute    // browser-flow timeout
	defaultTimeout = 30 * time.Second   // how long a waiter will block
)

// Lease represents an on-disk, cross-process mutex.
// It is obtained via (*Lease).Acquire and released with (*Lease).Release.
type Lease struct {
	path  string
	fh    *os.File // open handle that pins the inode
	token string   // 128-bit random nonce proving authorship
}

func NewLease(dir, name string) *Lease {
	return &Lease{path: filepath.Join(dir, name+".lck")}
}

func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func writeLease(f *os.File, exp time.Time, tok string) error {
	if _, err := fmt.Fprintf(f, "%d%c%s%c",
		exp.UnixNano(), leaseSep, tok, leaseSep); err != nil {
		return err
	}
	return f.Sync()
}

func parseLease(b []byte) (exp time.Time, tok string, err error) {
	parts := bytes.SplitN(b, []byte{leaseSep}, 3)
	if len(parts) < 2 {
		return time.Time{}, "", errors.New("corrupt lease")
	}
	n, err := strconv.ParseInt(string(parts[0]), 10, 64)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Unix(0, n), string(parts[1]), nil
}

func (l *Lease) Acquire(timeout, ttl time.Duration) error {
	deadline := time.Now().Add(timeout)
	tok, err := randomToken()
	if err != nil {
		return err
	}
	l.token = tok

	for time.Now().Before(deadline) {
		now := time.Now()
		exp := now.Add(ttl)

		// 1. try to create the file exclusively -> fast path
		fh, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			if err = writeLease(fh, exp, tok); err != nil {
				fh.Close()
				_ = os.Remove(l.path)
				return err
			}
			l.fh = fh
			return nil
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("lease: %w", err)
		}

		// 2. file exists - check whether it is stale
		b, err := os.ReadFile(l.path)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		prevExp, prevTok, err := parseLease(b)
		if err != nil || now.Before(prevExp) { // busy or unreadable -> wait
			time.Sleep(pollInterval)
			continue
		}

		// 3. attempt to steal the stale lease
		fh, err = os.OpenFile(l.path, os.O_RDWR, 0)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		// re-read to verify nothing changed since our earlier read
		cur, _ := io.ReadAll(fh)
		curExp, curTok, err := parseLease(cur)
		if err != nil || !now.After(curExp) || curTok != prevTok {
			fh.Close()
			time.Sleep(pollInterval)
			continue
		}

		// still stale - truncate in place, then write our data
		if err = fh.Truncate(0); err != nil {
			fh.Close()
			time.Sleep(pollInterval)
			continue
		}
		if _, err = fh.Seek(0, io.SeekStart); err != nil {
			fh.Close()
			time.Sleep(pollInterval)
			continue
		}
		if err = writeLease(fh, exp, tok); err != nil {
			fh.Close()
			time.Sleep(pollInterval)
			continue
		}
		l.fh = fh
		return nil
	}
	return fmt.Errorf("timeout acquiring %s", l.path)
}

// Release closes the FD and deletes the lock file **only** if we
// are still the owner (token matches).  Best-effort.
func (l *Lease) Release() error {
	if l.fh != nil {
		_ = l.fh.Close()
		l.fh = nil
	}

	b, err := os.ReadFile(l.path)
	if err != nil {
		return nil // already gone
	}
	_, tok, _ := parseLease(b)
	if tok == l.token {
		_ = os.Remove(l.path)
	}
	return nil
}

// Renew extends the expiry by ttl, keeping the same token.  Callers that may
// run > defaultTTL should spawn a goroutine that calls Renew every ttl/2.
// This should be safe to call even if the lease was already stolen (no-op).
func (l *Lease) Renew(ttl time.Duration) error {
	if l.fh == nil {
		return errors.New("lease not held")
	}
	exp := time.Now().Add(ttl)
	if _, err := l.fh.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := l.fh.Truncate(0); err != nil {
		return err
	}
	return writeLease(l.fh, exp, l.token)
}
