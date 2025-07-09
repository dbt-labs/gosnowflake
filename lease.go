package gosnowflake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	pollInterval   = 200 * time.Millisecond
)

type (
	Lease struct {
		path string   // absolute path to the *.lck file
		fh   *os.File // open handle, kept to hold the lock
	}
)

func NewLease(dir, name string) *Lease {
	return &Lease{path: filepath.Join(dir, name+".lck")}
}

func (l *Lease) Acquire(timeout, ttl time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		now := time.Now()
		exp := now.Add(ttl)

		fh, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		switch {
		case err == nil:
			_, _ = fh.WriteString(strconv.FormatInt(exp.UnixNano(), 10))
			l.fh = fh
			return nil
		case !errors.Is(err, os.ErrExist):
			return fmt.Errorf("lease: %w", err)
		}

		// File exists → check expiry and maybe steal it.
		b, err := os.ReadFile(l.path)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		prevExp, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if now.Before(time.Unix(0, prevExp)) { // still valid
			time.Sleep(pollInterval)
			continue
		}

		// Stale lease → truncate and claim
		fh, err = os.OpenFile(l.path, os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		_, err = fh.WriteString(strconv.FormatInt(exp.UnixNano(), 10))
		if err != nil {
			_ = fh.Close()
			time.Sleep(pollInterval)
			continue
		}
		l.fh = fh
		return nil
	}
	return fmt.Errorf("timeout acquiring %s", l.path)
}

// Release removes the *.lck file (best-effort) and closes the FD.
func (l *Lease) Release() error {
	_ = l.fh.Close()
	return os.Remove(l.path)
}
