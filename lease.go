package gosnowflake

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	gracePeriod                  = 10 * time.Millisecond
	pollInterval                 = 200 * time.Millisecond
	DefaultLeaseOperationTimeout = 30 * time.Second
)

// File-based lease [1].
//
// [1] https://en.wikipedia.org/wiki/Lease_(computer_science)
type Lease struct {
	path    string        // absolute path to the lease file
	timeout time.Duration // how long to keep trying to acquire or renew the lease
}

func NewLease(path string, timeout time.Duration) (*Lease, error) {
	abspath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("lease: %w", err)
	}
	if timeout < time.Second {
		timeout = time.Second // at least 1 second timeout
	}
	return &Lease{path: abspath, timeout: timeout}, nil
}

func genRandomLeaseId() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Update the contents of the lease file with the given leaseId and expiry.
func (l *Lease) write(leaseId *string, expiry time.Time, asNewFile bool) error {
	if !asNewFile {
		_ = os.Remove(l.path)
	}
	flags := os.O_WRONLY | os.O_TRUNC | os.O_CREATE | os.O_EXCL // fail if file already exists
	f, err := os.OpenFile(l.path, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s\r\n%d\r\n", *leaseId, expiry.UnixMilli()); err != nil {
		return err
	}
	return f.Close()
}

// Read the current lease ID and expiry time from the lease file.
func (l *Lease) read() (string, time.Time, error) {
	f, err := os.OpenFile(l.path, os.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return "", time.Time{}, nil // no lease file
	}
	// read the file contents into a small buffer
	data := make([]byte, 0, 512)
	for {
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}

		if len(data) >= cap(data) {
			// lease file is too large (unexpected), delete it
			_ = f.Close()
			_ = os.Remove(l.path)
			return "", time.Time{}, nil // as if it never existed
		}
	}
	if err != nil {
		_ = f.Close()
		return "", time.Time{}, err
	}
	// parse the lease file contents
	parts := bytes.SplitN(data, []byte{'\r', '\n'}, 3)
	if len(parts) < 2 {
		// corrupt lease file, delete it
		_ = f.Close()
		_ = os.Remove(l.path)
		return "", time.Time{}, nil // as if it never existed
	}
	leaseId := string(parts[0])
	expiryMillis, parseErr := strconv.ParseInt(string(parts[1]), 10, 64)
	if parseErr != nil {
		// corrupt lease file, delete it
		_ = f.Close()
		_ = os.Remove(l.path)
		return "", time.Time{}, nil // as if it never existed
	}
	sec := expiryMillis / 1000
	nsec := (expiryMillis % 1000) * 1_000_000
	expiry := time.Unix(sec, nsec)
	_ = f.Close()
	return leaseId, expiry, nil
}

func (l *Lease) Acquire(ttl time.Duration) (string, error) {
	newLeaseId, err := genRandomLeaseId()
	if err != nil {
		return "", fmt.Errorf("lease: %w", err)
	}

	deadline := time.Now().Add(l.timeout)
	for time.Now().Before(deadline) {
		leaseId, expiry, err := l.read()
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		// 1. empty lease file
		if leaseId == "" {
			newExpiry, asNewFile := time.Now().Add(ttl), true
			err = l.write(&newLeaseId, newExpiry, asNewFile)
			if err != nil {
				time.Sleep(pollInterval)
			}
			continue
		}
		// 2. lease successfully written and read once
		if leaseId == newLeaseId {
			return newLeaseId, nil
		}
		// 3. current lease is still valid
		if time.Now().Before(expiry) {
			time.Sleep(pollInterval)
			continue
		}
		// 4. existing lease is expired
		newExpiry, asNewFile := time.Now().Add(ttl), false
		err = l.write(&newLeaseId, newExpiry, asNewFile)
		if err != nil {
			time.Sleep(pollInterval)
		}
		continue
	}

	// final check after the timeout
	leaseId, _, err := l.read()
	if err == nil && leaseId == newLeaseId {
		return newLeaseId, nil // successfully acquired the lease
	}
	return "", fmt.Errorf("timed out trying to acquire lease after %s: %s", l.timeout, l.path)
}

// Ensure the lease will be valid for at least the given ttl. Users should call
// this periodically to keep the lease alive (e.g. every ttl/2 units of time).
func (l *Lease) Renew(leaseId *string, ttl time.Duration) error {
	now := time.Now()
	newExpiry := now.Add(ttl)

	deadline := now.Add(l.timeout)
	for time.Now().Before(deadline) {
		currentLeaseId, expiry, err := l.read()
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		// 1. lease is now different or expired
		if currentLeaseId != *leaseId || time.Now().Add(gracePeriod).After(expiry) {
			return fmt.Errorf("lease %s has expired: %s", *leaseId, l.path)
		}
		// 2. lease reached the desired expiry or later in the future
		if expiry.Compare(newExpiry) >= 0 {
			return nil
		}
		// 3. leaseId is still valid, so we can renew it
		err = l.write(leaseId, newExpiry, false)
		if err != nil {
			time.Sleep(pollInterval)
			continue // retry on write error
		}
	}
	return fmt.Errorf("timed out trying to renew lease: %s", l.path)
}

// Makes an effort to release the given leaseId to help other processes acquire it sooner.
func (l *Lease) Release(leaseId *string) {
	currentLeaseId, expiry, err := l.read()
	if currentLeaseId == "" || err != nil {
		return
	}
	if currentLeaseId == *leaseId && time.Now().Add(gracePeriod).Before(expiry) {
		_ = os.Remove(l.path)
	}
}
