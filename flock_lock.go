// +build !windows

// for *nix only

package gosnowflake

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// withFlockFile is a drop-in replacement for withLock.  The action
// executes while holding an OS-level advisory lock on a regular file
// named `credential_cache_v1.lock`.
func (ssm *fileBasedSecureStorageManager) withFlockFile(action func(cacheFile *os.File)) {
	lf, err := ssm.flockLockFile()
	if err != nil {
		logger.Warnf("Unable to obtain flock: %v", err)
		return
	}
	defer ssm.flockUnlockFile(lf)

	ssm.withCacheFile(action)
}

func (ssm *fileBasedSecureStorageManager) flockLockFile() (*os.File, error) {
	lockPath := filepath.Join(ssm.credDirPath, "credential_cache_v1.lock")

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("flock EX: %w", err)
	}
	return f, nil
}

func (ssm *fileBasedSecureStorageManager) flockUnlockFile(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}
