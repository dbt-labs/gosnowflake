//go:build linux

package gosnowflake

import (
	"runtime"
)

func defaultOsSpecificSecureStorageManager() secureStorageManager {
	logger.Debugf("OS is %v, using file based secure storage manager.", runtime.GOOS)
	ssm, err := newFileBasedSecureStorageManager()
	if err != nil {
		logger.Debugf("failed to create credentials cache dir: %v. Not storing credentials locally.", err)
		return newNoopSecureStorageManager()
	}
	// dbt-only: returned unwrapped. The lease arbitrates on file content, so it
	// serialises goroutines as well as processes, and ConfigureLeaseOnce needs to
	// reach the concrete manager.
	return ssm
}
