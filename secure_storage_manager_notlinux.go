//go:build !linux

package gosnowflake

import (
	"runtime"
	"sync"

	"github.com/99designs/keyring"
)

// dbt-only: upstream returns a keyring-based manager on darwin and windows. dbt
// uses the file cache on every platform — the keyring backends prompt
// interactively (macOS Keychain) and cannot be shared between processes the way
// the lease-protected file cache can. Body mirrors the linux implementation.
func defaultOsSpecificSecureStorageManager() secureStorageManager {
	if !isCacheSupportedGOOS(runtime.GOOS) {
		logger.Debugf("OS %v does not support credentials cache", runtime.GOOS)
		return newNoopSecureStorageManager()
	}
	logger.Debugf("OS is %v, using file based secure storage manager.", runtime.GOOS)
	ssm, err := newFileBasedSecureStorageManager()
	if err != nil {
		logger.Debugf("failed to create credentials cache dir: %v. Not storing credentials locally.", err)
		return newNoopSecureStorageManager()
	}
	return &threadSafeSecureStorageManager{&sync.Mutex{}, ssm}
}

// dbt-only: everything below is unreferenced and retained deliberately, to track
// upstream rather than diverge. dbt never selects the keyring backend.
type keyringSecureStorageManager struct {
}

func newKeyringBasedSecureStorageManager() *keyringSecureStorageManager {
	return &keyringSecureStorageManager{}
}

func (ssm *keyringSecureStorageManager) setCredential(tokenSpec secureTokenSpec, value string) {
	if value == "" {
		logger.Debug("no token provided")
	} else {
		credentialsKey, err := tokenSpec.buildKey()
		if err != nil {
			logger.Warnf("cannot build token spec: %v", err)
			return
		}
		switch runtime.GOOS {
		case "windows":
			ring, _ := keyring.Open(keyring.Config{
				WinCredPrefix: credentialsKey,
				ServiceName:   credentialsKey,
			})
			item := keyring.Item{
				Key:  credentialsKey,
				Data: []byte(value),
			}
			if err := ring.Set(item); err != nil {
				logger.Debugf("Failed to write to Windows credential manager. Err: %v", err)
			}
		case "darwin":
			ring, _ := keyring.Open(keyring.Config{
				ServiceName: credentialsKey,
			})
			item := keyring.Item{
				Key:  credentialsKey,
				Data: []byte(value),
			}
			if err := ring.Set(item); err != nil {
				logger.Debugf("Failed to write to keychain. Err: %v", err)
			}
		}
	}
}

func (ssm *keyringSecureStorageManager) getCredential(tokenSpec secureTokenSpec) string {
	cred := ""
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warnf("cannot build token spec: %v", err)
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		ring, _ := keyring.Open(keyring.Config{
			WinCredPrefix: credentialsKey,
			ServiceName:   credentialsKey,
		})
		i, err := ring.Get(credentialsKey)
		if err != nil {
			logger.Debugf("Failed to read credentialsKey or could not find it in Windows Credential Manager. Error: %v", err)
		}
		cred = string(i.Data)
	case "darwin":
		ring, _ := keyring.Open(keyring.Config{
			ServiceName: credentialsKey,
		})
		i, err := ring.Get(credentialsKey)
		if err != nil {
			logger.Debugf("Failed to find the item in keychain or item does not exist. Error: %v", err)
		}
		cred = string(i.Data)
		if cred == "" {
			logger.Debug("Returned credential is empty")
		} else {
			logger.Debug("Successfully read token. Returning as string")
		}
	}
	return cred
}

func (ssm *keyringSecureStorageManager) deleteCredential(tokenSpec secureTokenSpec) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warnf("cannot build token spec: %v", err)
		return
	}
	switch runtime.GOOS {
	case "windows":
		ring, _ := keyring.Open(keyring.Config{
			WinCredPrefix: credentialsKey,
			ServiceName:   credentialsKey,
		})
		err := ring.Remove(credentialsKey)
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in Windows Credential Manager. Error: %v", err)
		}
	case "darwin":
		ring, _ := keyring.Open(keyring.Config{
			ServiceName: credentialsKey,
		})
		err := ring.Remove(credentialsKey)
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in keychain. Error: %v", err)
		}
	}
}
