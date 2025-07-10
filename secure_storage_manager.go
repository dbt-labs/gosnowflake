package gosnowflake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	leaseTTL          = 10 * time.Second
	shortLeaseTTL     = leaseTTL / 2
	credCacheDirEnv   = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR"
	credLeaseFileName = "credential_cache.lease"
	credCacheFileName = "credential_cache_v1.json"
)

type cacheDirConf struct {
	envVar       string
	pathSegments []string
}

var defaultLinuxCacheDirConf = []cacheDirConf{
	{envVar: credCacheDirEnv, pathSegments: []string{}},
	{envVar: "XDG_CACHE_DIR", pathSegments: []string{"snowflake"}},
	{envVar: "HOME", pathSegments: []string{".cache", "snowflake"}},
}

var defaultMacCacheDirConf = []cacheDirConf{
	{envVar: credCacheDirEnv, pathSegments: []string{}},
	// NOTE: Caches/Snowflake/Credentials is used instead of simply Caches/Snowflake/
	// so that more restrictive permissions can be set on the directory.
	{envVar: "HOME", pathSegments: []string{"Library", "Caches", "Snowflake", "Credentials"}},
}

func defaultUnixCacheDirConf() []cacheDirConf {
	if runtime.GOOS == "darwin" {
		return defaultMacCacheDirConf
	}
	return defaultLinuxCacheDirConf
}

type secureStorageManager interface {
	acquireLease() (string, error)
	setCredential(leaseId *string, tokenSpec *secureTokenSpec, value string)
	getCredential(leaseId *string, tokenSpec *secureTokenSpec) (string, error)
	deleteCredential(leaseId *string, tokenSpec *secureTokenSpec)
	releaseLease(leaseId *string)
}

var credentialsStorage = newSecureStorageManager()

func newSecureStorageManager() secureStorageManager {
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		ssm, err := newFileBasedSecureStorageManager()
		if err != nil {
			logger.Debugf("failed to create credentials cache dir. %v", err)
			return newNoopSecureStorageManager()
		}
		return ssm
	default:
		logger.Warnf("OS %v does not support credentials cache", runtime.GOOS)
		return newNoopSecureStorageManager()
	}
}

type fileBasedSecureStorageManager struct {
	credDirPath string
	lease       *Lease
}

func newFileBasedSecureStorageManager() (*fileBasedSecureStorageManager, error) {
	credDirPath, err := buildCredCacheDirPath(defaultUnixCacheDirConf())
	if err != nil {
		return nil, err
	}
	lease, err := NewLease(filepath.Join(credDirPath, credLeaseFileName), DefaultLeaseOperationTimeout)
	if err != nil {
		return nil, err
	}
	ssm := &fileBasedSecureStorageManager{
		credDirPath: credDirPath,
		lease:       lease,
	}
	return ssm, nil
}

func lookupCacheDir(envVar string, pathSegments ...string) (string, error) {
	envVal := os.Getenv(envVar)
	if envVal == "" {
		return "", fmt.Errorf("environment variable %s not set", envVar)
	}

	fileInfo, err := os.Stat(envVal)
	if err != nil {
		return "", fmt.Errorf("failed to stat %s=%s, due to %v", envVar, envVal, err)
	}

	if !fileInfo.IsDir() {
		return "", fmt.Errorf("environment variable %s=%s is not a directory", envVar, envVal)
	}

	cacheDir := filepath.Join(envVal, filepath.Join(pathSegments...))
	parentOfCacheDir := cacheDir[:strings.LastIndex(cacheDir, "/")]

	if err = os.MkdirAll(parentOfCacheDir, os.FileMode(0755)); err != nil {
		return "", err
	}

	// We don't check if permissions are incorrect here if a directory exists, because we check it later.
	if err = os.Mkdir(cacheDir, os.FileMode(0700)); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	return cacheDir, nil
}

func buildCredCacheDirPath(confs []cacheDirConf) (string, error) {
	for _, conf := range confs {
		path, err := lookupCacheDir(conf.envVar, conf.pathSegments...)
		if err != nil {
			logger.Debugf("Skipping %s in cache directory lookup due to %v", conf.envVar, err)
		} else {
			logger.Debugf("Using %s as cache directory", path)
			return path, nil
		}
	}

	return "", errors.New("no credentials cache directory found")
}

func (ssm *fileBasedSecureStorageManager) getTokens(data map[string]any) map[string]interface{} {
	val, ok := data["tokens"]
	if !ok {
		return map[string]interface{}{}
	}

	tokens, ok := val.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}

	return tokens
}

func (ssm *fileBasedSecureStorageManager) acquireLease() (string, error) {
	return ssm.lease.Acquire(leaseTTL)
}

func (ssm *fileBasedSecureStorageManager) withLease(leaseId *string, action func(cacheFile *os.File)) error {
	err := ssm.lease.Renew(leaseId, shortLeaseTTL)
	if err != nil {
		logger.Warnf("Unable to lease cache. %v", err)
		return err
	}

	return ssm.withCacheFile(action)
}

func (ssm *fileBasedSecureStorageManager) withCacheFile(action func(*os.File)) error {
	cacheFile, err := os.OpenFile(ssm.credFilePath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		logger.Warnf("cannot access %v. %v", ssm.credFilePath(), err)
		return err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			logger.Warnf("cannot release file descriptor for %v. %v", ssm.credFilePath(), err)
		}
	}(cacheFile)

	cacheDir, err := os.Open(ssm.credDirPath)
	if err != nil {
		logger.Warnf("cannot access %v. %v", ssm.credDirPath, err)
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			logger.Warnf("cannot release file descriptor for %v. %v", cacheDir, err)
		}
	}(cacheDir)

	if err := ensureFileOwner(cacheFile); err != nil {
		logger.Warnf("failed to ensure owner for temporary cache file. %v", err)
		return err
	}
	if err := ensureFilePermissions(cacheFile, 0600); err != nil {
		logger.Warnf("failed to ensure permission for temporary cache file. %v", err)
		return err
	}
	if err := ensureFileOwner(cacheDir); err != nil {
		logger.Warnf("failed to ensure owner for temporary cache dir. %v", err)
		return err
	}
	if err := ensureFilePermissions(cacheDir, 0700|os.ModeDir); err != nil {
		logger.Warnf("failed to ensure permission for temporary cache dir. %v", err)
		return err
	}

	action(cacheFile)
	return nil
}

func (ssm *fileBasedSecureStorageManager) setCredential(leaseId *string, tokenSpec *secureTokenSpec, value string) {
	// Skip caching when the MFA token is empty.
	// This can occur in successful auth scenarios where:
	// 1. Snowflake reuses a valid recent MFA session and returns an empty "mfaToken".
	// 2. The MFA provider (e.g., Duo) determines that no challenge is needed.
	if value == "" {
		logger.Debug("No token provided. Will not create or modify existing mfa token cache file.")
		return
	}

	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return
	}

	_ = ssm.withLease(leaseId, func(cacheFile *os.File) {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file: %v", err)
			return
		}
		tokens := ssm.getTokens(credCache)
		tokens[credentialsKey] = value
		credCache["tokens"] = tokens

		if err := ssm.writeTemporaryCacheFile(credCache, cacheFile); err != nil {
			logger.Warnf("Set credential failed: %v", err)
		}
	})
}

// func (ssm *fileBasedSecureStorageManager) lockPath() string {
// 	return filepath.Join(ssm.credDirPath, credCacheFileName+".lck")
// }

// func (ssm *fileBasedSecureStorageManager) lockFile() error {
// 	const numRetries = 10
// 	const retryInterval = 100 * time.Millisecond
// 	lockPath := ssm.lockPath()

// 	lockFile, err := os.Open(lockPath)
// 	if err != nil && !errors.Is(err, os.ErrNotExist) {
// 		return fmt.Errorf("failed to open %v. err: %v", lockPath, err)
// 	}
// 	defer func() {
// 		err = lockFile.Close()
// 		if err != nil {
// 			logger.Debugf("error while closing lock file. %v", err)
// 		}
// 	}()

// 	if err == nil { // file exists
// 		fileInfo, err := lockFile.Stat()
// 		if err != nil {
// 			return fmt.Errorf("failed to stat %v and determine if lock is stale. err: %v", lockPath, err)
// 		}

// 		ownerUID, err := provideFileOwner(lockFile)
// 		if err != nil && !errors.Is(err, os.ErrNotExist) {
// 			return err
// 		}
// 		currentUser, err := user.Current()
// 		if err != nil {
// 			return err
// 		}
// 		if strconv.Itoa(int(ownerUID)) != currentUser.Uid {
// 			return errors.New("incorrect owner of " + lockFile.Name())
// 		}

// 		// removing stale lock
// 		now := time.Now()
// 		if fileInfo.ModTime().Add(time.Second).UnixNano() < now.UnixNano() {
// 			logger.Debugf("removing credentials cache lock file, stale for %vms", (now.UnixNano()-fileInfo.ModTime().UnixNano())/1000/1000)
// 			err = os.Remove(lockPath)
// 			if err != nil {
// 				return fmt.Errorf("failed to remove %v while trying to remove stale lock. err: %v", lockPath, err)
// 			}
// 		}
// 	}

// 	locked := false
// 	for i := 0; i < numRetries; i++ {
// 		err := os.Mkdir(lockPath, 0700)
// 		if err != nil {
// 			if errors.Is(err, os.ErrExist) {
// 				time.Sleep(retryInterval)
// 				continue
// 			}
// 			return fmt.Errorf("failed to create cache lock: %v, err: %v", lockPath, err)
// 		}
// 		locked = true
// 		break
// 	}
// 	if !locked {
// 		return fmt.Errorf("failed to lock cache. lockPath: %v", lockPath)
// 	}
// 	return nil
// }
//
// func (ssm *fileBasedSecureStorageManager) unlockFile() {
// 	lockPath := ssm.lockPath()
// 	err := os.Remove(lockPath)
// 	if err != nil {
// 		logger.Warnf("Failed to unlock cache lock: %v. %v", lockPath, err)
// 	}
// }

func (ssm *fileBasedSecureStorageManager) getCredential(leaseId *string, tokenSpec *secureTokenSpec) (string, error) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		return "", err
	}

	ret := ""
	err = ssm.withLease(leaseId, func(cacheFile *os.File) {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file. %v", err)
			return
		}
		cred, ok := ssm.getTokens(credCache)[credentialsKey]
		if !ok {
			return
		}

		credStr, ok := cred.(string)
		if !ok {
			return
		}

		ret = credStr
	})
	return ret, err
}

func (ssm *fileBasedSecureStorageManager) credFilePath() string {
	return filepath.Join(ssm.credDirPath, credCacheFileName)
}

func ensureFilePermissions(f *os.File, expectedMode os.FileMode) error {
	fileInfo, err := f.Stat()
	if err != nil {
		return err
	}
	if fileInfo.Mode().Perm() != expectedMode&os.ModePerm {
		return fmt.Errorf("incorrect permissions(%v, expected %v) for credential file", fileInfo.Mode(), expectedMode)
	}
	return nil
}

func (ssm *fileBasedSecureStorageManager) readTemporaryCacheFile(cacheFile *os.File) (map[string]any, error) {

	jsonData, err := io.ReadAll(cacheFile)
	if err != nil {
		logger.Warnf("Failed to read credential cache file. %v.\n", err)
		return map[string]any{}, nil
	}
	if _, err = cacheFile.Seek(0, 0); err != nil {
		return map[string]any{}, fmt.Errorf("cannot seek to the beginning of a cache file. %v", err)
	}

	if len(jsonData) == 0 {
		// Happens when the file didn't exist before.
		return map[string]any{}, nil
	}

	credentialsMap := map[string]any{}
	err = json.Unmarshal(jsonData, &credentialsMap)
	if err != nil {
		return map[string]any{}, fmt.Errorf("failed to unmarshal credential cache file. %v", err)
	}

	return credentialsMap, nil
}

func (ssm *fileBasedSecureStorageManager) deleteCredential(leaseId *string, tokenSpec *secureTokenSpec) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return
	}

	_ = ssm.withLease(leaseId, func(cacheFile *os.File) {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file. %v", err)
			return
		}
		delete(ssm.getTokens(credCache), credentialsKey)

		err = ssm.writeTemporaryCacheFile(credCache, cacheFile)
		if err != nil {
			logger.Warnf("Set credential failed. Unable to write cache. %v", err)
		}
	})
}

func (ssm *fileBasedSecureStorageManager) writeTemporaryCacheFile(cache map[string]any, cacheFile *os.File) error {
	bytes, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed to marshal credential cache map. %w", err)
	}

	if err = cacheFile.Truncate(0); err != nil {
		return fmt.Errorf("error while truncating credentials cache. %v", err)
	}
	_, err = cacheFile.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write the credential cache file: %w", err)
	}
	return nil
}

func (ssm *fileBasedSecureStorageManager) releaseLease(leaseId *string) {
	ssm.lease.Release(leaseId)
}

type noopSecureStorageManager struct {
}

func (ssm *noopSecureStorageManager) acquireLease() (string, error) {
	return "", nil // no-op implementation for secure storage manager
}

func newNoopSecureStorageManager() *noopSecureStorageManager {
	return &noopSecureStorageManager{}
}

func (ssm *noopSecureStorageManager) setCredential(_ *string, _ *secureTokenSpec, _ string) {
}

func (ssm *noopSecureStorageManager) getCredential(_ *string, _ *secureTokenSpec) (string, error) {
	return "", nil // no-op implementation for secure storage manager
}

func (ssm *noopSecureStorageManager) deleteCredential(_ *string, _ *secureTokenSpec) {
}

func (ssm *noopSecureStorageManager) releaseLease(_ *string) {
}
