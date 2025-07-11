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
	acquireLease() (*Lease, error)
	setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error
	getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error)
	deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error
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
	credDirPath  string
	leaseHandler *LeaseHandler
}

func newFileBasedSecureStorageManager() (*fileBasedSecureStorageManager, error) {
	credDirPath, err := buildCredCacheDirPath(defaultUnixCacheDirConf())
	if err != nil {
		return nil, err
	}
	lease, err := NewLeaseHandler(filepath.Join(credDirPath, credLeaseFileName), DefaultLeaseOperationTimeout)
	if err != nil {
		return nil, err
	}
	ssm := &fileBasedSecureStorageManager{
		credDirPath:  credDirPath,
		leaseHandler: lease,
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

func (ssm *fileBasedSecureStorageManager) acquireLease() (*Lease, error) {
	return ssm.leaseHandler.Acquire(leaseTTL)
}

func (ssm *fileBasedSecureStorageManager) withCacheFile(lease *Lease, action func(*os.File)) error {
	err := lease.Renew(leaseTTL / 2)
	if err != nil {
		logger.Warnf("Unable to lease cache. %v", err)
		return err
	}
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

func (ssm *fileBasedSecureStorageManager) setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error {
	// Skip caching when the MFA token is empty.
	// This can occur in successful auth scenarios where:
	// 1. Snowflake reuses a valid recent MFA session and returns an empty "mfaToken".
	// 2. The MFA provider (e.g., Duo) determines that no challenge is needed.
	if value == "" {
		logger.Debug("No token provided. Will not create or modify existing mfa token cache file.")
		return nil
	}

	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return err
	}

	return ssm.withCacheFile(lease, func(cacheFile *os.File) {
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

func (ssm *fileBasedSecureStorageManager) getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		return "", err
	}

	ret := ""
	err = ssm.withCacheFile(lease, func(cacheFile *os.File) {
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

func (ssm *fileBasedSecureStorageManager) deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return err
	}

	return ssm.withCacheFile(lease, func(cacheFile *os.File) {
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

type noopSecureStorageManager struct {
}

func (ssm *noopSecureStorageManager) acquireLease() (*Lease, error) {
	return nil, nil // no-op implementation for secure storage manager
}

func newNoopSecureStorageManager() *noopSecureStorageManager {
	return &noopSecureStorageManager{}
}

func (ssm *noopSecureStorageManager) setCredential(_ *Lease, _ *secureTokenSpec, _ string) error {
	return nil
}

func (ssm *noopSecureStorageManager) getCredential(_ *Lease, _ *secureTokenSpec) (string, error) {
	return "", nil // no-op implementation for secure storage manager
}

func (ssm *noopSecureStorageManager) deleteCredential(_ *Lease, _ *secureTokenSpec) error {
	return nil
}
