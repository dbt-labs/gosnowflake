package gosnowflake

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	leaseTTL              = 10 * time.Second
	leaseOperationTimeout = 60 * time.Second

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

func credCacheDirPath() (string, error) {
	switch runtime.GOOS {
	case "linux":
		return buildCredCacheDirPath(defaultLinuxCacheDirConf)
	case "darwin":
		return buildCredCacheDirPath(defaultMacCacheDirConf)
	case "windows":
		path, err := getLocalAppDataPath()
		if err != nil {
			return "", fmt.Errorf("failed to get Local/AppData folder: %v", err)
		}
		path = filepath.Join(path, "Snowflake", "Credentials")
		return ensureCacheDir(path)
	default:
		return "", fmt.Errorf("unsupported OS %v for credentials cache", runtime.GOOS)
	}
}

type secureStorageManager interface {
	acquireLease() (*Lease, error)
	setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error
	getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error)
	deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error
}

var credentialsStorage = newSecureStorageManager()

func newSecureStorageManager() secureStorageManager {
	var ssm secureStorageManager
	var err error
	if isCacheSupportedGOOS(runtime.GOOS) {
		ssm, err = newFileBasedSecureStorageManager()
	} else {
		logger.Warnf("OS %v does not support credentials cache", runtime.GOOS)
		ssm = newNoopSecureStorageManager()
	}

	if err != nil {
		logger.Warnf("Failed to create secure storage manager: %v", err)
		ssm = newNoopSecureStorageManager()
	}
	return ssm
}

type fileBasedSecureStorageManager struct {
	credDirPath  string
	leaseHandler *LeaseHandler
}

func newFileBasedSecureStorageManager() (*fileBasedSecureStorageManager, error) {
	credDirPath, err := credCacheDirPath()
	if err != nil {
		return nil, err
	}
	leaseHandler, err := NewLeaseHandler(filepath.Join(credDirPath, credLeaseFileName), leaseOperationTimeout)
	if err != nil {
		return nil, err
	}
	ssm := &fileBasedSecureStorageManager{
		credDirPath:  credDirPath,
		leaseHandler: leaseHandler,
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
	return ensureCacheDir(cacheDir)
}

func ensureCacheDir(cacheDir string) (string, error) {
	sep := string(os.PathSeparator)
	parentOfCacheDir := cacheDir[:strings.LastIndex(cacheDir, sep)]

	if err := os.MkdirAll(parentOfCacheDir, os.FileMode(0755)); err != nil {
		return "", err
	}

	// We don't check if permissions are incorrect here if a directory exists, because we check it later.
	if err := os.Mkdir(cacheDir, os.FileMode(0700)); err != nil && !errors.Is(err, os.ErrExist) {
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

func (ssm *fileBasedSecureStorageManager) withCacheFile(lease *Lease, action func(*os.File) error) error {
	err := lease.Renew(leaseTTL / 2)
	if err != nil {
		logger.Warnf("Unable to lease cache. %v", err)
		return err
	}

	// Users may manually create or save over the credential cache file leading to the presence of
	// a zombie cache file with no path to recovery. This gives a path to recovery.
	// If the file exists, try to secure its perms before opening
	path := ssm.credFilePath()
	if _, statErr := os.Stat(path); statErr == nil {
		if chmodErr := os.Chmod(path, 0600); chmodErr == nil {
			logger.Infof("Set existing cache file %v to 0600 permissions (owner read/write only)", path)
		} else {
			logger.Warnf("could not force 0600 on existing cache file %v: %v", path, chmodErr)
		}
	}

	cacheFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		logger.Warnf("cannot access %v. %v", path, err)
		return err
	}
	defer func(file *os.File) {
		if err := file.Close(); err != nil {
			logger.Warnf("cannot release file descriptor for %v. %v", path, err)
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

	// Ensure secure permissions on POSIX systems. On Windows, the Windows Data
	// Protection API is used to secure the credentials (more secure than file
	// permissions).
	if runtime.GOOS != "windows" {
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
	}

	return action(cacheFile)
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

	return ssm.withCacheFile(lease, func(cacheFile *os.File) error {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file: %v", err)
			return err
		}
		tokens := ssm.getTokens(credCache)
		tokens[credentialsKey] = value
		credCache["tokens"] = tokens

		return ssm.writeTemporaryCacheFile(credCache, cacheFile)
	})
}

func (ssm *fileBasedSecureStorageManager) getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		return "", err
	}

	ret := ""
	err = ssm.withCacheFile(lease, func(cacheFile *os.File) error {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file. %v", err)
			return err
		}
		cred, ok := ssm.getTokens(credCache)[credentialsKey]
		if !ok {
			return nil
		}

		credStr, ok := cred.(string)
		if !ok {
			return nil
		}

		ret = credStr
		return nil
	})
	return ret, err
}

func (ssm *fileBasedSecureStorageManager) credFilePath() string {
	return filepath.Join(ssm.credDirPath, credCacheFileName)
}

func ensureFileOwner(f *os.File) error {
	ownerUID, err := provideFileOwner(f)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	currentUser, err := user.Current()
	if err != nil {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if strconv.Itoa(int(ownerUID)) != currentUser.Uid {
		return errors.New("incorrect owner of " + f.Name())
	}
	return nil
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
	data, err := io.ReadAll(cacheFile)
	if err != nil {
		logger.Warnf("Failed to read credential cache file. %v.\n", err)
		return map[string]any{}, nil
	}
	if _, err = cacheFile.Seek(0, 0); err != nil {
		return map[string]any{}, fmt.Errorf("cannot seek to the beginning of a cache file. %v", err)
	}

	credentialsMap, err := unmarshalCredentialsData(data)
	if err != nil {
		return map[string]any{}, err
	}
	return credentialsMap, nil
}

func (ssm *fileBasedSecureStorageManager) deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return err
	}

	return ssm.withCacheFile(lease, func(cacheFile *os.File) error {
		credCache, err := ssm.readTemporaryCacheFile(cacheFile)
		if err != nil {
			logger.Warnf("Error while reading cache file. %v", err)
			return err
		}
		delete(ssm.getTokens(credCache), credentialsKey)

		return ssm.writeTemporaryCacheFile(credCache, cacheFile)
	})
}

func (ssm *fileBasedSecureStorageManager) writeTemporaryCacheFile(cache map[string]any, cacheFile *os.File) error {
	if err := cacheFile.Truncate(0); err != nil {
		return fmt.Errorf("error while truncating credentials cache. %v", err)
	}

	bytes, err := marshalCredentialsData(cache)
	if err != nil {
		return err
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

type threadSafeSecureStorageManager struct {
	mu       *sync.Mutex
	delegate secureStorageManager
}

func (ssm *threadSafeSecureStorageManager) acquireLease() (*Lease, error) {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	return ssm.delegate.acquireLease()
}

func (ssm *threadSafeSecureStorageManager) setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	return ssm.delegate.setCredential(lease, tokenSpec, value)
}

func (ssm *threadSafeSecureStorageManager) getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error) {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	return ssm.delegate.getCredential(lease, tokenSpec)
}

func (ssm *threadSafeSecureStorageManager) deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error {
	ssm.mu.Lock()
	defer ssm.mu.Unlock()
	return ssm.delegate.deleteCredential(lease, tokenSpec)
}
