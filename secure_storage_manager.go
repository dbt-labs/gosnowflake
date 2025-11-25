package gosnowflake

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/99designs/keyring"
)

const (
	// accessed through getters that provide an override hook, do not use directly
	_defaultLeaseTTL              = 30 * time.Second
	_defaultLeaseOperationTimeout = 90 * time.Second

	credCacheDirEnv   = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR"
	credLeaseFileName = "credential_cache.lease"
	credCacheFileName = "credential_cache_v1.json"
)

// --- EvalOnce hook to configure lease semantics ------------------------

var (
	_cfgOnce         sync.Once
	_overrideTTL     atomic.Value // stores time.Duration
	_overrideTimeout atomic.Value // ditto
)

// Call once per process.
//
// Ignore 0 values and keep defaults
// Propogate changes to singleton credentialsStorage's LeaseHandler
func ConfigureLeaseOnce(ttl, timeout time.Duration) {
	_cfgOnce.Do(func() {
		if ttl > 0 {
			_overrideTTL.Store(ttl)
		}
		if timeout > 0 {
			_overrideTimeout.Store(timeout)
			// warn: will fail if of other type but this is not dbt's use
			// of the api
			if fb, ok := credentialsStorage.(*fileBasedSecureStorageManager); ok && fb.leaseHandler != nil {
				fb.leaseHandler.SetTimeout(timeout)
			}
		}
	})
}

func leaseTTL() time.Duration {
	if v := _overrideTTL.Load(); v != nil {
		return v.(time.Duration)
	}
	return _defaultLeaseTTL
}

func leaseOperationTimeout() time.Duration {
	if v := _overrideTimeout.Load(); v != nil {
		return v.(time.Duration)
	}
	return _defaultLeaseOperationTimeout
}

// --- CacheDir resolution ------------------------

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
		if dir := os.Getenv(credCacheDirEnv); dir != "" {
			return ensureCacheDir(dir)
		}
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

// Helper fast-paths to minimize lease contention for common operations.
// These acquire a lease only if needed.

// getCredentialFast attempts an in-memory read first (if available),
// otherwise acquires a lease to consult the persistent cache.
func getCredentialFast(tokenSpec *secureTokenSpec) (string, error) {
	// Try in-memory if file-based storage
	if fb, ok := credentialsStorage.(*fileBasedSecureStorageManager); ok {
		key, err := tokenSpec.buildKey()
		if err != nil {
			return "", err
		}
		fb.memMu.RLock()
		if v, ok := fb.mem[key]; ok {
			fb.memMu.RUnlock()
			return v, nil
		}
		fb.memMu.RUnlock()
	}

	// Miss: acquire lease and consult backing store
	lease, err := credentialsStorage.acquireLease()
	if err != nil {
		return "", err
	}
	if lease != nil {
		defer lease.Release()
	}
	return credentialsStorage.getCredential(lease, tokenSpec)
}

func setCredentialWithLease(tokenSpec *secureTokenSpec, value string) error {
	lease, err := credentialsStorage.acquireLease()
	if err != nil {
		return err
	}
	if lease != nil {
		defer lease.Release()
	}
	return credentialsStorage.setCredential(lease, tokenSpec, value)
}

func deleteCredentialWithLease(tokenSpec *secureTokenSpec) error {
	lease, err := credentialsStorage.acquireLease()
	if err != nil {
		return err
	}
	if lease != nil {
		defer lease.Release()
	}
	return credentialsStorage.deleteCredential(lease, tokenSpec)
}

func newSecureStorageManager() secureStorageManager {
	var ssm secureStorageManager
	var err error
	if isCacheSupportedGOOS(runtime.GOOS) {
		ssm, err = newFileBasedSecureStorageManager()
	} else {
		logger.Debugf("OS %v does not support credentials cache", runtime.GOOS)
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
	// in-memory fast path cache to reduce file lock contention within a process
	memMu sync.RWMutex
	mem   map[string]string
}

func newFileBasedSecureStorageManager() (*fileBasedSecureStorageManager, error) {
	credDirPath, err := credCacheDirPath()
	if err != nil {
		return nil, err
	}
	leaseHandler, err := NewLeaseHandler(filepath.Join(credDirPath, credLeaseFileName), leaseOperationTimeout())
	if err != nil {
		return nil, err
	}
	ssm := &fileBasedSecureStorageManager{
		credDirPath:  credDirPath,
		leaseHandler: leaseHandler,
		mem:          make(map[string]string),
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
	return ssm.leaseHandler.Acquire(leaseTTL())
}

func (ssm *fileBasedSecureStorageManager) withCacheFile(lease *Lease, action func(*os.File) error) error {
	err := lease.Renew(leaseTTL() / 2)
	if err != nil {
		logger.Warnf("Unable to lease cache. %v", err)
		return err
	}

	const cachefilePermissions = 0600

	path := ssm.credFilePath()

	cacheFile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, cachefilePermissions)
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

		tryRemediateFilePermissions(cacheFile, cachefilePermissions)
		if err := ensureFilePermissions(cacheFile, cachefilePermissions); err != nil {
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

	// Update in-memory cache fast path first to satisfy concurrent readers
	// in this process without hitting the filesystem.
	if credentialsKey != "" && value != "" {
		ssm.memMu.Lock()
		ssm.mem[credentialsKey] = value
		ssm.memMu.Unlock()
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

func (ssm *fileBasedSecureStorageManager) lockPath() string {
	return filepath.Join(ssm.credDirPath, credCacheFileName+".lck")
}

func (ssm *fileBasedSecureStorageManager) lockFile() error {
	const numRetries = 10
	const retryInterval = 100 * time.Millisecond
	lockPath := ssm.lockPath()

	lockFile, err := os.Open(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to open %v. err: %v", lockPath, err)
	}
	defer func() {
		if lockFile != nil {
			err = lockFile.Close()
			if err != nil {
				logger.Debugf("error while closing lock file. %v", err)
			}
		}
	}()

	if err == nil { // file exists
		fileInfo, err := lockFile.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat %v and determine if lock is stale. err: %v", lockPath, err)
		}

		ownerUID, err := provideFileOwner(lockFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		currentUser, err := user.Current()
		if err != nil {
			return err
		}
		if strconv.Itoa(int(ownerUID)) != currentUser.Uid {
			return errors.New("incorrect owner of " + lockFile.Name())
		}

		// removing stale lock
		now := time.Now()
		if fileInfo.ModTime().Add(time.Second).UnixNano() < now.UnixNano() {
			logger.Debugf("removing credentials cache lock file, stale for %vms", (now.UnixNano()-fileInfo.ModTime().UnixNano())/1000/1000)
			err = os.Remove(lockPath)
			if err != nil {
				return fmt.Errorf("failed to remove %v while trying to remove stale lock. err: %v", lockPath, err)
			}
		}
	}

	locked := false
	for i := 0; i < numRetries; i++ {
		err := os.Mkdir(lockPath, 0700)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				time.Sleep(retryInterval)
				continue
			}
			return fmt.Errorf("failed to create cache lock: %v, err: %v", lockPath, err)
		}
		locked = true
		break
	}
	if !locked {
		return fmt.Errorf("failed to lock cache. lockPath: %v", lockPath)
	}
	return nil
}

func (ssm *fileBasedSecureStorageManager) unlockFile() {
	lockPath := ssm.lockPath()
	err := os.Remove(lockPath)
	if err != nil {
		logger.Warnf("Failed to unlock cache lock: %v. %v", lockPath, err)
	}
}

func (ssm *fileBasedSecureStorageManager) getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error) {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		return "", err
	}

	// Fast path: serve from in-memory cache if present
	ssm.memMu.RLock()
	if v, ok := ssm.mem[credentialsKey]; ok {
		ssm.memMu.RUnlock()
		return v, nil
	}
	ssm.memMu.RUnlock()

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
		// Populate in-memory cache for subsequent readers
		ssm.memMu.Lock()
		ssm.mem[credentialsKey] = credStr
		ssm.memMu.Unlock()
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

// Users may manually create or save over the credential cache file leading to the presence of
// a zombie cache file with no path to recovery. This gives a path to recovery.
// If the file exists, try to secure its perms before opening
func tryRemediateFilePermissions(f *os.File, expectedMode os.FileMode) {
	info, err := f.Stat()
	if err != nil {
		// With an open FD, ENOENT is unlikely; warn on real errors and return.
		if !errors.Is(err, os.ErrNotExist) {
			logger.Warnf("could not stat %s: %v", f.Name(), err)
		}
		return
	}

	current := info.Mode().Perm()
	if current == expectedMode {
		// No-op: silently return
		return
	}

	if chmodErr := f.Chmod(expectedMode); chmodErr == nil {
		logger.Infof("Set existing file %s to %04o permissions", f.Name(), expectedMode)
	} else {
		logger.Warnf("could not force %04o on existing file %s: %v", expectedMode, f.Name(), chmodErr)
	}
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

	// Remove from in-memory cache first
	ssm.memMu.Lock()
	delete(ssm.mem, credentialsKey)
	ssm.memMu.Unlock()

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

type keyringSecureStorageManager struct {
}

func newKeyringBasedSecureStorageManager() *keyringSecureStorageManager {
	return &keyringSecureStorageManager{}
}

func (ssm *keyringSecureStorageManager) acquireLease() (*Lease, error) {
	return &Lease{
		id:      "keyring-lease",
		expiry:  time.Now().Add(time.Duration(math.MaxInt64 / 2)),
		handler: nil,
	}, nil
}

func (ssm *keyringSecureStorageManager) setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error {
	if value == "" {
		logger.Debug("no token provided")
	} else {
		credentialsKey, err := tokenSpec.buildKey()
		if err != nil {
			logger.Warn(err)
			return err
		}
		switch runtime.GOOS {
		case "windows":
			ring, _ := keyring.Open(keyring.Config{
				WinCredPrefix: strings.ToUpper(tokenSpec.host),
				ServiceName:   strings.ToUpper(tokenSpec.user),
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
			account := strings.ToUpper(tokenSpec.user)
			item := keyring.Item{
				Key:  account,
				Data: []byte(value),
			}
			if err := ring.Set(item); err != nil {
				logger.Debugf("Failed to write to keychain. Err: %v", err)
			}
		}
	}
	return nil
}

func (ssm *keyringSecureStorageManager) getCredential(_ *Lease, tokenSpec *secureTokenSpec) (string, error) {
	cred := ""
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return "", nil
	}
	switch runtime.GOOS {
	case "windows":
		ring, _ := keyring.Open(keyring.Config{
			WinCredPrefix: strings.ToUpper(tokenSpec.host),
			ServiceName:   strings.ToUpper(tokenSpec.user),
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
		account := strings.ToUpper(tokenSpec.user)
		i, err := ring.Get(account)
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
	return cred, nil
}

func (ssm *keyringSecureStorageManager) deleteCredential(_ *Lease, tokenSpec *secureTokenSpec) error {
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return nil
	}
	switch runtime.GOOS {
	case "windows":
		ring, _ := keyring.Open(keyring.Config{
			WinCredPrefix: strings.ToUpper(tokenSpec.host),
			ServiceName:   strings.ToUpper(tokenSpec.user),
		})
		err := ring.Remove(string(credentialsKey))
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in Windows Credential Manager. Error: %v", err)
		}
	case "darwin":
		ring, _ := keyring.Open(keyring.Config{
			ServiceName: credentialsKey,
		})
		account := strings.ToUpper(tokenSpec.user)
		err := ring.Remove(account)
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in keychain. Error: %v", err)
		}
	}
	return nil
}

func (ssm *keyringSecureStorageManager) releaseLease(_ *Lease) error {
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
