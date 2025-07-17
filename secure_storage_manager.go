package gosnowflake

import (
	"encoding/json"
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
	"unsafe"

	"github.com/99designs/keyring"
	"golang.org/x/sys/windows"
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
		path, err := getKnownFolderPath(FOLDERID_LocalAppData)
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
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		ssm, err = newFileBasedSecureStorageManager()
	default:
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

	var jsonData []byte
	if runtime.GOOS == "windows" && len(data) > 0 {
		ciphertext := windows.DataBlob{
			Size: uint32(len(data)),
			Data: &data[0],
		}
		plaintext := windows.DataBlob{
			Size: 0,
			Data: nil,
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
		err = windows.CryptUnprotectData(&ciphertext, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &plaintext)
		if err != nil {
			return map[string]any{}, fmt.Errorf("failed to decrypt credential cache file. %v", err)
		}
		jsonData = unsafe.Slice(plaintext.Data, plaintext.Size)
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(plaintext.Data)))
	} else {
		jsonData = data
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
	bytes, err := json.Marshal(cache)
	if err != nil {
		return fmt.Errorf("failed to marshal credential cache map. %w", err)
	}

	if err = cacheFile.Truncate(0); err != nil {
		return fmt.Errorf("error while truncating credentials cache. %v", err)
	}
	if runtime.GOOS == "windows" {
		plaintext := windows.DataBlob{
			Size: uint32(len(bytes)),
			Data: &bytes[0],
		}
		ciphertext := windows.DataBlob{
			Size: 0,
			Data: nil,
		}
		// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
		err = windows.CryptProtectData(&plaintext, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &ciphertext)
		if err != nil {
			return fmt.Errorf("failed to encrypt credential cache file: %w", err)
		}
		bytes = unsafe.Slice(ciphertext.Data, ciphertext.Size)
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(ciphertext.Data)))
	}
	_, err = cacheFile.Write(bytes)
	if err != nil {
		return fmt.Errorf("failed to write the credential cache file: %w", err)
	}
	return nil
}

type keyringSecureStorageManager struct {
	leaseHandler *LeaseHandler
}

func newKeyringBasedSecureStorageManager() (*keyringSecureStorageManager, error) {
	credDirPath, err := credCacheDirPath()
	if err != nil {
		return nil, err
	}
	leaseHandler, err := NewLeaseHandler(filepath.Join(credDirPath, credLeaseFileName), leaseOperationTimeout)
	if err != nil {
		return nil, err
	}
	ssm := &keyringSecureStorageManager{
		leaseHandler: leaseHandler,
	}
	return ssm, nil
}

func (ssm *keyringSecureStorageManager) acquireLease() (*Lease, error) {
	return ssm.leaseHandler.Acquire(leaseTTL)
}

func (ssm *keyringSecureStorageManager) setCredential(lease *Lease, tokenSpec *secureTokenSpec, value string) error {
	err := lease.Renew(leaseTTL / 2)
	if err != nil {
		return err
	}
	if value == "" {
		logger.Debug("no token provided")
	} else {
		credentialsKey, err := tokenSpec.buildKey()
		if err != nil {
			logger.Warn(err)
			return err
		}
		if runtime.GOOS == "windows" {
			ring, err := keyring.Open(keyring.Config{
				WinCredPrefix: strings.ToUpper(tokenSpec.host),
				ServiceName:   strings.ToUpper(tokenSpec.user),
			})
			if err != nil {
				return err
			}
			item := keyring.Item{
				Key:  credentialsKey,
				Data: []byte(value),
			}
			if err := ring.Set(item); err != nil {
				logger.Warnf("Failed to write to Windows credential manager. Err: %v", err)
				return err
			}
		} else if runtime.GOOS == "darwin" {
			ring, err := keyring.Open(keyring.Config{
				ServiceName: credentialsKey,
			})
			if err != nil {
				return err
			}
			account := strings.ToUpper(tokenSpec.user)
			item := keyring.Item{
				Key:  account,
				Data: []byte(value),
			}
			if err := ring.Set(item); err != nil {
				logger.Debugf("Failed to write to keychain. Err: %v", err)
				return err
			}
		}
	}
	return nil
}

func (ssm *keyringSecureStorageManager) getCredential(lease *Lease, tokenSpec *secureTokenSpec) (string, error) {
	cred := ""
	err := lease.Renew(leaseTTL / 2)
	if err != nil {
		return cred, err
	}
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return "", nil
	}
	if runtime.GOOS == "windows" {
		ring, err := keyring.Open(keyring.Config{
			WinCredPrefix: strings.ToUpper(tokenSpec.host),
			ServiceName:   strings.ToUpper(tokenSpec.user),
		})
		if err != nil {
			return cred, err
		}
		i, err := ring.Get(credentialsKey)
		if err != nil {
			logger.Debugf("Failed to read credentialsKey or could not find it in Windows Credential Manager. Error: %v", err)
			return cred, err
		}
		cred = string(i.Data)
	} else if runtime.GOOS == "darwin" {
		ring, err := keyring.Open(keyring.Config{
			ServiceName: credentialsKey,
		})
		if err != nil {
			return cred, err
		}
		account := strings.ToUpper(tokenSpec.user)
		i, err := ring.Get(account)
		if err != nil {
			logger.Debugf("Failed to find the item in keychain or item does not exist. Error: %v", err)
			return cred, err
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

func (ssm *keyringSecureStorageManager) deleteCredential(lease *Lease, tokenSpec *secureTokenSpec) error {
	err := lease.Renew(leaseTTL / 2)
	if err != nil {
		return err
	}
	credentialsKey, err := tokenSpec.buildKey()
	if err != nil {
		logger.Warn(err)
		return nil
	}
	if runtime.GOOS == "windows" {
		ring, err := keyring.Open(keyring.Config{
			WinCredPrefix: strings.ToUpper(tokenSpec.host),
			ServiceName:   strings.ToUpper(tokenSpec.user),
		})
		if err != nil {
			return err
		}
		err = ring.Remove(string(credentialsKey))
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in Windows Credential Manager. Error: %v", err)
			return err
		}
	} else if runtime.GOOS == "darwin" {
		ring, err := keyring.Open(keyring.Config{
			ServiceName: credentialsKey,
		})
		if err != nil {
			return err
		}
		account := strings.ToUpper(tokenSpec.user)
		err = ring.Remove(account)
		if err != nil {
			logger.Debugf("Failed to delete credentialsKey in keychain. Error: %v", err)
			return err
		}
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
