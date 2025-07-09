package gosnowflake

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

type Lock interface{ release() error }

type Storage interface {
	Acquire() (Lock, error)
	Release(Lock) error
	Get(Lock, *secureTokenSpec) (string, error)
	Set(Lock, *secureTokenSpec, string) error
	Delete(Lock, *secureTokenSpec) error
}

const (
	leaseDuration  = defaultTTL     // 5 min, from lease.go
	acquireTimeout = defaultTimeout // 30 s
)

type fileLease struct{ *Lease } // adapts Lease to the private Lock interface

func acquireFileLease(dir string) (Lock, error) {
	l := NewLease(dir, credCacheFileName)
	if err := l.Acquire(acquireTimeout, leaseDuration); err != nil {
		return nil, err
	}
	return fileLease{l}, nil
}
func (fl fileLease) release() error { return fl.Lease.Release() }

/*
 * Cache directory helpers
 */

const (
	credCacheDirEnv   = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR"
	credCacheFileName = "credential_cache_v2.json"
)

type cacheDirConf struct {
	envVar       string
	pathSegments []string
}

var (
	defaultLinuxCacheDirConf = []cacheDirConf{
		{envVar: "XDG_CACHE_HOME", pathSegments: []string{"snowflake"}},
		{envVar: "HOME", pathSegments: []string{".cache", "snowflake"}},
		{envVar: credCacheDirEnv},
	}
	defaultMacCacheDirConf = []cacheDirConf{
		{envVar: "HOME", pathSegments: []string{"Library", "Caches", "Snowflake", "Credentials"}},
		{envVar: credCacheDirEnv},
	}
	defaultWindowsCacheDirConf = []cacheDirConf{
		{envVar: "USERPROFILE", pathSegments: []string{"AppData", "Local", "Snowflake", "Credentials"}},
		{envVar: "LOCALAPPDATA", pathSegments: []string{"Snowflake", "Credentials"}},
		{envVar: credCacheDirEnv},
	}
)

func defaultCacheDirConf() []cacheDirConf {
	switch runtime.GOOS {
	case "windows":
		return defaultWindowsCacheDirConf
	case "darwin":
		return defaultMacCacheDirConf
	default:
		return defaultLinuxCacheDirConf
	}
}

// lookupCacheDir validates envVar, assembles segments, does the mkdir -p, returns it.
func lookupCacheDir(envVar string, segs ...string) (string, error) {
	root := os.Getenv(envVar)
	if root == "" {
		return "", fmt.Errorf("%s not set", envVar)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not dir", root)
	}

	// reject if root is a symlink (prevents pointing at someone else's dir)
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s must not be a symlink", root)
	}

	dir := filepath.Join(append([]string{root}, segs...)...)
	if err = os.MkdirAll(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return dir, nil
}

func buildCredCacheDirPath(confs []cacheDirConf) (string, error) {
	for _, c := range confs {
		if d, err := lookupCacheDir(c.envVar, c.pathSegments...); err == nil {
			return d, nil
		}
	}
	return "", errors.New("no credential cache directory found")
}

/*
 * Token Cache Helpers
 */

type cacheFile struct {
	Tokens map[string]string `json:"tokens"`
}

type fileStore struct{ cacheDir string }

func newFileStore() (*fileStore, error) {
	dir, err := buildCredCacheDirPath(defaultCacheDirConf())
	if err != nil {
		return nil, err
	}
	return &fileStore{cacheDir: dir}, nil
}

/*
 * Storage interface
 */

func (s *fileStore) Acquire() (Lock, error) { return acquireFileLease(s.cacheDir) }
func (s *fileStore) Release(l Lock) error   { return l.release() }

func (s *fileStore) credFile() string { return filepath.Join(s.cacheDir, credCacheFileName) }

func (s *fileStore) readAll() (*cacheFile, error) {
	f, err := os.OpenFile(s.credFile(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cf cacheFile
	if err = json.NewDecoder(f).Decode(&cf); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("decode cache: %w", err)
	}
	if cf.Tokens == nil {
		cf.Tokens = make(map[string]string)
	}
	return &cf, nil
}

func (s *fileStore) writeAll(cf *cacheFile) error {
	b, err := json.Marshal(cf)
	if err != nil {
		return err
	}
	tmp := s.credFile() + ".tmp"
	if err = os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.credFile()) // atomic
}

func (s *fileStore) Get(_ Lock, spec *secureTokenSpec) (string, error) {
	key, err := spec.buildKey()
	if err != nil {
		return "", err
	}
	cf, err := s.readAll()
	if err != nil {
		return "", err
	}
	return cf.Tokens[key], nil
}

func (s *fileStore) Set(_ Lock, spec *secureTokenSpec, v string) error {
	key, err := spec.buildKey()
	if err != nil {
		return err
	}
	cf, err := s.readAll()
	if err != nil {
		return err
	}
	cf.Tokens[key] = v
	return s.writeAll(cf)
}

func (s *fileStore) Delete(_ Lock, spec *secureTokenSpec) error {
	key, err := spec.buildKey()
	if err != nil {
		return err
	}
	cf, err := s.readAll()
	if err != nil {
		return err
	}
	delete(cf.Tokens, key)
	return s.writeAll(cf)
}

/*
 * Thread Safe Wrapper
 */

type tsStore struct {
	mu sync.Mutex
	s  Storage
}

func newThreadSafe(s Storage) Storage { return &tsStore{s: s} }
func (t *tsStore) Acquire() (Lock, error) {
	t.mu.Lock()
	l, e := t.s.Acquire()
	t.mu.Unlock()
	return l, e
}
func (t *tsStore) Release(l Lock) error { t.mu.Lock(); e := t.s.Release(l); t.mu.Unlock(); return e }
func (t *tsStore) Get(l Lock, s *secureTokenSpec) (string, error) {
	t.mu.Lock()
	v, e := t.s.Get(l, s)
	t.mu.Unlock()
	return v, e
}
func (t *tsStore) Set(l Lock, s *secureTokenSpec, v string) error {
	t.mu.Lock()
	e := t.s.Set(l, s, v)
	t.mu.Unlock()
	return e
}
func (t *tsStore) Delete(l Lock, s *secureTokenSpec) error {
	t.mu.Lock()
	e := t.s.Delete(l, s)
	t.mu.Unlock()
	return e
}

/*
 * No-op as a fallback
 */

type noopLock struct{}

func (noopLock) release() error { return nil }

type noopStore struct{}

func (noopStore) Acquire() (Lock, error)                     { return noopLock{}, nil }
func (noopStore) Release(Lock) error                         { return nil }
func (noopStore) Get(Lock, *secureTokenSpec) (string, error) { return "", nil }
func (noopStore) Set(Lock, *secureTokenSpec, string) error   { return nil }
func (noopStore) Delete(Lock, *secureTokenSpec) error        { return nil }

/*
 * Backend helpers
 */

func chooseBackend() Storage {
	if fs, err := newFileStore(); err == nil {
		return fs
	}
	logger.Debug("credential cache disabled ... falling back to noop implementation")
	return noopStore{}
}

// exported singleton the rest of gosnowflake uses
var credentialsStorage Storage = newThreadSafe(chooseBackend())
