package gosnowflake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Lock interface{ release() error }

type Storage interface {
	Acquire() (Lock, error)
	Release(Lock) error
	Get   (Lock, *secureTokenSpec) (string, error)
	Set   (Lock, *secureTokenSpec, string) error
	Delete(Lock, *secureTokenSpec) error
}

const (
	leaseDuration  = 5 * time.Minute // time of browser timeout
	acquireTimeout = 30 * time.Second
	pollInterval   = 200 * time.Millisecond
)

type fileLease struct{ path string; fh *os.File }

func (l fileLease) release() error {
	_ = l.fh.Close()
	return os.Remove(l.path) // best-effort; stale leases self-expire
}

func acquireFileLease(dir string) (Lock, error) {
	lockPath := filepath.Join(dir, credCacheFileName+".lck")
	deadline := time.Now().Add(acquireTimeout)

	for time.Now().Before(deadline) {
		now := time.Now()
		exp := now.Add(leaseDuration)

		// try exclusive create
		fh, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			_, _ = fh.WriteString(strconv.FormatInt(exp.UnixNano(), 10))
			return fileLease{lockPath, fh}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock: %w", err)
		}

		// file exists
		b, err := os.ReadFile(lockPath)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		prevExp, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		if now.Before(time.Unix(0, prevExp)) {
			time.Sleep(pollInterval)
			continue
		}

		// steal stale lease
		fh, err = os.OpenFile(lockPath, os.O_RDWR|os.O_TRUNC, 0o600)
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}
		_, err = fh.WriteString(strconv.FormatInt(exp.UnixNano(), 10))
		if err != nil {
			_ = fh.Close()
			time.Sleep(pollInterval)
			continue
		}
		return fileLease{lockPath, fh}, nil
	}
	return nil, fmt.Errorf("timeout acquiring %s", lockPath)
}

/*
 * Cache directory helpers
 */

const credCacheDirEnv = "SF_TEMPORARY_CREDENTIAL_CACHE_DIR"
const credCacheFileName = "credential_cache_v2.json"

type cacheDirConf struct {
	envVar       string
	pathSegments []string
}

var (
	defaultLinuxCacheDirConf = []cacheDirConf{
		{envVar: credCacheDirEnv, pathSegments: nil},
		{envVar: "XDG_CACHE_HOME", pathSegments: []string{"snowflake"}},
		{envVar: "HOME", pathSegments: []string{".cache", "snowflake"}},
	}
	defaultMacCacheDirConf = []cacheDirConf{
		{envVar: credCacheDirEnv, pathSegments: nil},
		// narrower perms than ~/Library/Caches/Snowflake
		{envVar: "HOME", pathSegments: []string{"Library", "Caches", "Snowflake", "Credentials"}},
	}
	defaultWindowsCacheDirConf = []cacheDirConf{
		{envVar: credCacheDirEnv, pathSegments: nil},
		{envVar: "LOCALAPPDATA", pathSegments: []string{"Snowflake", "Credentials"}},
		{envVar: "USERPROFILE", pathSegments: []string{"AppData", "Local", "Snowflake", "Credentials"}},
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
 * Token cache (fileStore)
 */

type fileStore struct{ cacheDir string }

func (s *fileStore) Acquire() (Lock, error)                 { return acquireFileLease(s.cacheDir) }
func (s *fileStore) Release(l Lock) error                   { return l.release() }

func (s *fileStore) credFile() string                       { return filepath.Join(s.cacheDir, credCacheFileName) }

func (s *fileStore) readAll() (map[string]any, error) {
	f, err := os.OpenFile(s.credFile(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil { return nil, err }
	defer f.Close()
	var m map[string]any
	b, _ := io.ReadAll(f)
	if len(b) != 0 { _ = json.Unmarshal(b, &m) }
	if m == nil { m = map[string]any{} }
	if _, ok := m["tokens"]; !ok { m["tokens"] = map[string]any{} }
	return m, nil
}
func (s *fileStore) writeAll(m map[string]any) error {
	b, e := json.Marshal(m); if e != nil { return e }
	return os.WriteFile(s.credFile(), b, 0o600)
}

func (s *fileStore) Get(_ Lock, spec *secureTokenSpec) (string, error) {
	key, err := spec.buildKey(); if err != nil { return "", err }
	m, err := s.readAll();       if err != nil { return "", err }
	v, _ := m["tokens"].(map[string]any)[key].(string)
	return v, nil
}
func (s *fileStore) Set(_ Lock, spec *secureTokenSpec, v string) error {
	key, err := spec.buildKey(); if err != nil { return err }
	m, err := s.readAll();       if err != nil { return err }
	m["tokens"].(map[string]any)[key] = v
	return s.writeAll(m)
}
func (s *fileStore) Delete(_ Lock, spec *secureTokenSpec) error {
	key, err := spec.buildKey(); if err != nil { return err }
	m, err := s.readAll();       if err != nil { return err }
	delete(m["tokens"].(map[string]any), key)
	return s.writeAll(m)
}


/*
 * Thread-safe wrapper
 */

type tsStore struct {
	mu sync.Mutex
	s  Storage
}

func newThreadSafe(s Storage) Storage { return &tsStore{s: s} }

func (t *tsStore) Acquire() (Lock, error) {
	t.mu.Lock();
	l, e := t.s.Acquire();
	t.mu.Unlock();
	return l, e
}

func (t *tsStore) Release(l Lock) error {
    t.mu.Lock()
    err := t.s.Release(l)
    t.mu.Unlock()
    return err
}

func (t *tsStore) Get(l Lock, s *secureTokenSpec) (string, error) {
	t.mu.Lock(); v, e := t.s.Get(l, s); t.mu.Unlock(); return v, e
}
func (t *tsStore) Set(l Lock, s *secureTokenSpec, v string) error {
	t.mu.Lock(); e := t.s.Set(l, s, v); t.mu.Unlock(); return e
}
func (t *tsStore) Delete(l Lock, s *secureTokenSpec) error {
	t.mu.Lock(); e := t.s.Delete(l, s); t.mu.Unlock(); return e
}

/*
 * Backend selection
 */

func newFileStore() (*fileStore, error) {
	dir, err := buildCredCacheDirPath(defaultCacheDirConf())
	if err != nil { return nil, err }
	return &fileStore{cacheDir: dir}, nil
}

// no-op fallback if directory cannot be created
type noopLock struct{}; func (noopLock) release() error { return nil }
type noopStore struct{}
func (noopStore) Acquire() (Lock, error)                  { return noopLock{}, nil }
func (noopStore) Release(Lock) error                      { return nil }
func (noopStore) Get   (Lock,*secureTokenSpec)(string,error){ return "", nil }
func (noopStore) Set   (Lock,*secureTokenSpec,string)error  { return nil }
func (noopStore) Delete(Lock,*secureTokenSpec) error        { return nil }

func chooseBackend() Storage {
	if fs, err := newFileStore(); err == nil {
		return fs
	}
	logger.Debug("credential cache disabled ... falling back to noop implementation")
	return noopStore{}
}

// exported singleton
var credentialsStorage Storage = newThreadSafe(chooseBackend())

/*
 * Shared helper
 */

func buildCredentialsKey(host, user string, t tokenType) (string, error) {
	if host == "" { return "", errors.New("host missing for token cache") }
	if user == "" { return "", errors.New("user missing for token cache") }
	sum := sha256.Sum256([]byte(host + ":" + user + ":" + string(t)))
	return hex.EncodeToString(sum[:]), nil
}
