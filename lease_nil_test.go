package gosnowflake

import (
	"errors"
	"os"
	"testing"
)

// Credential storage used to dereference a nil lease. Callers that have no lease (tests
// ported from before leases existed) get an error instead of a panic.
func TestFileBasedSecureStorageManagerNilLease(t *testing.T) {
	skipOnWindows(t, "file system permission is different")
	credCacheDir, err := os.MkdirTemp("", "")
	assertNilF(t, err)
	defer os.RemoveAll(credCacheDir)
	credCacheDirEnvOverride := overrideEnv(credCacheDirEnv, credCacheDir)
	defer credCacheDirEnvOverride.rollback()
	ssm, err := newFileBasedSecureStorageManager()
	assertNilF(t, err)
	tokenSpec := newMfaTokenSpec("host.com", "johndoe")

	t.Run("getCredential", func(t *testing.T) {
		tok, err := ssm.getCredential(nil, tokenSpec)
		assertEqualE(t, tok, "")
		assertTrueE(t, errors.Is(err, errNilLease), "expected errNilLease")
	})
	t.Run("setCredential", func(t *testing.T) {
		err := ssm.setCredential(nil, tokenSpec, "token123")
		assertTrueE(t, errors.Is(err, errNilLease), "expected errNilLease")
	})
	t.Run("deleteCredential", func(t *testing.T) {
		err := ssm.deleteCredential(nil, tokenSpec)
		assertTrueE(t, errors.Is(err, errNilLease), "expected errNilLease")
	})
	t.Run("nothing was written", func(t *testing.T) {
		lease, err := ssm.acquireLease()
		assertNilF(t, err)
		defer lease.Release()
		tok, err := ssm.getCredential(lease, tokenSpec)
		assertNilE(t, err)
		assertEqualE(t, tok, "")
	})
}

func TestEnsureLeaseForCacheWriteNilLease(t *testing.T) {
	assertTrueE(t, errors.Is(ensureLeaseForCacheWrite(nil), errNilLease), "expected errNilLease")
}

func TestDoAuthenticateByExternalBrowserNilLease(t *testing.T) {
	result := doAuthenticateByExternalBrowser(t.Context(), nil, nil, "", "", "", "", ConfigBoolTrue)
	assertTrueE(t, errors.Is(result.err, errNilLease), "expected errNilLease")
}
