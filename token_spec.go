package gosnowflake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// tokenType enumerates the different logical credentials we store.
type tokenType string

const (
	idToken           tokenType = "ID_TOKEN"
	mfaToken          tokenType = "MFA_TOKEN"
	oauthAccessToken  tokenType = "OAUTH_ACCESS_TOKEN"
	oauthRefreshToken tokenType = "OAUTH_REFRESH_TOKEN"
)

type secureTokenSpec struct {
	host, user string
	tokenType  tokenType
}

func (t *secureTokenSpec) buildKey() (string, error) {
	return buildCredentialsKey(t.host, t.user, t.tokenType)
}

func buildCredentialsKey(host, user string, t tokenType) (string, error) {
	if host == "" {
		return "", errors.New("host missing for token cache")
	}
	if user == "" {
		return "", errors.New("user missing for token cache")
	}
	sum := sha256.Sum256([]byte(host + ":" + user + ":" + string(t)))
	return hex.EncodeToString(sum[:]), nil
}

func newIDTokenSpec(host, user string) *secureTokenSpec {
	return &secureTokenSpec{host, user, idToken}
}
func newMfaTokenSpec(host, user string) *secureTokenSpec {
	return &secureTokenSpec{host, user, mfaToken}
}
func newOAuthAccessTokenSpec(host, user string) *secureTokenSpec {
	return &secureTokenSpec{host, user, oauthAccessToken}
}
func newOAuthRefreshTokenSpec(host, user string) *secureTokenSpec {
	return &secureTokenSpec{host, user, oauthRefreshToken}
}
