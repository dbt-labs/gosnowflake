package gosnowflake

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
