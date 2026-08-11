package gosnowflake

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	sferrors "github.com/snowflakedb/gosnowflake/v2/internal/errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/snowflakedb/gosnowflake/v2/internal/compilation"
	sfconfig "github.com/snowflakedb/gosnowflake/v2/internal/config"
	internalos "github.com/snowflakedb/gosnowflake/v2/internal/os"
	"github.com/snowflakedb/gosnowflake/v2/internal/spcs"
)

const (
	clientType = "Go"
)

const (
	clientStoreTemporaryCredential = "CLIENT_STORE_TEMPORARY_CREDENTIAL"
	clientRequestMfaToken          = "CLIENT_REQUEST_MFA_TOKEN"
	idTokenAuthenticator           = "ID_TOKEN"
)

// AuthType indicates the type of authentication in Snowflake
type AuthType = sfconfig.AuthType

const (
	// AuthTypeSnowflake is the general username password authentication
	AuthTypeSnowflake = sfconfig.AuthTypeSnowflake
	// AuthTypeOAuth is the OAuth authentication
	AuthTypeOAuth = sfconfig.AuthTypeOAuth
	// AuthTypeExternalBrowser is to use a browser to access an Fed and perform SSO authentication
	AuthTypeExternalBrowser = sfconfig.AuthTypeExternalBrowser
	// AuthTypeOkta is to use a native okta URL to perform SSO authentication on Okta
	AuthTypeOkta = sfconfig.AuthTypeOkta
	// AuthTypeJwt is to use Jwt to perform authentication
	AuthTypeJwt = sfconfig.AuthTypeJwt
	// AuthTypeTokenAccessor is to use the provided token accessor and bypass authentication
	AuthTypeTokenAccessor = sfconfig.AuthTypeTokenAccessor
	// AuthTypeUsernamePasswordMFA is to use username and password with mfa
	AuthTypeUsernamePasswordMFA = sfconfig.AuthTypeUsernamePasswordMFA
	// AuthTypePat is to use programmatic access token
	AuthTypePat = sfconfig.AuthTypePat
	// AuthTypeOAuthAuthorizationCode is to use browser-based OAuth2 flow
	AuthTypeOAuthAuthorizationCode = sfconfig.AuthTypeOAuthAuthorizationCode
	// AuthTypeOAuthClientCredentials is to use non-interactive OAuth2 flow
	AuthTypeOAuthClientCredentials = sfconfig.AuthTypeOAuthClientCredentials
	// AuthTypeWorkloadIdentityFederation is to use CSP identity for authentication
	AuthTypeWorkloadIdentityFederation = sfconfig.AuthTypeWorkloadIdentityFederation
)

func isOauthNativeFlow(authType AuthType) bool {
	return authType == AuthTypeOAuthAuthorizationCode || authType == AuthTypeOAuthClientCredentials
}

var refreshOAuthTokenErrorCodes = []string{
	strconv.Itoa(ErrMissingAccessATokenButRefreshTokenPresent),
	invalidOAuthAccessTokenCode,
	expiredOAuthAccessTokenCode,
}

// userAgent shows up in User-Agent HTTP header
var userAgent = fmt.Sprintf("%v/%v (%v-%v) %v/%v",
	clientType,
	SnowflakeGoDriverVersion,
	runtime.GOOS,
	runtime.GOARCH,
	runtime.Compiler,
	runtime.Version())

type authRequestClientEnvironment struct {
	Application             string            `json:"APPLICATION"`
	ApplicationPath         string            `json:"APPLICATION_PATH"`
	Os                      string            `json:"OS"`
	OsVersion               string            `json:"OS_VERSION"`
	OsDetails               map[string]string `json:"OS_DETAILS,omitempty"`
	Isa                     string            `json:"ISA,omitempty"`
	OCSPMode                string            `json:"OCSP_MODE"`
	GoVersion               string            `json:"GO_VERSION"`
	OAuthType               string            `json:"OAUTH_TYPE,omitempty"`
	CertRevocationCheckMode string            `json:"CERT_REVOCATION_CHECK_MODE,omitempty"`
	Platform                []string          `json:"PLATFORM,omitempty"`
	CoreVersion             string            `json:"CORE_VERSION,omitempty"`
	CoreLoadError           string            `json:"CORE_LOAD_ERROR,omitempty"`
	CoreFileName            string            `json:"CORE_FILE_NAME,omitempty"`
	CgoEnabled              bool              `json:"CGO_ENABLED,omitempty"`
	LinkingMode             string            `json:"LINKING_MODE,omitempty"`
	LibcFamily              string            `json:"LIBC_FAMILY,omitempty"`
	LibcVersion             string            `json:"LIBC_VERSION,omitempty"`
}

type authRequestData struct {
	ClientAppID             string                       `json:"CLIENT_APP_ID"`
	ClientAppVersion        string                       `json:"CLIENT_APP_VERSION"`
	SvnRevision             string                       `json:"SVN_REVISION"`
	AccountName             string                       `json:"ACCOUNT_NAME"`
	LoginName               string                       `json:"LOGIN_NAME,omitempty"`
	Password                string                       `json:"PASSWORD,omitempty"`
	RawSAMLResponse         string                       `json:"RAW_SAML_RESPONSE,omitempty"`
	ExtAuthnDuoMethod       string                       `json:"EXT_AUTHN_DUO_METHOD,omitempty"`
	Passcode                string                       `json:"PASSCODE,omitempty"`
	Authenticator           string                       `json:"AUTHENTICATOR,omitempty"`
	SessionParameters       map[string]any               `json:"SESSION_PARAMETERS,omitempty"`
	ClientEnvironment       authRequestClientEnvironment `json:"CLIENT_ENVIRONMENT"`
	SpcsToken               string                       `json:"SPCS_TOKEN,omitempty"`
	BrowserModeRedirectPort string                       `json:"BROWSER_MODE_REDIRECT_PORT,omitempty"`
	ProofKey                string                       `json:"PROOF_KEY,omitempty"`
	Token                   string                       `json:"TOKEN,omitempty"`
	Provider                string                       `json:"PROVIDER,omitempty"`
}
type authRequest struct {
	Data authRequestData `json:"data"`
}

type nameValueParameter struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type authResponseSessionInfo struct {
	DatabaseName  string `json:"databaseName"`
	SchemaName    string `json:"schemaName"`
	WarehouseName string `json:"warehouseName"`
	RoleName      string `json:"roleName"`
}

type authResponseMain struct {
	Token               string                  `json:"token,omitempty"`
	Validity            time.Duration           `json:"validityInSeconds,omitempty"`
	MasterToken         string                  `json:"masterToken,omitempty"`
	MasterValidity      time.Duration           `json:"masterValidityInSeconds"`
	MfaToken            string                  `json:"mfaToken,omitempty"`
	MfaTokenValidity    time.Duration           `json:"mfaTokenValidityInSeconds"`
	IDToken             string                  `json:"idToken,omitempty"`
	IDTokenValidity     time.Duration           `json:"idTokenValidityInSeconds"`
	DisplayUserName     string                  `json:"displayUserName"`
	ServerVersion       string                  `json:"serverVersion"`
	FirstLogin          bool                    `json:"firstLogin"`
	RemMeToken          string                  `json:"remMeToken"`
	RemMeValidity       time.Duration           `json:"remMeValidityInSeconds"`
	HealthCheckInterval time.Duration           `json:"healthCheckInterval"`
	NewClientForUpgrade string                  `json:"newClientForUpgrade"`
	SessionID           int64                   `json:"sessionId"`
	Parameters          []nameValueParameter    `json:"parameters"`
	SessionInfo         authResponseSessionInfo `json:"sessionInfo"`
	TokenURL            string                  `json:"tokenUrl,omitempty"`
	SSOURL              string                  `json:"ssoUrl,omitempty"`
	ProofKey            string                  `json:"proofKey,omitempty"`
}

type authResponse struct {
	Data    authResponseMain `json:"data"`
	Message string           `json:"message"`
	Code    string           `json:"code"`
	Success bool             `json:"success"`
}

func postAuth(
	ctx context.Context,
	sr *snowflakeRestful,
	client *http.Client,
	params *url.Values,
	headers map[string]string,
	bodyCreator bodyCreatorType,
	timeout time.Duration) (
	data *authResponse, err error) {
	params.Set(requestIDKey, getOrGenerateRequestIDFromContext(ctx).String())
	params.Set(requestGUIDKey, NewUUID().String())

	fullURL := sr.getFullURL(loginRequestPath, params)
	logger.WithContext(ctx).Infof("full URL: %v", fullURL)
	resp, err := sr.FuncAuthPost(ctx, client, fullURL, headers, bodyCreator, timeout, sr.MaxRetryCount)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.WithContext(ctx).Errorf("failed to close HTTP response body for %v. err: %v", fullURL, closeErr)
		}
	}()
	if resp.StatusCode == http.StatusOK {
		var respd authResponse
		err = json.NewDecoder(resp.Body).Decode(&respd)
		if err != nil {
			logger.WithContext(ctx).Errorf("failed to decode JSON. err: %v", err)
			return nil, err
		}
		return &respd, nil
	}
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		// service availability or connectivity issue. Most likely server side issue.
		return nil, &SnowflakeError{
			Number:      ErrCodeServiceUnavailable,
			SQLState:    SQLStateConnectionWasNotEstablished,
			Message:     sferrors.ErrMsgServiceUnavailable,
			MessageArgs: []any{resp.StatusCode, fullURL},
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		// failed to connect to db. account name may be wrong
		return nil, &SnowflakeError{
			Number:      ErrCodeFailedToConnect,
			SQLState:    SQLStateConnectionRejected,
			Message:     sferrors.ErrMsgFailedToConnect,
			MessageArgs: []any{resp.StatusCode, fullURL},
		}
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.WithContext(ctx).Errorf("failed to extract HTTP response body. err: %v", err)
		return nil, err
	}
	logger.WithContext(ctx).Infof("HTTP: %v, URL: %v, Body: %v", resp.StatusCode, fullURL, b)
	logger.WithContext(ctx).Infof("Header: %v", resp.Header)
	return nil, &SnowflakeError{
		Number:      ErrFailedToAuth,
		SQLState:    SQLStateConnectionRejected,
		Message:     sferrors.ErrMsgFailedToAuth,
		MessageArgs: []any{resp.StatusCode, fullURL},
	}
}

// Generates a map of headers needed to authenticate
// with Snowflake.
func getHeaders() map[string]string {
	headers := make(map[string]string)
	headers[httpHeaderContentType] = headerContentTypeApplicationJSON
	headers[httpHeaderAccept] = headerAcceptTypeApplicationSnowflake
	headers[httpClientAppID] = clientType
	headers[httpClientAppVersion] = SnowflakeGoDriverVersion
	headers[httpHeaderUserAgent] = userAgent
	return headers
}

// Used to authenticate the user with Snowflake.
func authenticate(
	ctx context.Context,
	lease *Lease,
	sc *snowflakeConn,
	samlResponse []byte,
	proofKey []byte,
) (resp *authResponseMain, err error) {
	if sc.cfg.Authenticator == AuthTypeTokenAccessor {
		logger.WithContext(ctx).Info("Bypass authentication using existing token from token accessor")
		sessionInfo := authResponseSessionInfo{
			DatabaseName:  sc.cfg.Database,
			SchemaName:    sc.cfg.Schema,
			WarehouseName: sc.cfg.Warehouse,
			RoleName:      sc.cfg.Role,
		}
		token, masterToken, sessionID := sc.cfg.TokenAccessor.GetTokens()
		return &authResponseMain{
			Token:       token,
			MasterToken: masterToken,
			SessionID:   sessionID,
			SessionInfo: sessionInfo,
		}, nil
	}

	headers := getHeaders()
	// Get the current application path
	applicationPath, err := os.Executable()
	if err != nil {
		logger.WithContext(ctx).Warnf("Failed to get executable path: %v", err)
		applicationPath = "unknown"
	}

	oauthType := ""
	switch sc.cfg.Authenticator {
	case AuthTypeOAuthAuthorizationCode:
		oauthType = "OAUTH_AUTHORIZATION_CODE"
	case AuthTypeOAuthClientCredentials:
		oauthType = "OAUTH_CLIENT_CREDENTIALS"
	}

	clientEnvironment := newAuthRequestClientEnvironment()
	clientEnvironment.Application = sc.cfg.Application
	clientEnvironment.ApplicationPath = applicationPath
	clientEnvironment.OAuthType = oauthType
	clientEnvironment.CertRevocationCheckMode = sc.cfg.CertRevocationCheckMode.String()
	clientEnvironment.Platform = getDetectedPlatforms()

	sessionParameters := make(map[string]any)
	for k, v := range sc.syncParams.All() {
		// upper casing to normalize keys
		sessionParameters[strings.ToUpper(k)] = v
	}

	sessionParameters[sessionClientValidateDefaultParameters] = sc.cfg.ValidateDefaultParameters != ConfigBoolFalse
	if sc.cfg.ClientRequestMfaToken == ConfigBoolTrue {
		sessionParameters[clientRequestMfaToken] = true
	}
	if sc.cfg.ClientStoreTemporaryCredential == ConfigBoolTrue {
		sessionParameters[clientStoreTemporaryCredential] = true
	}
	bodyCreator := func() ([]byte, error) {
		return createRequestBody(sc, lease, sessionParameters, clientEnvironment, proofKey, samlResponse)
	}

	params := &url.Values{}
	if sc.cfg.Database != "" {
		params.Add("databaseName", sc.cfg.Database)
	}
	if sc.cfg.Schema != "" {
		params.Add("schemaName", sc.cfg.Schema)
	}
	if sc.cfg.Warehouse != "" {
		params.Add("warehouse", sc.cfg.Warehouse)
	}
	if sc.cfg.Role != "" {
		params.Add("roleName", sc.cfg.Role)
	}

	logger.WithContext(ctx).Infof("Information for Auth: Host: %v, User: %v, Authenticator: %v, Params: %v, Protocol: %v, Port: %v, LoginTimeout: %v",
		sc.rest.Host, sc.cfg.User, sc.cfg.Authenticator.String(), params, sc.rest.Protocol, sc.rest.Port, sc.rest.LoginTimeout)

	respd, err := sc.rest.FuncPostAuth(ctx, sc.rest, sc.rest.getClientFor(sc.cfg.Authenticator), params, headers, bodyCreator, sc.rest.LoginTimeout)
	if err != nil {
		return nil, err
	}
	if !respd.Success {
		logger.WithContext(ctx).Error("Authentication FAILED")
		sc.rest.TokenAccessor.SetTokens("", "", -1)
		// dbt-only: a write that could not be performed under a relaxed read is
		// reported so the caller can escalate to a held lease and retry.
		if sessionParameters[clientRequestMfaToken] == true {
			if err := credentialsStorage.deleteCredential(lease, newMfaTokenSpec(sc.cfg)); err != nil && lease.RelaxedReadAllowed {
				return nil, err
			}
		}
		if sessionParameters[clientStoreTemporaryCredential] == true && sc.cfg.Authenticator == AuthTypeExternalBrowser {
			if err := credentialsStorage.deleteCredential(lease, newIDTokenSpec(sc.cfg)); err != nil && lease.RelaxedReadAllowed {
				return nil, err
			}
		}
		if sessionParameters[clientStoreTemporaryCredential] == true && isOauthNativeFlow(sc.cfg.Authenticator) {
			if err := credentialsStorage.deleteCredential(lease, newOAuthAccessTokenSpec(sc.cfg)); err != nil && lease.RelaxedReadAllowed {
				return nil, err
			}
		}
		code, err := strconv.Atoi(respd.Code)
		if err != nil {
			return nil, err
		}
		return nil, exceptionTelemetry(&SnowflakeError{
			Number:   code,
			SQLState: SQLStateConnectionRejected,
			Message:  respd.Message,
		}, sc)
	}
	logger.WithContext(ctx).Info("Authentication SUCCESS")
	sc.rest.TokenAccessor.SetTokens(respd.Data.Token, respd.Data.MasterToken, respd.Data.SessionID)
	if shouldCacheMfaToken(sc.cfg.Authenticator, sessionParameters) {
		if err := credentialsStorage.setCredential(lease, newMfaTokenSpec(sc.cfg), respd.Data.MfaToken); err != nil && lease.RelaxedReadAllowed {
			return nil, err
		}
	}
	if shouldCacheIDToken(sc.cfg.Authenticator, sessionParameters, respd.Data.IDToken) {
		if err := credentialsStorage.setCredential(lease, newIDTokenSpec(sc.cfg), respd.Data.IDToken); err != nil && lease.RelaxedReadAllowed {
			return nil, err
		}
	}
	return &respd.Data, nil
}

// shouldCacheMfaToken reports whether a successful login may write the MFA token
// cache slot.
//
// dbt-only: upstream checks only the session parameter. The slot belongs to
// AuthTypeUsernamePasswordMFA, and ClientRequestMfaToken can be set on any
// authenticator, so the flow must be checked too.
func shouldCacheMfaToken(authenticator AuthType, sessionParameters map[string]any) bool {
	return sessionParameters[clientRequestMfaToken] == true && authenticator == AuthTypeUsernamePasswordMFA
}

// shouldCacheIDToken reports whether a successful login may write the ID token
// cache slot.
//
// dbt-only: upstream checks only the session parameter, which is enabled for
// AuthTypeExternalBrowser and both OAuth flows alike — so an OAuth login would
// write its absent ID token over the browser flow's cached one. An empty token is
// likewise refused: a successful login does not always carry one, and storing ""
// evicts a valid entry and forces a needless browser tab on the next connect.
func shouldCacheIDToken(authenticator AuthType, sessionParameters map[string]any, idToken string) bool {
	return sessionParameters[clientStoreTemporaryCredential] == true && authenticator == AuthTypeExternalBrowser && idToken != ""
}

// dbt-only. Named so the switch below can re-assert it inside the case body,
// which a fallthrough enters without evaluating the guard.
func isOAuthRefreshable(err error) bool {
	var se *SnowflakeError
	return errors.As(err, &se) && slices.Contains(refreshOAuthTokenErrorCodes, strconv.Itoa(se.Number))
}

// dbt-only. A failure while presenting a cached ID token most likely means the
// token expired; without one, the failure is genuine.
func shouldRetryWithFreshExternalBrowserLogin(authenticator AuthType, cachedIDToken string) bool {
	return authenticator == AuthTypeExternalBrowser && cachedIDToken != ""
}

func newAuthRequestClientEnvironment() authRequestClientEnvironment {
	var coreVersion string
	var coreLoadError string

	// Try to get minicore version, but don't block if it's not loaded yet
	if !compilation.MinicoreEnabled {
		logger.Trace("minicore disabled at compile time")
		coreLoadError = "Minicore is disabled at compile time (built with -tags minicore_disabled)"
	} else if strings.EqualFold(os.Getenv(disableMinicoreEnv), "true") {
		logger.Trace("minicore loading disabled")
		coreLoadError = "Minicore is disabled with SF_DISABLE_MINICORE env variable"
	} else if mc := getMiniCore(); mc != nil {
		var err error
		coreVersion, err = mc.FullVersion()
		if err != nil {
			logger.Debugf("Minicore loading failed. %v", err)
			var mcErr *miniCoreError
			if errors.As(err, &mcErr) {
				coreLoadError = fmt.Sprintf("Failed to load binary: %v", mcErr.errorType)
			} else {
				coreLoadError = "Failed to load binary: unknown"
			}
		}
	} else {
		// Minicore not loaded yet - this is expected during startup
		coreVersion = ""
		coreLoadError = "Minicore is still loading"
		logger.Debugf("Minicore not yet loaded for client environment telemetry")
	}
	libcInfo := internalos.GetLibcInfo()
	linkingMode, err := compilation.CheckDynamicLinking()
	if err != nil {
		logger.Debugf("cannot determine if app is dynamically linked: %v", err)
	}
	return authRequestClientEnvironment{
		Os:            runtime.GOOS,
		OsVersion:     osVersion,
		OsDetails:     internalos.GetOsDetails(),
		Isa:           runtime.GOARCH,
		GoVersion:     runtime.Version(),
		CoreVersion:   coreVersion,
		CoreFileName:  getMiniCoreFileName(),
		CoreLoadError: coreLoadError,
		CgoEnabled:    compilation.CgoEnabled,
		LinkingMode:   linkingMode.String(),
		LibcFamily:    libcInfo.Family,
		LibcVersion:   libcInfo.Version,
	}
}

// parseAccount returns the bare account identifier for the auth request body.
//
// dbt-only: not upstream. ParseDSN strips the region subdomain
// (internal/config/dsn.go), but FillMissingConfigParameters does not, and the
// database/sql Connector path runs only the latter. A Config built in code with
// Account: "myacct.us-east-1" therefore reaches this point un-normalized and the
// login request 404s.
//
// Reference: snowflake-connector-python util_text.py
// https://github.com/snowflakedb/snowflake-connector-python/blob/f087cf6cdf684a44b40e6bbe329f597ac0997707/src/snowflake/connector/util_text.py#L258
//
//  1. "<account>"                      no dot; returned unchanged
//  2. "<account>.<region>"             region subdomain removed
//  3. "<account>-<external_id>.global" global locator; suffix after last '-' removed
//  4. "<account>.global"               no external ID present
//
// Deviates from the Python reference in case 4: there, rfind returning -1 is used
// unguarded as a slice bound, dropping the account's last character.
func parseAccount(account string) string {
	parts := strings.Split(account, ".")
	if len(parts) <= 1 {
		return account
	}

	head := parts[0]
	if parts[1] == "global" {
		if j := strings.LastIndex(head, "-"); j >= 0 {
			return head[:j]
		}
		return head
	}

	return head
}

func createRequestBody(sc *snowflakeConn, lease *Lease, sessionParameters map[string]any,
	clientEnvironment authRequestClientEnvironment, proofKey []byte, samlResponse []byte,
) ([]byte, error) {
	requestMain := authRequestData{
		ClientAppID:       clientType,
		ClientAppVersion:  SnowflakeGoDriverVersion,
		AccountName:       parseAccount(sc.cfg.Account),
		SessionParameters: sessionParameters,
		ClientEnvironment: clientEnvironment,
		SpcsToken:         spcs.GetToken(sc.ctx),
	}

	switch sc.cfg.Authenticator {
	case AuthTypeExternalBrowser:
		if sc.idToken != "" {
			requestMain.Authenticator = idTokenAuthenticator
			requestMain.Token = sc.idToken
			requestMain.LoginName = sc.cfg.User
		} else {
			requestMain.ProofKey = string(proofKey)
			requestMain.Token = string(samlResponse)
			requestMain.LoginName = sc.cfg.User
			requestMain.Authenticator = AuthTypeExternalBrowser.String()
		}
	case AuthTypeOAuth:
		requestMain.LoginName = sc.cfg.User
		requestMain.Authenticator = AuthTypeOAuth.String()
		var err error
		if requestMain.Token, err = sfconfig.GetToken(sc.cfg); err != nil {
			return nil, fmt.Errorf("failed to get OAuth token: %w", err)
		}
	case AuthTypeOkta:
		samlResponse, err := authenticateBySAML(
			sc.ctx,
			sc.rest,
			sc.cfg.OktaURL,
			sc.cfg.Application,
			sc.cfg.Account,
			sc.cfg.User,
			sc.cfg.Password,
			sc.cfg.DisableSamlURLCheck)
		if err != nil {
			return nil, err
		}
		requestMain.RawSAMLResponse = string(samlResponse)
	case AuthTypeJwt:
		requestMain.Authenticator = AuthTypeJwt.String()

		jwtTokenString, err := prepareJWTToken(sc.cfg)
		if err != nil {
			return nil, err
		}
		requestMain.Token = jwtTokenString
	case AuthTypePat:
		logger.WithContext(sc.ctx).Info("Programmatic access token")
		requestMain.Authenticator = AuthTypePat.String()
		requestMain.LoginName = sc.cfg.User
		var err error
		if requestMain.Token, err = sfconfig.GetToken(sc.cfg); err != nil {
			return nil, fmt.Errorf("failed to get PAT token: %w", err)
		}
	case AuthTypeSnowflake:
		logger.WithContext(sc.ctx).Debug("Username and password")
		requestMain.LoginName = sc.cfg.User
		requestMain.Password = sc.cfg.Password
		switch {
		case sc.cfg.PasscodeInPassword:
			requestMain.ExtAuthnDuoMethod = "passcode"
		case sc.cfg.Passcode != "":
			requestMain.Passcode = sc.cfg.Passcode
			requestMain.ExtAuthnDuoMethod = "passcode"
		}
	case AuthTypeUsernamePasswordMFA:
		logger.WithContext(sc.ctx).Debug("Username and password MFA")
		requestMain.LoginName = sc.cfg.User
		requestMain.Password = sc.cfg.Password
		switch {
		case sc.mfaToken != "":
			requestMain.Token = sc.mfaToken
		case sc.cfg.PasscodeInPassword:
			requestMain.ExtAuthnDuoMethod = "passcode"
		case sc.cfg.Passcode != "":
			requestMain.Passcode = sc.cfg.Passcode
			requestMain.ExtAuthnDuoMethod = "passcode"
		}
	case AuthTypeOAuthAuthorizationCode:
		logger.WithContext(sc.ctx).Debug("OAuth authorization code")
		token, err := authenticateByAuthorizationCode(sc, lease)
		if err != nil {
			return nil, err
		}
		requestMain.LoginName = sc.cfg.User
		requestMain.Token = token
	case AuthTypeOAuthClientCredentials:
		logger.WithContext(sc.ctx).Debug("OAuth client credentials")
		oauthClient, err := newOauthClient(sc.ctx, sc.cfg, sc)
		if err != nil {
			return nil, err
		}
		token, err := oauthClient.authenticateByOAuthClientCredentials(lease)
		if err != nil {
			return nil, err
		}
		requestMain.LoginName = sc.cfg.User
		requestMain.Token = token
	case AuthTypeWorkloadIdentityFederation:
		logger.WithContext(sc.ctx).Debug("Workload Identity Federation")
		wifAttestationProvider := createWifAttestationProvider(sc.ctx, sc.cfg, sc.telemetry)
		wifAttestation, err := wifAttestationProvider.getAttestation(sc.cfg.WorkloadIdentityProvider)
		if err != nil {
			return nil, err
		}
		if wifAttestation == nil {
			return nil, errors.New("workload identity federation attestation is not available, please check your configuration")
		}
		requestMain.Authenticator = AuthTypeWorkloadIdentityFederation.String()
		requestMain.Token = wifAttestation.Credential
		requestMain.Provider = wifAttestation.ProviderType
	}

	logger.WithContext(sc.ctx).Debugf("Request body is created for the authentication. Authenticator: %s, User: %s, Account: %s", sc.cfg.Authenticator.String(), sc.cfg.User, sc.cfg.Account)

	authRequest := authRequest{
		Data: requestMain,
	}
	jsonBody, err := json.Marshal(authRequest)
	if err != nil {
		logger.WithContext(sc.ctx).Errorf("Failed to marshal JSON. err: %v", err)
		return nil, err
	}
	return jsonBody, nil
}

func authenticateByAuthorizationCode(sc *snowflakeConn, lease *Lease) (string, error) {
	oauthClient, err := newOauthClient(sc.ctx, sc.cfg, sc)
	if err != nil {
		return "", err
	}
	if !isEligibleForParallelLogin(sc.cfg, sc.cfg.ClientStoreTemporaryCredential) {
		return oauthClient.authenticateByOAuthAuthorizationCode(lease)
	}

	lockKey := newOAuthAccessTokenSpec(sc.cfg)
	valueAwaiter := valueAwaitHolder.get(lockKey)
	defer valueAwaiter.resumeOne()
	token, err := awaitValue(valueAwaiter, func() (string, error) {
		return credentialsStorage.getCredential(lease, newOAuthAccessTokenSpec(sc.cfg))
	}, func(s string, err error) bool {
		return s != ""
	}, func() string {
		return ""
	})
	if err != nil || token != "" {
		return token, err
	}
	token, err = oauthClient.authenticateByOAuthAuthorizationCode(lease)
	if err != nil {
		return "", err
	}
	valueAwaiter.done()
	return token, err
}

// Generate a JWT token in string given the configuration
func prepareJWTToken(config *Config) (string, error) {
	if config.PrivateKey == nil {
		return "", errors.New("trying to use keypair authentication, but PrivateKey was not provided in the driver config")
	}
	logger.Debug("preparing JWT for keypair authentication")
	pubBytes, err := x509.MarshalPKIXPublicKey(config.PrivateKey.Public())
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(pubBytes)

	accountName := sfconfig.ExtractAccountName(config.Account)
	userName := strings.ToUpper(config.User)

	issueAtTime := time.Now().UTC()
	jwtClaims := jwt.MapClaims{
		"iss": fmt.Sprintf("%s.%s.%s", accountName, userName, "SHA256:"+base64.StdEncoding.EncodeToString(hash[:])),
		"sub": fmt.Sprintf("%s.%s", accountName, userName),
		"iat": issueAtTime.Unix(),
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		"exp": issueAtTime.Add(config.JWTExpireTimeout).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)

	tokenString, err := token.SignedString(config.PrivateKey)

	if err != nil {
		return "", err
	}

	logger.Debugf("successfully generated JWT with following claims: %v", jwtClaims)
	return tokenString, err
}

func (s *hostUserTokenSpec) lockID() string {
	return s.snowflake + "|" + s.username + "|" + string(s.tokenType)
}

func (s *oauthTokenSpec) lockID() string {
	return s.idp + "|" + s.snowflake + "|" + s.username + "|" + s.role + "|" + string(s.tokenType)
}

// External-browser failure backoff. dbt-only: not upstream.
//
// An IP restriction or misconfigured IDP fails every attempt, and each attempt
// opens a browser tab, so a reconnecting pool produces a storm of tabs at a page
// the user cannot get past. Process-global because the tabs it prevents are a
// property of the machine's display, not of one connection.
var lastFail sync.Map // backoff key -> time.Time at which the refusal expires

const extBrowserBackoffWindow = 60 * time.Second

// Accepts a bare host, host:port, or full URL, since Config.Host may hold any of
// the three depending on how the config was built.
func normalizeHost(h string) string {
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		if u, err := url.Parse(h); err == nil && u != nil && u.Host != "" {
			h = u.Host
		}
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	return strings.ToLower(h)
}

// User is upper-cased because Snowflake login names are case-insensitive, so
// differing spellings must not each get their own tab budget.
func extBrowserBackoffKey(host, user string) string {
	return normalizeHost(host) + "|" + strings.ToUpper(user)
}

// Prunes an expired entry as a side effect. Takes now rather than calling
// time.Now so the window is testable without sleeping.
func extBrowserBackoffActive(key string, now time.Time) bool {
	value, ok := lastFail.Load(key)
	if !ok {
		return false
	}
	if until, ok := value.(time.Time); ok && now.Before(until) {
		return true
	}
	lastFail.Delete(key)
	return false
}

func recordExtBrowserFailure(key string, now time.Time) {
	lastFail.Store(key, now.Add(extBrowserBackoffWindow))
}

func clearExtBrowserFailure(key string) {
	lastFail.Delete(key)
}

// dbt-only: the first attempt runs on a *broken* lease with relaxed reads, so a
// login served entirely from cache never pays for a lease. Any operation that must
// write, or that refuses to act on a relaxed read — opening a browser tab, above
// all — fails with ErrFailedToRenewLease, and the second attempt runs holding a
// real lease.
func authenticateWithConfig(sc *snowflakeConn) error {
	lease := credentialsStorage.brokenLease()
	lease.RelaxedReadAllowed = true

	var err error
	for range 2 {
		// Deferred per iteration on purpose: the receiver is bound now, so both the
		// broken lease and any acquired replacement are released at return.
		defer func(l *Lease) {
			if relErr := l.Release(); relErr != nil {
				logger.WithContext(sc.ctx).Debugf("failed to release credential cache lease. %v", relErr)
			}
		}(lease)

		err = tryAuthenticateWithConfig(lease, sc)
		if err == nil {
			return nil
		}
		var leaseErr *LeaseError
		if lease.RelaxedReadAllowed && errors.As(err, &leaseErr) && leaseErr.Code == ErrFailedToRenewLease {
			if lease, err = credentialsStorage.acquireLease(); err == nil {
				continue
			}
		}
		return err
	}
	return err
}

func tryAuthenticateWithConfig(lease *Lease, sc *snowflakeConn) error {
	var authData *authResponseMain
	var samlResponse []byte
	var proofKey []byte
	var err error

	mfaTokenLockKey := newMfaTokenSpec(sc.cfg)
	idTokenLockKey := newIDTokenSpec(sc.cfg)
	extBrowserKey := extBrowserBackoffKey(sc.cfg.Host, sc.cfg.User)

	if sc.cfg.Authenticator == AuthTypeExternalBrowser || sc.cfg.Authenticator == AuthTypeOAuthAuthorizationCode || sc.cfg.Authenticator == AuthTypeOAuthClientCredentials {
		// dbt-only: upstream gates on the platforms that have a keyring. dbt uses
		// the file cache on all three, so the gate follows the storage layer.
		if isCacheSupportedGOOS(runtime.GOOS) && sc.cfg.ClientStoreTemporaryCredential == sfconfig.BoolNotSet {
			sc.cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		}
		if sc.cfg.Authenticator == AuthTypeExternalBrowser {
			if isEligibleForParallelLogin(sc.cfg, sc.cfg.ClientStoreTemporaryCredential) {
				valueAwaiter := valueAwaitHolder.get(idTokenLockKey)
				defer valueAwaiter.resumeOne()
				sc.idToken, _ = awaitValue(valueAwaiter, func() (string, error) {
					credential, _ := credentialsStorage.getCredential(lease, newIDTokenSpec(sc.cfg))
					return credential, nil
				}, func(s string, err error) bool {
					return s != ""
				}, func() string {
					return ""
				})
			} else if sc.cfg.ClientStoreTemporaryCredential == ConfigBoolTrue {
				sc.idToken, _ = credentialsStorage.getCredential(lease, newIDTokenSpec(sc.cfg))
			}
		}
		// Disable console login by default
		if sc.cfg.DisableConsoleLogin == sfconfig.BoolNotSet {
			sc.cfg.DisableConsoleLogin = ConfigBoolTrue
		}
	}

	if sc.cfg.Authenticator == AuthTypeUsernamePasswordMFA {
		// dbt-only: The fork changed only the ID-token gate and left this
		// one on the keyring platforms, so MFA caching silently stayed off on linux
		// while ID-token caching was on. Same predicate, so same answer.
		if isCacheSupportedGOOS(runtime.GOOS) && sc.cfg.ClientRequestMfaToken == sfconfig.BoolNotSet {
			sc.cfg.ClientRequestMfaToken = ConfigBoolTrue
		}
		if isEligibleForParallelLogin(sc.cfg, sc.cfg.ClientRequestMfaToken) {
			valueAwaiter := valueAwaitHolder.get(mfaTokenLockKey)
			defer valueAwaiter.resumeOne()
			sc.mfaToken, _ = awaitValue(valueAwaiter, func() (string, error) {
				credential, err := credentialsStorage.getCredential(lease, newMfaTokenSpec(sc.cfg))
				if err != nil {
					logger.WithContext(sc.ctx).Warnf("failed to get MFA token from credential storage: %v", err)
				}
				return credential, nil
			}, func(s string, err error) bool {
				return s != ""
			}, func() string {
				return ""
			})
		} else if sc.cfg.ClientRequestMfaToken == ConfigBoolTrue {
			tok, err := credentialsStorage.getCredential(lease, newMfaTokenSpec(sc.cfg))
			if err != nil {
				logger.WithContext(sc.ctx).Warnf("failed to get MFA token from credential storage: %v", err)
			}
			sc.mfaToken = tok
		}
	}

	logger.WithContext(sc.ctx).Infof("Authenticating via %v", sc.cfg.Authenticator.String())
	switch sc.cfg.Authenticator {
	case AuthTypeExternalBrowser:
		if sc.idToken == "" {
			if extBrowserBackoffActive(extBrowserKey, time.Now()) {
				sc.cleanup()
				return errors.New("External browser sign-in failed recently due to an unrecoverable authentication failure (e.g., IP restriction, IDP error)")
			}
			samlResponse, proofKey, err = authenticateByExternalBrowser(
				sc.ctx,
				lease,
				sc.rest,
				sc.cfg.Authenticator.String(),
				sc.cfg.Application,
				sc.cfg.Account,
				sc.cfg.User,
				sc.cfg.ExternalBrowserTimeout,
				sc.cfg.DisableConsoleLogin)
			if err != nil {
				sc.cleanup()
				return err
			}
		}
	}
	authData, err = authenticate(
		sc.ctx,
		lease,
		sc,
		samlResponse,
		proofKey)
	if err != nil {
		// dbt-only: a cancelled context is not a credential problem. Return before
		// discarding a cached token or opening a tab.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			sc.cleanup()
			return err
		}
		switch {
		// dbt-only: the cached ID token was rejected. Discard it and try one
		// interactive login.
		//
		// TODO: not gated on the backoff, matching the fork. A connection holding a
		// stale token skips the gate above, so a pool of them can each open a tab
		// past an active backoff. Consider gating once the lease lands and the
		// escalate-vs-terminate signal is settled.
		case shouldRetryWithFreshExternalBrowserLogin(sc.cfg.Authenticator, sc.idToken):
			if err := credentialsStorage.deleteCredential(lease, newIDTokenSpec(sc.cfg)); err != nil && lease.RelaxedReadAllowed {
				return err
			}
			sc.idToken = ""
			samlResponse, proofKey, err = authenticateByExternalBrowser(
				sc.ctx,
				lease,
				sc.rest,
				sc.cfg.Authenticator.String(),
				sc.cfg.Application,
				sc.cfg.Account,
				sc.cfg.User,
				sc.cfg.ExternalBrowserTimeout,
				sc.cfg.DisableConsoleLogin)
			if err != nil {
				sc.cleanup() // sign-in did not complete; stays retryable, no backoff
				return err
			}
			authData, err = authenticate(sc.ctx, lease, sc, samlResponse, proofKey)
			if err == nil {
				break
			}
			fallthrough

		case isOAuthRefreshable(err):
			// Re-asserted: a fallthrough from above enters here without evaluating
			// the guard.
			if isOAuthRefreshable(err) {
				credentialsStorage.deleteCredential(lease, newOAuthAccessTokenSpec(sc.cfg))

				if sc.cfg.Authenticator == AuthTypeOAuthAuthorizationCode {
					doRefreshTokenWithLock(sc, lease)
				}

				// if refreshing succeeds for authorization code, we will take a token from cache
				// if it fails, we will just run the full flow
				authData, err = authenticate(sc.ctx, lease, sc, nil, nil)
			}
			if err == nil {
				break
			}
			fallthrough

		default:
			// The early return above only sees the first authenticate; a retry above
			// can surface its own cancellation, which must not cost a backoff.
			if sc.cfg.Authenticator == AuthTypeExternalBrowser &&
				!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				recordExtBrowserFailure(extBrowserKey, time.Now())
			}
			sc.cleanup()
			return err
		}
	}
	if sc.cfg.Authenticator == AuthTypeUsernamePasswordMFA && isEligibleForParallelLogin(sc.cfg, sc.cfg.ClientRequestMfaToken) {
		valueAwaiter := valueAwaitHolder.get(mfaTokenLockKey)
		valueAwaiter.done()
	}
	if sc.cfg.Authenticator == AuthTypeExternalBrowser && isEligibleForParallelLogin(sc.cfg, sc.cfg.ClientStoreTemporaryCredential) {
		valueAwaiter := valueAwaitHolder.get(idTokenLockKey)
		valueAwaiter.done()
	}
	clearExtBrowserFailure(extBrowserKey)
	sc.populateSessionParameters(authData.Parameters)
	sc.configureTelemetry()
	sc.ctx = context.WithValue(sc.ctx, SFSessionIDKey, authData.SessionID)
	return nil
}

func doRefreshTokenWithLock(sc *snowflakeConn, lease *Lease) {
	if oauthClient, err := newOauthClient(sc.ctx, sc.cfg, sc); err != nil {
		logger.Warnf("failed to create oauth client. %v", err)
	} else {
		lockKey := newOAuthRefreshTokenSpec(sc.cfg)
		if _, err = getValueWithLock(chooseLockerForAuth(sc.cfg), lockKey, func() (string, error) {
			if err = oauthClient.refreshToken(lease); err != nil {
				logger.Warnf("cannot refresh token. %v", err)
				credentialsStorage.deleteCredential(lease, newOAuthRefreshTokenSpec(sc.cfg))
				return "", err
			}
			return "", nil
		}); err != nil {
			logger.Warnf("failed to refresh token with lock. %v", err)
		}
	}
}

func chooseLockerForAuth(cfg *Config) locker {
	if cfg.SingleAuthenticationPrompt == ConfigBoolFalse {
		return noopLocker
	}
	if cfg.User == "" {
		return noopLocker
	}
	return exclusiveLocker
}

func isEligibleForParallelLogin(cfg *Config, cacheEnabled ConfigBool) bool {
	return cfg.SingleAuthenticationPrompt != ConfigBoolFalse && cfg.User != "" && cacheEnabled == ConfigBoolTrue
}
