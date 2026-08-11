package gosnowflake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	sfconfig "github.com/snowflakedb/gosnowflake/v2/internal/config"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestUnitPostAuth(t *testing.T) {
	sr := &snowflakeRestful{
		TokenAccessor: getSimpleTokenAccessor(),
		FuncAuthPost:  postAuthTestAfterRenew,
	}
	var err error
	bodyCreator := func() ([]byte, error) {
		return []byte{0x12, 0x34}, nil
	}
	_, err = postAuth(context.Background(), sr, sr.Client, &url.Values{}, make(map[string]string), bodyCreator, 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	sr.FuncAuthPost = postAuthTestError
	_, err = postAuth(context.Background(), sr, sr.Client, &url.Values{}, make(map[string]string), bodyCreator, 0)
	if err == nil {
		t.Fatal("should have failed to auth for unknown reason")
	}
	sr.FuncAuthPost = postAuthTestAppBadGatewayError
	_, err = postAuth(context.Background(), sr, sr.Client, &url.Values{}, make(map[string]string), bodyCreator, 0)
	if err == nil {
		t.Fatal("should have failed to auth for unknown reason")
	}
	sr.FuncAuthPost = postAuthTestAppForbiddenError
	_, err = postAuth(context.Background(), sr, sr.Client, &url.Values{}, make(map[string]string), bodyCreator, 0)
	if err == nil {
		t.Fatal("should have failed to auth for unknown reason")
	}
	sr.FuncAuthPost = postAuthTestAppUnexpectedError
	_, err = postAuth(context.Background(), sr, sr.Client, &url.Values{}, make(map[string]string), bodyCreator, 0)
	if err == nil {
		t.Fatal("should have failed to auth for unknown reason")
	}
}

func postAuthFailServiceIssue(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return nil, &SnowflakeError{
		Number: ErrCodeServiceUnavailable,
	}
}

func postAuthFailWrongAccount(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return nil, &SnowflakeError{
		Number: ErrCodeFailedToConnect,
	}
}

func postAuthFailUnknown(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return nil, &SnowflakeError{
		Number: ErrFailedToAuth,
	}
}

func postAuthSuccessWithErrorCode(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Code:    "98765",
		Message: "wrong!",
	}, nil
}

func postAuthSuccessWithInvalidErrorCode(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Code:    "abcdef",
		Message: "wrong!",
	}, nil
}

func postAuthSuccess(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, _ bodyCreatorType, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckSAMLResponse(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, err := bodyCreator()
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}
	if ar.Data.RawSAMLResponse == "" {
		return nil, errors.New("SAML response is empty")
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

// Checks that the request body generated when authenticating with OAuth
// contains all the necessary values.
func postAuthCheckOAuth(
	_ context.Context,
	_ *snowflakeRestful,
	_ *http.Client,
	_ *url.Values, _ map[string]string,
	bodyCreator bodyCreatorType,
	_ time.Duration,
) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}
	if ar.Data.Authenticator != AuthTypeOAuth.String() {
		return nil, errors.New("Authenticator is not OAUTH")
	}
	if ar.Data.Token == "" {
		return nil, errors.New("Token is empty")
	}
	if ar.Data.LoginName == "" {
		return nil, errors.New("Login name is empty")
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckPasscode(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}
	if ar.Data.Passcode != "987654321" || ar.Data.ExtAuthnDuoMethod != "passcode" {
		return nil, fmt.Errorf("passcode didn't match. expected: 987654321, got: %v, duo: %v", ar.Data.Passcode, ar.Data.ExtAuthnDuoMethod)
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckPasscodeInPassword(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}
	if ar.Data.Passcode != "" || ar.Data.ExtAuthnDuoMethod != "passcode" {
		return nil, fmt.Errorf("passcode must be empty, got: %v, duo: %v", ar.Data.Passcode, ar.Data.ExtAuthnDuoMethod)
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckUsernamePasswordMfa(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.SessionParameters["CLIENT_REQUEST_MFA_TOKEN"] != true {
		return nil, fmt.Errorf("expected client_request_mfa_token to be true but was %v", ar.Data.SessionParameters["CLIENT_REQUEST_MFA_TOKEN"])
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			MfaToken:    "mockedMfaToken",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckUsernamePasswordMfaToken(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.Token != "mockedMfaToken" {
		return nil, fmt.Errorf("unexpected mfa token: %v", ar.Data.Token)
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			MfaToken:    "mockedMfaToken",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckUsernamePasswordMfaFailed(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.Token != "mockedMfaToken" {
		return nil, fmt.Errorf("unexpected mfa token: %v", ar.Data.Token)
	}
	return &authResponse{
		Success: false,
		Data:    authResponseMain{},
		Message: "auth failed",
		Code:    "260008",
	}, nil
}

func postAuthCheckExternalBrowser(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.SessionParameters["CLIENT_STORE_TEMPORARY_CREDENTIAL"] != true {
		return nil, fmt.Errorf("expected client_store_temporary_credential to be true but was %v", ar.Data.SessionParameters["CLIENT_STORE_TEMPORARY_CREDENTIAL"])
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			IDToken:     "mockedIDToken",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckExternalBrowserToken(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.Token != "mockedIDToken" {
		return nil, fmt.Errorf("unexpected mfatoken: %v", ar.Data.Token)
	}
	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			IDToken:     "mockedIDToken",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func postAuthCheckExternalBrowserFailed(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest
	jsonBody, _ := bodyCreator()
	if err := json.Unmarshal(jsonBody, &ar); err != nil {
		return nil, err
	}

	if ar.Data.SessionParameters["CLIENT_STORE_TEMPORARY_CREDENTIAL"] != true {
		return nil, fmt.Errorf("expected client_store_temporary_credential to be true but was %v", ar.Data.SessionParameters["CLIENT_STORE_TEMPORARY_CREDENTIAL"])
	}
	return &authResponse{
		Success: false,
		Data:    authResponseMain{},
		Message: "auth failed",
		Code:    "260008",
	}, nil
}

type restfulTestWrapper struct {
	t *testing.T
}

func (rtw restfulTestWrapper) postAuthOktaWithNewToken(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
	var ar authRequest

	cfg := &Config{
		Authenticator: AuthTypeOkta,
	}

	// Retry 3 times and success
	client := &fakeHTTPClient{
		cnt:        3,
		success:    true,
		statusCode: 429,
		t:          rtw.t,
	}

	urlPtr, err := url.Parse("https://fakeaccountretrylogin.snowflakecomputing.com:443/login-request?request_guid=testguid")
	if err != nil {
		return &authResponse{}, err
	}

	body := func() ([]byte, error) {
		jsonBody, _ := bodyCreator()
		if err := json.Unmarshal(jsonBody, &ar); err != nil {
			return nil, err
		}
		return jsonBody, err
	}

	_, err = newRetryHTTP(context.Background(), client, emptyRequest, urlPtr, make(map[string]string), 60*time.Second, 3, defaultTimeProvider, cfg).doPost().setBodyCreator(body).execute()
	if err != nil {
		return &authResponse{}, err
	}

	return &authResponse{
		Success: true,
		Data: authResponseMain{
			Token:       "t",
			MasterToken: "m",
			MfaToken:    "mockedMfaToken",
			SessionInfo: authResponseSessionInfo{
				DatabaseName: "dbn",
			},
		},
	}, nil
}

func getDefaultSnowflakeConn() *snowflakeConn {
	sc := &snowflakeConn{
		rest: &snowflakeRestful{
			TokenAccessor: getSimpleTokenAccessor(),
		},
		cfg: &Config{
			Account:            "a",
			User:               "u",
			Password:           "p",
			Database:           "d",
			Schema:             "s",
			Warehouse:          "w",
			Role:               "r",
			Region:             "",
			PasscodeInPassword: false,
			Passcode:           "",
			Application:        "testapp",
		},
		telemetry: &snowflakeTelemetry{enabled: false},
	}
	return sc
}

func TestUnitAuthenticateWithTokenAccessor(t *testing.T) {
	expectedSessionID := int64(123)
	expectedMasterToken := "master_token"
	expectedToken := "auth_token"

	ta := getSimpleTokenAccessor()
	ta.SetTokens(expectedToken, expectedMasterToken, expectedSessionID)
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeTokenAccessor
	sc.cfg.TokenAccessor = ta
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthFailServiceIssue,
		TokenAccessor: ta,
	}
	sc.rest = sr

	// FuncPostAuth is set to fail, but AuthTypeTokenAccessor should not even make a call to FuncPostAuth
	resp, err := authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("should not have failed, err %v", err)
	}

	if resp.SessionID != expectedSessionID {
		t.Fatalf("Expected session id %v but got %v", expectedSessionID, resp.SessionID)
	}
	if resp.Token != expectedToken {
		t.Fatalf("Expected token %v but got %v", expectedToken, resp.Token)
	}
	if resp.MasterToken != expectedMasterToken {
		t.Fatalf("Expected master token %v but got %v", expectedMasterToken, resp.MasterToken)
	}
	if resp.SessionInfo.DatabaseName != sc.cfg.Database {
		t.Fatalf("Expected database %v but got %v", sc.cfg.Database, resp.SessionInfo.DatabaseName)
	}
	if resp.SessionInfo.WarehouseName != sc.cfg.Warehouse {
		t.Fatalf("Expected warehouse %v but got %v", sc.cfg.Warehouse, resp.SessionInfo.WarehouseName)
	}
	if resp.SessionInfo.RoleName != sc.cfg.Role {
		t.Fatalf("Expected role %v but got %v", sc.cfg.Role, resp.SessionInfo.RoleName)
	}
	if resp.SessionInfo.SchemaName != sc.cfg.Schema {
		t.Fatalf("Expected schema %v but got %v", sc.cfg.Schema, resp.SessionInfo.SchemaName)
	}
}

func TestUnitAuthenticate(t *testing.T) {
	var err error
	var driverErr *SnowflakeError
	var ok bool

	ta := getSimpleTokenAccessor()
	sc := getDefaultSnowflakeConn()
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthFailServiceIssue,
		TokenAccessor: ta,
	}
	sc.rest = sr

	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed.")
	}
	driverErr, ok = err.(*SnowflakeError)
	if !ok || driverErr.Number != ErrCodeServiceUnavailable {
		t.Fatalf("Snowflake error is expected. err: %v", driverErr)
	}
	sr.FuncPostAuth = postAuthFailWrongAccount
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed.")
	}
	driverErr, ok = err.(*SnowflakeError)
	if !ok || driverErr.Number != ErrCodeFailedToConnect {
		t.Fatalf("Snowflake error is expected. err: %v", driverErr)
	}
	sr.FuncPostAuth = postAuthFailUnknown
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed.")
	}
	driverErr, ok = err.(*SnowflakeError)
	if !ok || driverErr.Number != ErrFailedToAuth {
		t.Fatalf("Snowflake error is expected. err: %v", driverErr)
	}
	ta.SetTokens("bad-token", "bad-master-token", 1)
	sr.FuncPostAuth = postAuthSuccessWithErrorCode
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed.")
	}
	newToken, newMasterToken, newSessionID := ta.GetTokens()
	if newToken != "" || newMasterToken != "" || newSessionID != -1 {
		t.Fatalf("failed auth should have reset tokens: %v %v %v", newToken, newMasterToken, newSessionID)
	}
	driverErr, ok = err.(*SnowflakeError)
	if !ok || driverErr.Number != 98765 {
		t.Fatalf("Snowflake error is expected. err: %v", driverErr)
	}
	ta.SetTokens("bad-token", "bad-master-token", 1)
	sr.FuncPostAuth = postAuthSuccessWithInvalidErrorCode
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed.")
	}
	oldToken, oldMasterToken, oldSessionID := ta.GetTokens()
	if oldToken != "" || oldMasterToken != "" || oldSessionID != -1 {
		t.Fatalf("failed auth should have reset tokens: %v %v %v", oldToken, oldMasterToken, oldSessionID)
	}
	sr.FuncPostAuth = postAuthSuccess
	var resp *authResponseMain
	resp, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to auth. err: %v", err)
	}
	if resp.SessionInfo.DatabaseName != "dbn" {
		t.Fatalf("failed to get response from auth")
	}
	newToken, newMasterToken, newSessionID = ta.GetTokens()
	if newToken == oldToken {
		t.Fatalf("new token was not set: %v", newToken)
	}
	if newMasterToken == oldMasterToken {
		t.Fatalf("new master token was not set: %v", newMasterToken)
	}
	if newSessionID == oldSessionID {
		t.Fatalf("new session id was not set: %v", newSessionID)
	}
}

func TestUnitAuthenticateSaml(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthSAMLAuthSuccess,
		FuncPostAuthOKTA: postAuthOKTASuccess,
		FuncGetSSO:       getSSOSuccess,
		FuncPostAuth:     postAuthCheckSAMLResponse,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeOkta
	sc.cfg.OktaURL = &url.URL{
		Scheme: "https",
		Host:   "abc.com",
	}
	sc.rest = sr
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	assertNilF(t, err, "failed to run.")
}

// Unit test for OAuth.
func TestUnitAuthenticateOAuth(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckOAuth,
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Token = "oauthToken"
	sc.cfg.Authenticator = AuthTypeOAuth
	sc.rest = sr
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}
}

func TestUnitAuthenticatePasscode(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckPasscode,
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Passcode = "987654321"
	sc.rest = sr

	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}
	sr.FuncPostAuth = postAuthCheckPasscodeInPassword
	sc.rest = sr
	sc.cfg.PasscodeInPassword = true
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}
}

// Test JWT function in the local environment against the validation function in go
func TestUnitAuthenticateJWT(t *testing.T) {
	var err error

	// Generate a fresh private key for this unit test only
	localTestKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test private key: %s", err.Error())
	}

	// Create custom JWT verification function that uses the local key
	postAuthCheckLocalJWTToken := func(_ context.Context, _ *snowflakeRestful, _ *http.Client, _ *url.Values, _ map[string]string, bodyCreator bodyCreatorType, _ time.Duration) (*authResponse, error) {
		var ar authRequest
		jsonBody, _ := bodyCreator()
		if err := json.Unmarshal(jsonBody, &ar); err != nil {
			return nil, err
		}
		if ar.Data.Authenticator != AuthTypeJwt.String() {
			return nil, errors.New("Authenticator is not JWT")
		}

		tokenString := ar.Data.Token

		// Validate token using the local test key's public key
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return localTestKey.Public(), nil // Use local key for verification
		})
		if err != nil {
			return nil, err
		}

		return &authResponse{
			Success: true,
			Data: authResponseMain{
				Token:       "t",
				MasterToken: "m",
				SessionInfo: authResponseSessionInfo{
					DatabaseName: "dbn",
				},
			},
		}, nil
	}

	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckLocalJWTToken, // Use local verification function
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeJwt
	sc.cfg.JWTExpireTimeout = time.Duration(sfconfig.DefaultJWTTimeout)
	sc.cfg.PrivateKey = localTestKey
	sc.rest = sr

	// A valid JWT token should pass
	if _, err = authenticate(context.Background(), sc, []byte{}, []byte{}); err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}

	// An invalid JWT token should not pass
	invalidPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
	}
	sc.cfg.PrivateKey = invalidPrivateKey
	if _, err = authenticate(context.Background(), sc, []byte{}, []byte{}); err == nil {
		t.Fatalf("invalid token passed")
	}
}

func TestUnitAuthenticateUsernamePasswordMfa(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckUsernamePasswordMfa,
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeUsernamePasswordMFA
	sc.cfg.ClientRequestMfaToken = ConfigBoolTrue
	sc.rest = sr
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}

	sr.FuncPostAuth = postAuthCheckUsernamePasswordMfaToken
	sc.mfaToken = "mockedMfaToken"
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}

	sr.FuncPostAuth = postAuthCheckUsernamePasswordMfaFailed
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed")
	}
}

func TestUnitAuthenticateWithConfigMFA(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckUsernamePasswordMfa,
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeUsernamePasswordMFA
	sc.cfg.ClientRequestMfaToken = ConfigBoolTrue
	sc.rest = sr
	sc.ctx = context.Background()
	err = authenticateWithConfig(sc)
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}
}

// This test creates two groups of scenarios:
// a) singleAuthenticationPrompt=true - in this case, we start authenticating threads at once,
// but due to locking mechanism only one should reach wiremock without MFA token.
// b) singleAuthenticationPrompt=false - in this case, there is no locking, so all threads should rush,
// but on Wiremock only first will be served with correct response (simulating a user confirming MFA only once).
// The remaining threads should return error.
func TestMfaParallelLogin(t *testing.T) {
	skipOnMissingHome(t)
	skipOnMac(t, "interactive keyring access not available on macOS runners")
	cfg := wiremock.connectionConfig()
	tokenSpec := newMfaTokenSpec(cfg)

	for _, singleAuthenticationPrompt := range []ConfigBool{ConfigBoolTrue, ConfigBoolFalse} {
		t.Run("starts without mfa token, singleAuthenticationPrompt="+singleAuthenticationPrompt.String(), func(t *testing.T) {
			wiremock.registerMappings(t, newWiremockMapping("auth/mfa/parallel_login_successful_flow.json"),
				newWiremockMapping("select1.json"),
				newWiremockMapping("close_session.json"))
			cfg := wiremock.connectionConfig()
			cfg.Authenticator = AuthTypeUsernamePasswordMFA
			cfg.SingleAuthenticationPrompt = singleAuthenticationPrompt
			cfg.ClientRequestMfaToken = ConfigBoolTrue
			connector := NewConnector(SnowflakeDriver{}, *cfg)
			db := sql.OpenDB(connector)
			defer db.Close()
			credentialsStorage.deleteCredential(tokenSpec)
			errs := initPoolWithSizeAndReturnErrors(db, 20)
			if singleAuthenticationPrompt == ConfigBoolTrue {
				assertEqualE(t, len(errs), 0)
			} else {
				// most of for the one that actually retrieves MFA token should fail
				assertEqualE(t, len(errs), 19)
			}
		})

		t.Run("starts without mfa token, first attempt fails, singleAuthenticationPrompt="+singleAuthenticationPrompt.String(), func(t *testing.T) {
			wiremock.registerMappings(t, newWiremockMapping("auth/mfa/parallel_login_first_fails_then_successful_flow.json"),
				newWiremockMapping("select1.json"),
				newWiremockMapping("close_session.json"))
			cfg := wiremock.connectionConfig()
			cfg.Authenticator = AuthTypeUsernamePasswordMFA
			cfg.SingleAuthenticationPrompt = singleAuthenticationPrompt
			cfg.ClientRequestMfaToken = ConfigBoolTrue
			credentialsStorage.deleteCredential(tokenSpec)
			connector := NewConnector(SnowflakeDriver{}, *cfg)
			db := sql.OpenDB(connector)
			defer db.Close()
			errs := initPoolWithSizeAndReturnErrors(db, 20)
			if singleAuthenticationPrompt == ConfigBoolTrue {
				assertEqualF(t, len(errs), 1)
				assertStringContainsE(t, errs[0].Error(), "MFA with TOTP is required")
			} else {
				assertEqualE(t, len(errs), 19)
			}
		})
	}
}

func TestUnitAuthenticateWithConfigOkta(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthSAMLAuthSuccess,
		FuncPostAuthOKTA: postAuthOKTASuccess,
		FuncGetSSO:       getSSOSuccess,
		FuncPostAuth:     postAuthCheckSAMLResponse,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeOkta
	sc.cfg.OktaURL = &url.URL{
		Scheme: "https",
		Host:   "abc.com",
	}
	sc.rest = sr
	sc.ctx = context.Background()

	err = authenticateWithConfig(sc)
	assertNilE(t, err, "expected to have no error.")

	sr.FuncPostAuthSAML = postAuthSAMLError
	err = authenticateWithConfig(sc)
	assertNotNilF(t, err, "should have failed at FuncPostAuthSAML.")
	assertEqualE(t, err.Error(), "failed to get SAML response")
}

func TestUnitAuthenticateWithExternalBrowserParallel(t *testing.T) {
	skipOnMissingHome(t)
	skipOnMac(t, "interactive keyring access not available on macOS runners")
	t.Run("no ID token cached", func(t *testing.T) {
		origSamlResponseProvider := defaultSamlResponseProvider
		defer func() { defaultSamlResponseProvider = origSamlResponseProvider }()
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &nonInteractiveSamlResponseProvider{t: t}
		}
		wiremock.registerMappings(t, newWiremockMapping("auth/external_browser/successful_flow.json"),
			newWiremockMapping("select1.json"),
			newWiremockMapping("close_session.json"))
		cfg := wiremock.connectionConfig()
		cfg.Authenticator = AuthTypeExternalBrowser
		cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		connector := NewConnector(SnowflakeDriver{}, *cfg)
		credentialsStorage.deleteCredential(newIDTokenSpec(cfg))
		db := sql.OpenDB(connector)
		defer db.Close()
		runSmokeQuery(t, db)
		assertEqualE(t, credentialsStorage.getCredential(newIDTokenSpec(cfg)), "test-id-token")
	})

	t.Run("ID token cached", func(t *testing.T) {
		wiremock.registerMappings(t, newWiremockMapping("auth/external_browser/successful_flow.json"),
			newWiremockMapping("select1.json"),
			newWiremockMapping("close_session.json"))
		cfg := wiremock.connectionConfig()
		cfg.Authenticator = AuthTypeExternalBrowser
		cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		connector := NewConnector(SnowflakeDriver{}, *cfg)
		credentialsStorage.setCredential(newIDTokenSpec(cfg), "test-id-token")
		db := sql.OpenDB(connector)
		defer db.Close()
		runSmokeQuery(t, db)
	})

	t.Run("first connection retrieves ID token, second request uses cached ID token", func(t *testing.T) {
		origSamlResponseProvider := defaultSamlResponseProvider
		defer func() { defaultSamlResponseProvider = origSamlResponseProvider }()
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &nonInteractiveSamlResponseProvider{t: t}
		}
		wiremock.registerMappings(t, newWiremockMapping("auth/external_browser/parallel_login_successful_flow.json"),
			newWiremockMapping("select1.json"),
			newWiremockMapping("close_session.json"))
		cfg := wiremock.connectionConfig()
		cfg.Authenticator = AuthTypeExternalBrowser
		cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		connector := NewConnector(SnowflakeDriver{}, *cfg)
		credentialsStorage.deleteCredential(newIDTokenSpec(cfg))
		db := sql.OpenDB(connector)
		defer db.Close()
		conn1, err := db.Conn(context.Background())
		assertNilF(t, err)
		defer conn1.Close()
		runSmokeQueryWithConn(t, conn1)
		conn2, err := db.Conn(context.Background())
		assertNilF(t, err)
		defer conn2.Close()
		runSmokeQueryWithConn(t, conn2)
	})

	t.Run("first connection retrieves ID token, remaining ones wait and reuse", func(t *testing.T) {
		origSamlResponseProvider := defaultSamlResponseProvider
		defer func() { defaultSamlResponseProvider = origSamlResponseProvider }()
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &nonInteractiveSamlResponseProvider{t: t}
		}
		wiremock.registerMappings(t, newWiremockMapping("auth/external_browser/parallel_login_successful_flow.json"),
			newWiremockMapping("select1.json"),
			newWiremockMapping("close_session.json"))
		cfg := wiremock.connectionConfig()
		cfg.Authenticator = AuthTypeExternalBrowser
		cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		connector := NewConnector(SnowflakeDriver{}, *cfg)
		credentialsStorage.deleteCredential(newIDTokenSpec(cfg))
		db := sql.OpenDB(connector)
		defer db.Close()
		errs := initPoolWithSizeAndReturnErrors(db, 20)
		assertEqualE(t, len(errs), 0)
	})

	t.Run("first connection fails, second retrieves ID token, remaining ones wait and reuse", func(t *testing.T) {
		origSamlResponseProvider := defaultSamlResponseProvider
		defer func() { defaultSamlResponseProvider = origSamlResponseProvider }()
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &nonInteractiveSamlResponseProvider{t: t}
		}
		wiremock.registerMappings(t, newWiremockMapping("auth/external_browser/parallel_login_first_fails_then_successful_flow.json"),
			newWiremockMapping("select1.json"),
			newWiremockMapping("close_session.json"))
		cfg := wiremock.connectionConfig()
		cfg.Authenticator = AuthTypeExternalBrowser
		cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
		connector := NewConnector(SnowflakeDriver{}, *cfg)
		credentialsStorage.deleteCredential(newIDTokenSpec(cfg))
		db := sql.OpenDB(connector)
		defer db.Close()
		errs := initPoolWithSizeAndReturnErrors(db, 20)
		assertEqualE(t, len(errs), 1)
	})
}

func TestUnitAuthenticateWithConfigExternalBrowserWithFailedSAMLResponse(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuthSAML: postAuthSAMLError,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeExternalBrowser
	sc.cfg.ExternalBrowserTimeout = time.Duration(sfconfig.DefaultExternalBrowserTimeout)
	sc.rest = sr
	sc.ctx = context.Background()
	err = authenticateWithConfig(sc)
	assertNotNilF(t, err, "should have failed at FuncPostAuthSAML.")
	assertEqualE(t, err.Error(), "failed to get SAML response")
}

func TestUnitAuthenticateExternalBrowser(t *testing.T) {
	var err error
	sr := &snowflakeRestful{
		FuncPostAuth:  postAuthCheckExternalBrowser,
		TokenAccessor: getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeExternalBrowser
	sc.cfg.ClientStoreTemporaryCredential = ConfigBoolTrue
	sc.rest = sr
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}

	sr.FuncPostAuth = postAuthCheckExternalBrowserToken
	sc.idToken = "mockedIDToken"
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("failed to run. err: %v", err)
	}

	sr.FuncPostAuth = postAuthCheckExternalBrowserFailed
	_, err = authenticate(context.Background(), sc, []byte{}, []byte{})
	if err == nil {
		t.Fatal("should have failed")
	}
}

// To run this test you need to set environment variables in parameters.json to a user with MFA authentication enabled
// Set any other snowflake_test variables needed for database, schema, role for this user
func TestUsernamePasswordMfaCaching(t *testing.T) {
	t.Skip("manual test for MFA token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with MFA authentication
	user := os.Getenv("SNOWFLAKE_TEST_MFA_USER")
	password := os.Getenv("SNOWFLAKE_TEST_MFA_PASSWORD")
	config.User = user
	config.Password = password
	config.Authenticator = AuthTypeUsernamePasswordMFA
	if runtime.GOOS == "linux" {
		config.ClientRequestMfaToken = ConfigBoolTrue
	}
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should only be prompted to authenticate first time around.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUsernamePasswordMfaCachingWithPasscode(t *testing.T) {
	t.Skip("manual test for MFA token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with MFA authentication
	user := os.Getenv("SNOWFLAKE_TEST_MFA_USER")
	password := os.Getenv("SNOWFLAKE_TEST_MFA_PASSWORD")
	config.User = user
	config.Password = password
	config.Passcode = "" // fill with your passcode from DUO app
	config.Authenticator = AuthTypeUsernamePasswordMFA
	if runtime.GOOS == "linux" {
		config.ClientRequestMfaToken = ConfigBoolTrue
	}
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should only be prompted to authenticate first time around.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUsernamePasswordMfaCachingWithPasscodeInPassword(t *testing.T) {
	t.Skip("manual test for MFA token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with MFA authentication
	user := os.Getenv("SNOWFLAKE_TEST_MFA_USER")
	password := os.Getenv("SNOWFLAKE_TEST_MFA_PASSWORD")
	config.User = user
	config.Password = password + "" // fill with your passcode from DUO app
	config.PasscodeInPassword = true
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should only be prompted to authenticate first time around.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// To run this test you need to set environment variables in parameters.json to a user with MFA authentication enabled
// Set any other snowflake_test variables needed for database, schema, role for this user
func TestDisableUsernamePasswordMfaCaching(t *testing.T) {
	t.Skip("manual test for disabling MFA token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with MFA authentication
	user := os.Getenv("SNOWFLAKE_TEST_MFA_USER")
	password := os.Getenv("SNOWFLAKE_TEST_MFA_PASSWORD")
	config.User = user
	config.Password = password
	config.Authenticator = AuthTypeUsernamePasswordMFA
	// disable MFA token caching
	config.ClientRequestMfaToken = ConfigBoolFalse
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should be prompted to authenticate 3 times.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// To run this test you need to set SNOWFLAKE_TEST_EXT_BROWSER_USER environment variable to an external browser user
// Set any other snowflake_test variables needed for database, schema, role for this user
func TestExternalBrowserCaching(t *testing.T) {
	t.Skip("manual test for external browser token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with external browser authentication
	user := os.Getenv("SNOWFLAKE_TEST_EXT_BROWSER_USER")
	config.User = user
	config.Authenticator = AuthTypeExternalBrowser
	if runtime.GOOS == "linux" {
		config.ClientStoreTemporaryCredential = ConfigBoolTrue
	}
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should only be prompted to authenticate first time around.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

// To run this test you need to set SNOWFLAKE_TEST_EXT_BROWSER_USER environment variable to an external browser user
// Set any other snowflake_test variables needed for database, schema, role for this user
func TestDisableExternalBrowserCaching(t *testing.T) {
	t.Skip("manual test for disabling external browser token caching")

	config, err := ParseDSN(dsn)
	if err != nil {
		t.Fatal("Failed to parse dsn")
	}
	// connect with external browser authentication
	user := os.Getenv("SNOWFLAKE_TEST_EXT_BROWSER_USER")
	config.User = user
	config.Authenticator = AuthTypeExternalBrowser
	// disable external browser token caching
	config.ClientStoreTemporaryCredential = ConfigBoolFalse
	connector := NewConnector(SnowflakeDriver{}, *config)
	db := sql.OpenDB(connector)
	for range 3 {
		// should be prompted to authenticate 3 times.
		_, err := db.Query("select current_user()")
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestOktaRetryWithNewToken(t *testing.T) {
	expectedMasterToken := "m"
	expectedToken := "t"
	expectedMfaToken := "mockedMfaToken"
	expectedDatabaseName := "dbn"

	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthSAMLAuthSuccess,
		FuncPostAuthOKTA: postAuthOKTASuccess,
		FuncGetSSO:       getSSOSuccess,
		FuncPostAuth:     restfulTestWrapper{t: t}.postAuthOktaWithNewToken,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	sc := getDefaultSnowflakeConn()
	sc.cfg.Authenticator = AuthTypeOkta
	sc.cfg.OktaURL = &url.URL{
		Scheme: "https",
		Host:   "abc.com",
	}
	sc.rest = sr
	sc.ctx = context.Background()

	authResponse, err := authenticate(context.Background(), sc, []byte{0x12, 0x34}, []byte{0x56, 0x78})
	assertNilF(t, err, "should not have failed to run authenticate()")
	assertEqualF(t, authResponse.MasterToken, expectedMasterToken)
	assertEqualF(t, authResponse.Token, expectedToken)
	assertEqualF(t, authResponse.MfaToken, expectedMfaToken)
	assertEqualF(t, authResponse.SessionInfo.DatabaseName, expectedDatabaseName)
}

func TestContextPropagatedToAuthWhenUsingOpen(t *testing.T) {
	db, err := sql.Open("snowflake", dsn)
	assertNilF(t, err)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = db.QueryContext(ctx, "SELECT 1")
	assertNotNilF(t, err)
	assertStringContainsE(t, err.Error(), "context deadline exceeded")
	cancel()
}

func TestContextPropagatedToAuthWhenUsingOpenDB(t *testing.T) {
	cfg, err := ParseDSN(dsn)
	assertNilF(t, err)
	connector := NewConnector(&SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err = db.QueryContext(ctx, "SELECT 1")
	assertNotNilF(t, err)
	assertStringContainsE(t, err.Error(), "context deadline exceeded")
	cancel()
}

func TestPatSuccessfulFlow(t *testing.T) {
	cfg := wiremock.connectionConfig()
	cfg.Authenticator = AuthTypePat
	cfg.Token = "some PAT"
	wiremock.registerMappings(t,
		wiremockMapping{filePath: "auth/pat/successful_flow.json"},
		wiremockMapping{filePath: "select1.json"},
	)
	connector := NewConnector(SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)
	rows, err := db.Query("SELECT 1")
	assertNilF(t, err)
	var v int
	assertTrueE(t, rows.Next())
	assertNilF(t, rows.Scan(&v))
	assertEqualE(t, v, 1)
}

func TestPatTokenRotation(t *testing.T) {
	dir := t.TempDir()
	tokenFilePath := filepath.Join(dir, "tokenFile")
	assertNilF(t, os.WriteFile(tokenFilePath, []byte("some PAT"), 0644))

	cfg := wiremock.connectionConfig()
	cfg.Authenticator = AuthTypePat
	cfg.TokenFilePath = tokenFilePath
	wiremock.registerMappings(t,
		wiremockMapping{filePath: "auth/pat/reading_fresh_token.json"},
	)
	connector := NewConnector(SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)
	_, err := db.Conn(context.Background())
	assertNilF(t, err)

	assertNilF(t, os.WriteFile(tokenFilePath, []byte("some PAT 2"), 0644))
	_, err = db.Conn(context.Background())
	assertNilF(t, err)
}

func TestPatInvalidToken(t *testing.T) {
	wiremock.registerMappings(t,
		wiremockMapping{filePath: "auth/pat/invalid_token.json"},
	)
	cfg := wiremock.connectionConfig()
	cfg.Authenticator = AuthTypePat
	cfg.Token = "some PAT"
	connector := NewConnector(SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)
	_, err := db.Query("SELECT 1")
	assertNotNilF(t, err)
	var se *SnowflakeError
	assertErrorsAsF(t, err, &se)
	assertEqualE(t, se.Number, 394400)
	assertEqualE(t, se.Message, "Programmatic access token is invalid.")
}

func TestWithOauthAuthorizationCodeFlowManual(t *testing.T) {
	t.Skip("manual test")
	for _, provider := range []string{"OKTA", "SNOWFLAKE"} {
		t.Run(provider, func(t *testing.T) {
			cfg, err := GetConfigFromEnv([]*ConfigParam{
				{Name: "OAuthClientId", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_CLIENT_ID", FailOnMissing: true},
				{Name: "OAuthClientSecret", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_CLIENT_SECRET", FailOnMissing: true},
				{Name: "OAuthAuthorizationURL", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_AUTHORIZATION_URL", FailOnMissing: false},
				{Name: "OAuthTokenRequestURL", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_TOKEN_REQUEST_URL", FailOnMissing: false},
				{Name: "OAuthRedirectURI", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_REDIRECT_URI", FailOnMissing: false},
				{Name: "OAuthScope", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_SCOPE", FailOnMissing: false},
				{Name: "User", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_USER", FailOnMissing: true},
				{Name: "Role", EnvName: "SNOWFLAKE_TEST_OAUTH_" + provider + "_ROLE", FailOnMissing: true},
				{Name: "Account", EnvName: "SNOWFLAKE_TEST_ACCOUNT", FailOnMissing: true},
			})
			assertNilF(t, err)
			cfg.Authenticator = AuthTypeOAuthAuthorizationCode
			credentialsStorage.deleteCredential(newOAuthAccessTokenSpec(cfg))
			credentialsStorage.deleteCredential(newOAuthRefreshTokenSpec(cfg))
			connector := NewConnector(&SnowflakeDriver{}, *cfg)
			db := sql.OpenDB(connector)
			defer db.Close()
			conn1, err := db.Conn(context.Background())
			assertNilF(t, err)
			defer conn1.Close()
			runSmokeQueryWithConn(t, conn1)
			conn2, err := db.Conn(context.Background())
			assertNilF(t, err)
			defer conn2.Close()
			runSmokeQueryWithConn(t, conn2)
			credentialsStorage.setCredential(newOAuthAccessTokenSpec(cfg), "expired-token")
			conn3, err := db.Conn(context.Background())
			assertNilF(t, err)
			defer conn3.Close()
			runSmokeQueryWithConn(t, conn3)
		})
	}
}

func TestWithOAuthClientCredentialsFlowManual(t *testing.T) {
	t.Skip("manual test")
	cfg, err := GetConfigFromEnv([]*ConfigParam{
		{Name: "OAuthClientId", EnvName: "SNOWFLAKE_TEST_OAUTH_OKTA_CLIENT_ID", FailOnMissing: true},
		{Name: "OAuthClientSecret", EnvName: "SNOWFLAKE_TEST_OAUTH_OKTA_CLIENT_SECRET", FailOnMissing: true},
		{Name: "OAuthTokenRequestURL", EnvName: "SNOWFLAKE_TEST_OAUTH_OKTA_TOKEN_REQUEST_URL", FailOnMissing: true},
		{Name: "Role", EnvName: "SNOWFLAKE_TEST_OAUTH_OKTA_ROLE", FailOnMissing: true},
		{Name: "Account", EnvName: "SNOWFLAKE_TEST_ACCOUNT", FailOnMissing: true},
	})
	assertNilF(t, err)
	cfg.Authenticator = AuthTypeOAuthClientCredentials
	connector := NewConnector(&SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)
	defer db.Close()
	runSmokeQuery(t, db)
}

// ============================================================================
// dbt-only tests: not upstream.
//
// Ported from dbt fork commit 8cfa350 "Fix 404 when an account has .<region>".
// ============================================================================

// parseAccount must strip the region subdomain from the account identifier before
// it goes into the login request body.
//
// Why this is still needed on top of upstream's normalization: ParseDSN strips
// everything after the first dot (internal/config/dsn.go), and
// FillMissingConfigParameters strips the "-<external_id>" suffix for .global
// hosts -- but only ParseDSN does the dot. The database/sql Connector path
// (connector.go Connect) calls FillMissingConfigParameters alone, so a Config
// constructed in code, as arrow-adbc does, never gets the dot stripped.
func TestParseAccount(t *testing.T) {
	testcases := []struct {
		name     string
		account  string
		expected string
	}{
		{
			name:     "bare account is returned unchanged",
			account:  "myacct",
			expected: "myacct",
		},
		{
			name:     "region subdomain is removed",
			account:  "myacct.us-east-1",
			expected: "myacct",
		},
		{
			name:     "global locator drops the external id after the last dash",
			account:  "myacct-123abc.global",
			expected: "myacct",
		},
		{
			// The Python reference slices head[:rfind("-")] without guarding the
			// -1 sentinel, which silently drops the last character ("myacc").
			// Returning the head unchanged is correct.
			name:     "global locator with no external id keeps the whole account",
			account:  "myacct.global",
			expected: "myacct",
		},
		{
			// A dash outside a .global account is part of the account name and
			// must survive.
			name:     "dash is preserved when the locator is not global",
			account:  "my-acct.us-east-1",
			expected: "my-acct",
		},
		{
			name:     "dash with no dot at all is preserved",
			account:  "my-acct",
			expected: "my-acct",
		},
		{
			name:     "only the first segment is kept when several dots are present",
			account:  "myacct.us-east-1.aws",
			expected: "myacct",
		},
		{
			name:     "empty account is returned unchanged",
			account:  "",
			expected: "",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, parseAccount(tc.account), tc.expected)
		})
	}
}

// Credential-cache write guards, extracted from authenticate() so they are
// reachable without driving that whole function. Ported from dbt fork commits
// e2a04f6 "Ensure all operating systems use externalbrowser. Protect IDToken."
// and 268d1bb "Restore MFA caching behavior."
func TestShouldCacheMfaToken(t *testing.T) {
	testcases := []struct {
		name              string
		authenticator     AuthType
		sessionParameters map[string]any
		expected          bool
	}{
		{
			name:              "username-password-mfa with the session parameter set",
			authenticator:     AuthTypeUsernamePasswordMFA,
			sessionParameters: map[string]any{clientRequestMfaToken: true},
			expected:          true,
		},
		{
			name:              "username-password-mfa without the session parameter",
			authenticator:     AuthTypeUsernamePasswordMFA,
			sessionParameters: map[string]any{},
			expected:          false,
		},
		{
			// ClientRequestMfaToken is settable on any authenticator; only the MFA
			// flow owns this cache slot.
			name:              "plain snowflake auth may not write the mfa slot",
			authenticator:     AuthTypeSnowflake,
			sessionParameters: map[string]any{clientRequestMfaToken: true},
			expected:          false,
		},
		{
			name:              "external browser may not write the mfa slot",
			authenticator:     AuthTypeExternalBrowser,
			sessionParameters: map[string]any{clientRequestMfaToken: true},
			expected:          false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, shouldCacheMfaToken(tc.authenticator, tc.sessionParameters), tc.expected)
		})
	}
}

func TestShouldCacheIDToken(t *testing.T) {
	testcases := []struct {
		name              string
		authenticator     AuthType
		sessionParameters map[string]any
		idToken           string
		expected          bool
	}{
		{
			name:              "external browser with a token",
			authenticator:     AuthTypeExternalBrowser,
			sessionParameters: map[string]any{clientStoreTemporaryCredential: true},
			idToken:           "id-token",
			expected:          true,
		},
		{
			// The regression this guard exists for: a successful login that
			// reports no ID token must not evict a good cached one.
			name:              "external browser with an empty token",
			authenticator:     AuthTypeExternalBrowser,
			sessionParameters: map[string]any{clientStoreTemporaryCredential: true},
			idToken:           "",
			expected:          false,
		},
		{
			name:              "external browser with temporary credentials disabled",
			authenticator:     AuthTypeExternalBrowser,
			sessionParameters: map[string]any{},
			idToken:           "id-token",
			expected:          false,
		},
		{
			// clientStoreTemporaryCredential is enabled for both OAuth flows too,
			// so without the authenticator check an OAuth login would clobber the
			// browser flow's cached ID token.
			name:              "oauth authorization code may not write the id token slot",
			authenticator:     AuthTypeOAuthAuthorizationCode,
			sessionParameters: map[string]any{clientStoreTemporaryCredential: true},
			idToken:           "id-token",
			expected:          false,
		},
		{
			name:              "oauth client credentials may not write the id token slot",
			authenticator:     AuthTypeOAuthClientCredentials,
			sessionParameters: map[string]any{clientStoreTemporaryCredential: true},
			idToken:           "id-token",
			expected:          false,
		},
		{
			name:              "username-password-mfa may not write the id token slot",
			authenticator:     AuthTypeUsernamePasswordMFA,
			sessionParameters: map[string]any{clientStoreTemporaryCredential: true},
			idToken:           "id-token",
			expected:          false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, shouldCacheIDToken(tc.authenticator, tc.sessionParameters, tc.idToken), tc.expected)
		})
	}
}

// External-browser failure backoff (dbt-only). Ported from fork commit 7d40694
// "Less tab storms through smarter failures". Not yet wired into
// authenticateWithConfig; that is a separate change.

func TestNormalizeHost(t *testing.T) {
	testcases := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "bare host is unchanged",
			host:     "abc.snowflakecomputing.com",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "host is lowercased",
			host:     "ABC.SnowflakeComputing.COM",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "port is stripped",
			host:     "abc.snowflakecomputing.com:443",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "https scheme is stripped",
			host:     "https://abc.snowflakecomputing.com",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "http scheme and port are both stripped",
			host:     "http://abc.snowflakecomputing.com:443",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "path after the host is discarded",
			host:     "https://ABC.snowflakecomputing.com:443/some/path",
			expected: "abc.snowflakecomputing.com",
		},
		{
			name:     "empty host is unchanged",
			host:     "",
			expected: "",
		},
		{
			name:     "ipv6 literal with a port",
			host:     "[::1]:443",
			expected: "::1",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, normalizeHost(tc.host), tc.expected)
		})
	}
}

// The backoff must not be evadable by spelling the same account or user
// differently.
func TestExtBrowserBackoffKey(t *testing.T) {
	t.Run("equivalent spellings collapse to one key", func(t *testing.T) {
		canonical := extBrowserBackoffKey("abc.snowflakecomputing.com", "USER")
		for _, variant := range []struct {
			host string
			user string
		}{
			{"ABC.snowflakecomputing.com", "USER"},
			{"abc.snowflakecomputing.com:443", "USER"},
			{"https://abc.snowflakecomputing.com", "USER"},
			{"https://ABC.snowflakecomputing.com:443", "user"},
			{"abc.snowflakecomputing.com", "User"},
		} {
			assertEqualE(t, extBrowserBackoffKey(variant.host, variant.user), canonical,
				"host "+variant.host+" user "+variant.user+" should share the canonical key")
		}
	})

	t.Run("different principals get different keys", func(t *testing.T) {
		base := extBrowserBackoffKey("abc.snowflakecomputing.com", "user")
		assertNotEqualE(t, extBrowserBackoffKey("xyz.snowflakecomputing.com", "user"), base,
			"a different host must not share a backoff window")
		assertNotEqualE(t, extBrowserBackoffKey("abc.snowflakecomputing.com", "other"), base,
			"a different user must not share a backoff window")
	})
}

func TestExtBrowserBackoffLifecycle(t *testing.T) {
	now := time.Now()

	t.Run("no entry means not backed off", func(t *testing.T) {
		key := extBrowserBackoffKey("fresh."+t.Name(), "u")
		assertFalseE(t, extBrowserBackoffActive(key, now))
	})

	t.Run("a recorded failure refuses within the window", func(t *testing.T) {
		key := extBrowserBackoffKey("recorded."+t.Name(), "u")
		defer clearExtBrowserFailure(key)

		recordExtBrowserFailure(key, now)
		assertTrueE(t, extBrowserBackoffActive(key, now), "should refuse immediately after the failure")
		assertTrueE(t, extBrowserBackoffActive(key, now.Add(extBrowserBackoffWindow-time.Second)),
			"should still refuse just before the window closes")
	})

	t.Run("the refusal lapses once the window closes", func(t *testing.T) {
		key := extBrowserBackoffKey("lapsed."+t.Name(), "u")
		defer clearExtBrowserFailure(key)

		recordExtBrowserFailure(key, now)
		assertFalseE(t, extBrowserBackoffActive(key, now.Add(extBrowserBackoffWindow)),
			"should allow once the window has elapsed")
	})

	t.Run("an expired entry is pruned when it is checked", func(t *testing.T) {
		key := extBrowserBackoffKey("pruned."+t.Name(), "u")
		defer clearExtBrowserFailure(key)

		recordExtBrowserFailure(key, now)
		_, present := lastFail.Load(key)
		assertTrueE(t, present, "entry should exist before it is checked")

		extBrowserBackoffActive(key, now.Add(2*extBrowserBackoffWindow))
		_, present = lastFail.Load(key)
		assertFalseE(t, present, "checking an expired entry should remove it")
	})

	t.Run("a success clears the refusal immediately", func(t *testing.T) {
		key := extBrowserBackoffKey("cleared."+t.Name(), "u")
		defer clearExtBrowserFailure(key)

		recordExtBrowserFailure(key, now)
		clearExtBrowserFailure(key)
		assertFalseE(t, extBrowserBackoffActive(key, now), "a cleared key must not refuse")
	})

	t.Run("a refusal is scoped to its own key", func(t *testing.T) {
		failing := extBrowserBackoffKey("scoped-failing."+t.Name(), "u")
		other := extBrowserBackoffKey("scoped-other."+t.Name(), "u")
		defer clearExtBrowserFailure(failing)

		recordExtBrowserFailure(failing, now)
		assertFalseE(t, extBrowserBackoffActive(other, now), "an unrelated key must be unaffected")
	})
}

// Ported from dbt fork commit 144d002, restructured: the fork chains this into the
// OAuth refresh branch with fallthrough, which skips that branch's guard.
func TestShouldRetryWithFreshExternalBrowserLogin(t *testing.T) {
	testcases := []struct {
		name          string
		authenticator AuthType
		cachedIDToken string
		expected      bool
	}{
		{
			name:          "external browser that presented a cached token",
			authenticator: AuthTypeExternalBrowser,
			cachedIDToken: "stale-id-token",
			expected:      true,
		},
		{
			name:          "external browser with no cached token",
			authenticator: AuthTypeExternalBrowser,
			cachedIDToken: "",
			expected:      false,
		},
		{
			name:          "oauth authorization code is handled by the refresh path",
			authenticator: AuthTypeOAuthAuthorizationCode,
			cachedIDToken: "stale-id-token",
			expected:      false,
		},
		{
			name:          "username-password-mfa never opens a browser",
			authenticator: AuthTypeUsernamePasswordMFA,
			cachedIDToken: "stale-id-token",
			expected:      false,
		},
		{
			name:          "plain snowflake auth never opens a browser",
			authenticator: AuthTypeSnowflake,
			cachedIDToken: "stale-id-token",
			expected:      false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, shouldRetryWithFreshExternalBrowserLogin(tc.authenticator, tc.cachedIDToken), tc.expected)
		})
	}
}

func TestIsOAuthRefreshable(t *testing.T) {
	testcases := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "missing access token but refresh token present",
			err:      &SnowflakeError{Number: ErrMissingAccessATokenButRefreshTokenPresent},
			expected: true,
		},
		{
			name:     "invalid oauth access token",
			err:      &SnowflakeError{Number: 390303},
			expected: true,
		},
		{
			name:     "expired oauth access token",
			err:      &SnowflakeError{Number: 390318},
			expected: true,
		},
		{
			name:     "wrapped refreshable error",
			err:      fmt.Errorf("login failed: %w", &SnowflakeError{Number: 390318}),
			expected: true,
		},
		{
			name:     "unrelated snowflake error",
			err:      &SnowflakeError{Number: ErrCodeFailedToConnect},
			expected: false,
		},
		{
			name:     "plain error",
			err:      errors.New("boom"),
			expected: false,
		},
		{
			name:     "context cancelled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			assertEqualE(t, isOAuthRefreshable(tc.err), tc.expected)
		})
	}
}
