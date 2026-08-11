package gosnowflake

import (
	"context"
	"errors"
	"fmt"
	sfconfig "github.com/snowflakedb/gosnowflake/v2/internal/config"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGetTokenFromResponseFail(t *testing.T) {
	response := "GET /?fakeToken=fakeEncodedSamlToken HTTP/1.1\r\n" +
		"Host: localhost:54001\r\n" +
		"Connection: keep-alive\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: userAgentStr\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n" +
		"Referer: https://myaccount.snowflakecomputing.com/fed/login\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n\r\n"

	_, err := getTokenFromResponse(response)
	if err == nil {
		t.Errorf("Should have failed parsing the malformed response.")
	}
}

func TestGetTokenFromResponse(t *testing.T) {
	response := "GET /?token=GETtokenFromResponse HTTP/1.1\r\n" +
		"Host: localhost:54001\r\n" +
		"Connection: keep-alive\r\n" +
		"Upgrade-Insecure-Requests: 1\r\n" +
		"User-Agent: userAgentStr\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\n" +
		"Referer: https://myaccount.snowflakecomputing.com/fed/login\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n\r\n"

	expected := "GETtokenFromResponse"

	token, err := getTokenFromResponse(response)
	if err != nil {
		t.Errorf("Failed to get the token. Err: %#v", err)
	}
	if token != expected {
		t.Errorf("Expected: %s, found: %s", expected, token)
	}
}

func TestBuildResponse(t *testing.T) {
	resp, err := buildResponse(fmt.Sprintf(samlSuccessHTML, "Go"))
	assertNilF(t, err)
	bytes := resp.Bytes()
	respStr := string(bytes[:])
	if !strings.Contains(respStr, "Your identity was confirmed and propagated to Snowflake Go.\nYou can close this window now and go back where you started from.") {
		t.Fatalf("failed to build response")
	}
}

func postAuthExternalBrowserError(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{}, errors.New("failed to get SAML response")
}

func postAuthExternalBrowserErrorDelayed(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	time.Sleep(2 * time.Second)
	return &authResponse{}, errors.New("failed to get SAML response")
}

func postAuthExternalBrowserFail(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Message: "external browser auth failed",
	}, nil
}

func postAuthExternalBrowserFailWithCode(_ context.Context, _ *snowflakeRestful, _ map[string]string, _ []byte, _ time.Duration) (*authResponse, error) {
	return &authResponse{
		Success: false,
		Message: "failed to connect to db",
		Code:    "260008",
	}, nil
}

func TestUnitAuthenticateByExternalBrowser(t *testing.T) {
	authenticator := "externalbrowser"
	application := "testapp"
	account := "testaccount"
	user := "u"
	timeout := sfconfig.DefaultExternalBrowserTimeout
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthExternalBrowserError,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	_, _, err := authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	sr.FuncPostAuthSAML = postAuthExternalBrowserFail
	_, _, err = authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	sr.FuncPostAuthSAML = postAuthExternalBrowserFailWithCode
	_, _, err = authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	if err == nil {
		t.Fatal("should have failed.")
	}
	driverErr, ok := err.(*SnowflakeError)
	if !ok {
		t.Fatalf("should be snowflake error. err: %v", err)
	}
	if driverErr.Number != ErrCodeFailedToConnect {
		t.Fatalf("unexpected error code. expected: %v, got: %v", ErrCodeFailedToConnect, driverErr.Number)
	}
}

func TestAuthenticationTimeout(t *testing.T) {
	authenticator := "externalbrowser"
	application := "testapp"
	account := "testaccount"
	user := "u"
	timeout := 1 * time.Second
	sr := &snowflakeRestful{
		Protocol:         "https",
		Host:             "abc.com",
		Port:             443,
		FuncPostAuthSAML: postAuthExternalBrowserErrorDelayed,
		TokenAccessor:    getSimpleTokenAccessor(),
	}
	_, _, err := authenticateByExternalBrowser(context.Background(), sr, authenticator, application, account, user, timeout, ConfigBoolTrue)
	assertEqualE(t, err.Error(), "authentication timed out", err.Error())
}

func Test_createLocalTCPListener(t *testing.T) {
	listener, err := createLocalTCPListener(context.Background(), 0)
	if err != nil {
		t.Fatalf("createLocalTCPListener() failed: %v", err)
	}
	if listener == nil {
		t.Fatal("createLocalTCPListener() returned nil listener")
	}

	// Close the listener after the test.
	defer listener.Close()
}

func TestUnitGetLoginURL(t *testing.T) {
	expectedScheme := "https"
	expectedHost := "abc.com:443"
	user := "u"
	callbackPort := 123
	sr := &snowflakeRestful{
		Protocol:      "https",
		Host:          "abc.com",
		Port:          443,
		TokenAccessor: getSimpleTokenAccessor(),
	}

	loginURL, proofKey, err := getLoginURL(sr, user, callbackPort)
	assertNilF(t, err, "failed to get login URL")
	assertNotNilF(t, len(proofKey), "proofKey should be non-empty string")

	urlPtr, err := url.Parse(loginURL)
	assertNilF(t, err, "failed to parse the login URL")
	assertEqualF(t, urlPtr.Scheme, expectedScheme)
	assertEqualF(t, urlPtr.Host, expectedHost)
	assertEqualF(t, urlPtr.Path, consoleLoginRequestPath)
	assertStringContainsF(t, urlPtr.RawQuery, "login_name")
	assertStringContainsF(t, urlPtr.RawQuery, "browser_mode_redirect_port")
	assertStringContainsF(t, urlPtr.RawQuery, "proof_key")
}

type nonInteractiveSamlResponseProvider struct {
	t *testing.T
}

func (provider *nonInteractiveSamlResponseProvider) run(url string) (string, error) {
	go func() {
		resp, err := http.Get(url)
		assertNilF(provider.t, err)
		assertEqualE(provider.t, resp.StatusCode, http.StatusOK)
	}()
	// Empty token: this provider exercises the automatic path, where the SAML
	// response arrives on the local listener.
	return "", nil
}

// ============================================================================
// dbt-only tests: not upstream.
//
// These pin the behavior of the manual-token fallback for external-browser
// authentication, contributed by the dbt fork in:
//
//   f935821  "Token by browser and by return url with token."
//   72d0aa3  "use builtins to do the pasting in non-cannonical mode"
//   d7e3298  "Relegate prefunctory browser auth output to logging."
//
// Motivation: upstream fails the entire login when no browser can be opened,
// which makes external-browser auth unusable from headless shells, remote
// containers and CI-like environments. The fallback prints the login URL and
// accepts the post-login redirect URL pasted by the user instead.
// ============================================================================

func TestExtractToken(t *testing.T) {
	testcases := []struct {
		name     string
		input    string
		expected string
		found    bool
	}{
		{
			name:     "redirect URL with token",
			input:    "http://localhost:1234/?token=abc123",
			expected: "abc123",
			found:    true,
		},
		{
			name:     "token alongside other query parameters",
			input:    "http://localhost:1234/?foo=bar&token=abc123&baz=qux",
			expected: "abc123",
			found:    true,
		},
		{
			// url.Parse unescapes query values, so a percent-encoded token is
			// returned decoded. The caller must not double-unescape it.
			name:     "percent-encoded token is decoded once",
			input:    "http://localhost:1234/?token=a%2Bb%3Dc",
			expected: "a+b=c",
			found:    true,
		},
		{
			name:     "no token parameter",
			input:    "http://localhost:1234/?foo=bar",
			expected: "",
			found:    false,
		},
		{
			// A present-but-empty token must not be accepted: the prompt loop
			// relies on found==false to re-ask rather than proceed with "".
			name:     "empty token value is not a match",
			input:    "http://localhost:1234/?token=",
			expected: "",
			found:    false,
		},
		{
			name:     "unparseable input",
			input:    "://not a url",
			expected: "",
			found:    false,
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
			found:    false,
		},
		{
			// Query-parameter names are case-sensitive; "Token" is not "token".
			name:     "token parameter name is case sensitive",
			input:    "http://localhost:1234/?Token=abc123",
			expected: "",
			found:    false,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			token, ok := extractToken(tc.input)
			assertEqualE(t, ok, tc.found, "unexpected found value")
			assertEqualE(t, token, tc.expected, "unexpected token value")
		})
	}
}

// manualTokenSamlResponseProvider simulates a provider that could not open a
// browser and obtained the token by asking the user to paste the redirect URL.
type manualTokenSamlResponseProvider struct {
	token string
	err   error
}

func (p *manualTokenSamlResponseProvider) run(_ string) (string, error) {
	return p.token, p.err
}

// When the provider returns a token, doAuthenticateByExternalBrowser must not
// wait on the local listener -- no callback will ever arrive -- and must return
// the unescaped token as the SAML response.
func TestDoAuthenticateByExternalBrowserManualToken(t *testing.T) {
	origProvider := defaultSamlResponseProvider
	defer func() { defaultSamlResponseProvider = origProvider }()

	t.Run("returns pasted token without awaiting a callback", func(t *testing.T) {
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &manualTokenSamlResponseProvider{token: "pasted-saml-response"}
		}

		sr := &snowflakeRestful{
			Protocol:      "https",
			Host:          "abc.com",
			Port:          443,
			TokenAccessor: getSimpleTokenAccessor(),
		}

		done := make(chan authenticateByExternalBrowserResult, 1)
		go func() {
			done <- doAuthenticateByExternalBrowser(
				context.Background(), sr, "EXTERNALBROWSER", "testapp", "testaccount", "u", ConfigBoolFalse)
		}()

		select {
		case result := <-done:
			assertNilF(t, result.err, "manual token flow should not error")
			assertEqualE(t, string(result.escapedSamlResponse), "pasted-saml-response")
			assertNotNilF(t, len(result.proofKey), "proofKey should be non-empty")
		case <-time.After(10 * time.Second):
			t.Fatal("manual token flow blocked; it must not wait on the TCP listener")
		}
	})

	t.Run("unescapes the pasted token", func(t *testing.T) {
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &manualTokenSamlResponseProvider{token: "a%2Bb"}
		}

		sr := &snowflakeRestful{
			Protocol:      "https",
			Host:          "abc.com",
			Port:          443,
			TokenAccessor: getSimpleTokenAccessor(),
		}

		result := doAuthenticateByExternalBrowser(
			context.Background(), sr, "EXTERNALBROWSER", "testapp", "testaccount", "u", ConfigBoolFalse)
		assertNilF(t, result.err, "manual token flow should not error")
		assertEqualE(t, string(result.escapedSamlResponse), "a+b")
	})

	t.Run("propagates a provider error", func(t *testing.T) {
		defaultSamlResponseProvider = func() samlResponseProvider {
			return &manualTokenSamlResponseProvider{err: errors.New("no browser and no tty")}
		}

		sr := &snowflakeRestful{
			Protocol:      "https",
			Host:          "abc.com",
			Port:          443,
			TokenAccessor: getSimpleTokenAccessor(),
		}

		result := doAuthenticateByExternalBrowser(
			context.Background(), sr, "EXTERNALBROWSER", "testapp", "testaccount", "u", ConfigBoolFalse)
		assertNotNilF(t, result.err, "provider error should propagate")
		assertEqualE(t, result.err.Error(), "no browser and no tty")
	})
}
