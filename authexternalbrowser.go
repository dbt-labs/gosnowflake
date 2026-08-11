package gosnowflake

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	errors2 "github.com/snowflakedb/gosnowflake/v2/internal/errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/browser"
	"golang.org/x/term"
)

const (
	samlSuccessHTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>SAML Response for Snowflake</title></head>
<body>
Your identity was confirmed and propagated to Snowflake %v.
You can close this window now and go back where you started from.
</body></html>`

	bufSize = 8192
)

// Builds a response to show to the user after successfully
// getting a response from Snowflake.
func buildResponse(body string) (bytes.Buffer, error) {
	t := &http.Response{
		Status:        "200 OK",
		StatusCode:    200,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Body:          io.NopCloser(bytes.NewBufferString(body)),
		ContentLength: int64(len(body)),
		Request:       nil,
		Header:        make(http.Header),
	}
	var b bytes.Buffer
	err := t.Write(&b)
	return b, err
}

// This opens a socket that listens on all available unicast
// and any anycast IP addresses locally. By specifying "0", we are
// able to bind to a free port. Specifying a fixed port may cause a race condition.
//
// dbt-only deviation: binds through net.ListenConfig so that both binds observe
// context cancellation, rather than net.Listen which ignores it.
func createLocalTCPListener(ctx context.Context, port int) (*net.TCPListener, error) {
	logger.Debugf("creating local TCP listener on port %v", port)

	var lc net.ListenConfig
	allAddressesListener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%v", port))
	if err != nil {
		logger.Warnf("unable to bind to 0.0.0.0:%v — possible permission or firewall issue: %v", port, err)
		return nil, err
	}
	logger.Debugf("successfully bound to 0.0.0.0:%v; closing test listener", port)
	if err := allAddressesListener.Close(); err != nil {
		logger.Errorf("error while closing TCP listener. %v", err)
		return nil, err
	}

	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf("localhost:%v", port))
	if err != nil {
		logger.Warnf("error while setting up listener, unable to bind to localhost:%v: %v", port, err)
		return nil, err
	}

	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("failed to assert type as *net.TCPListener")
	}

	return tcpListener, nil
}

// Opens a browser window (or new tab) with the configured login Url.
// This can / will fail if running inside a shell with no display, ie
// ssh'ing into a box attempting to authenticate via external browser.
func openBrowser(browserURL string) error {
	parsedURL, err := url.ParseRequestURI(browserURL)
	if err != nil {
		logger.Errorf("error parsing url %v, err: %v", browserURL, err)
		return err
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("invalid browser URL: %v", browserURL)
	}
	err = browser.OpenURL(browserURL)
	if err != nil {
		logger.Errorf("failed to open a browser. err: %v", err)
		return err
	}
	return nil
}

// Gets the IDP Url and Proof Key from Snowflake.
// Note: FuncPostAuthSaml will return a fully qualified error if
// there is something wrong getting data from Snowflake.
func getIdpURLProofKey(
	ctx context.Context,
	sr *snowflakeRestful,
	authenticator string,
	application string,
	account string,
	user string,
	callbackPort int) (string, string, error) {

	headers := make(map[string]string)
	headers[httpHeaderContentType] = headerContentTypeApplicationJSON
	headers[httpHeaderAccept] = headerContentTypeApplicationJSON
	headers[httpHeaderUserAgent] = userAgent

	clientEnvironment := newAuthRequestClientEnvironment()
	clientEnvironment.Application = application

	requestMain := authRequestData{
		ClientAppID:             clientType,
		ClientAppVersion:        SnowflakeGoDriverVersion,
		AccountName:             account,
		LoginName:               user,
		ClientEnvironment:       clientEnvironment,
		Authenticator:           authenticator,
		BrowserModeRedirectPort: strconv.Itoa(callbackPort),
	}

	authRequest := authRequest{
		Data: requestMain,
	}

	jsonBody, err := json.Marshal(authRequest)
	if err != nil {
		logger.WithContext(ctx).Errorf("failed to serialize json. err: %v", err)
		return "", "", err
	}

	respd, err := sr.FuncPostAuthSAML(ctx, sr, headers, jsonBody, sr.LoginTimeout)
	if err != nil {
		return "", "", err
	}
	if !respd.Success {
		logger.WithContext(ctx).Error("Authentication FAILED")
		sr.TokenAccessor.SetTokens("", "", -1)
		code, err := strconv.Atoi(respd.Code)
		if err != nil {
			return "", "", err
		}
		return "", "", &SnowflakeError{
			Number:   code,
			SQLState: SQLStateConnectionRejected,
			Message:  respd.Message,
		}
	}
	return respd.Data.SSOURL, respd.Data.ProofKey, nil
}

// Gets the login URL for multiple SAML
func getLoginURL(sr *snowflakeRestful, user string, callbackPort int) (string, string, error) {
	proofKey := generateProofKey()

	params := &url.Values{}
	params.Add("login_name", user)
	params.Add("browser_mode_redirect_port", strconv.Itoa(callbackPort))
	params.Add("proof_key", proofKey)
	url := sr.getFullURL(consoleLoginRequestPath, params)

	return url.String(), proofKey, nil
}

func generateProofKey() string {
	randomness := getSecureRandom(32)
	return base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(randomness)
}

// The response returned from Snowflake looks like so:
// GET /?token=encodedSamlToken
// Host: localhost:54001
// Connection: keep-alive
// Upgrade-Insecure-Requests: 1
// User-Agent: userAgentStr
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
// Referer: https://myaccount.snowflakecomputing.com/fed/login
// Accept-Encoding: gzip, deflate, br
// Accept-Language: en-US,en;q=0.9
// This extracts the token portion of the response.
func getTokenFromResponse(response string) (string, error) {
	start := "GET /?token="
	arr := strings.Split(response, "\r\n")
	if !strings.HasPrefix(arr[0], start) {
		logger.Errorf("response is malformed. ")
		return "", &SnowflakeError{
			Number:      ErrFailedToParseResponse,
			SQLState:    SQLStateConnectionRejected,
			Message:     errors2.ErrMsgFailedToParseResponse,
			MessageArgs: []any{response},
		}
	}
	token := strings.TrimPrefix(arr[0], start)
	token = strings.Split(token, " ")[0]
	return token, nil
}

type authenticateByExternalBrowserResult struct {
	escapedSamlResponse []byte
	proofKey            []byte
	err                 error
}

func authenticateByExternalBrowser(ctx context.Context, sr *snowflakeRestful, authenticator string, application string,
	account string, user string, externalBrowserTimeout time.Duration, disableConsoleLogin ConfigBool) ([]byte, []byte, error) {
	resultChan := make(chan authenticateByExternalBrowserResult, 1)
	go GoroutineWrapper(
		ctx,
		func() {
			resultChan <- doAuthenticateByExternalBrowser(ctx, sr, authenticator, application, account, user, disableConsoleLogin)
		},
	)
	select {
	case <-time.After(externalBrowserTimeout):
		return nil, nil, errors.New("authentication timed out")
	case result := <-resultChan:
		return result.escapedSamlResponse, result.proofKey, result.err
	}
}

// Authentication by an external browser takes place via the following:
//   - the golang snowflake driver communicates to Snowflake that the user wishes to
//     authenticate via external browser
//   - snowflake sends back the IDP Url configured at the Snowflake side for the
//     provided account, or use the multiple SAML way via console login
//   - the default browser is opened to that URL
//   - user authenticates at the IDP, and is redirected to Snowflake
//   - Snowflake directs the user back to the driver
//   - authenticate is complete!
func doAuthenticateByExternalBrowser(ctx context.Context, sr *snowflakeRestful, authenticator string, application string, account string, user string, disableConsoleLogin ConfigBool) authenticateByExternalBrowserResult {
	l, err := createLocalTCPListener(ctx, 0)
	if err != nil {
		return authenticateByExternalBrowserResult{nil, nil, err}
	}
	defer func() {
		// The manual-paste path closes the listener early; a second close is
		// expected there and is not an error worth reporting.
		if err = l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Errorf("error while closing TCP listener for external browser (%v). %v", l.Addr().String(), err)
		}
	}()

	callbackPort := l.Addr().(*net.TCPAddr).Port

	var loginURL string
	var proofKey string
	if disableConsoleLogin == ConfigBoolTrue {
		// Gets the IDP URL and Proof Key from Snowflake
		loginURL, proofKey, err = getIdpURLProofKey(ctx, sr, authenticator, application, account, user, callbackPort)
	} else {
		// Multiple SAML way to do authentication via console login
		loginURL, proofKey, err = getLoginURL(sr, user, callbackPort)
	}

	if err != nil {
		return authenticateByExternalBrowserResult{nil, nil, err}
	}

	// A non-empty token means the provider could not reach the browser and
	// fell back to having the user paste the redirect URL; no callback will
	// ever arrive on the listener in that case.
	manualToken, err := defaultSamlResponseProvider().run(loginURL)
	if err != nil {
		return authenticateByExternalBrowserResult{nil, nil, err}
	}
	if manualToken != "" {
		// Close early so Snowflake cannot connect to a listener nobody reads.
		if err := l.Close(); err != nil {
			logger.WithContext(ctx).Warnf("error while closing unused TCP listener. %v", err)
		}
		unescaped, err := url.QueryUnescape(manualToken)
		if err != nil {
			logger.WithContext(ctx).Errorf("unable to unescape pasted saml response. err: %v", err)
			return authenticateByExternalBrowserResult{nil, nil, err}
		}
		return authenticateByExternalBrowserResult{[]byte(unescaped), []byte(proofKey), nil}
	}

	encodedSamlResponseChan := make(chan string)
	errChan := make(chan error)

	var encodedSamlResponse string
	var errFromGoroutine error
	conn, err := l.Accept()
	if err != nil {
		// dbt-only: upstream calls log.Fatal here, terminating the host process
		// from inside a library.
		logger.WithContext(ctx).Errorf("unable to accept connection. err: %v", err)
		return authenticateByExternalBrowserResult{nil, nil, err}
	}
	go func(c net.Conn) {
		var buf bytes.Buffer
		total := 0
		encodedSamlResponse := ""
		var errAccept error
		for {
			b := make([]byte, bufSize)
			n, err := c.Read(b)
			if err != nil {
				if err != io.EOF {
					logger.WithContext(ctx).Infof("error reading from socket. err: %v", err)
					errAccept = &SnowflakeError{
						Number:      ErrFailedToGetExternalBrowserResponse,
						SQLState:    SQLStateConnectionRejected,
						Message:     errors2.ErrMsgFailedToGetExternalBrowserResponse,
						MessageArgs: []any{err},
					}
				}
				break
			}
			total += n
			buf.Write(b)
			if n < bufSize {
				// We successfully read all data
				s := string(buf.Bytes()[:total])
				encodedSamlResponse, errAccept = getTokenFromResponse(s)
				break
			}
			buf.Grow(bufSize)
		}
		if encodedSamlResponse != "" {
			body := fmt.Sprintf(samlSuccessHTML, application)
			httpResponse, err := buildResponse(body)
			if err != nil && errAccept == nil {
				errAccept = err
			}
			if _, err = c.Write(httpResponse.Bytes()); err != nil && errAccept == nil {
				errAccept = err
			}
		}
		if err := c.Close(); err != nil {
			logger.Warnf("error while closing browser connection. %v", err)
		}
		encodedSamlResponseChan <- encodedSamlResponse
		errChan <- errAccept
	}(conn)

	encodedSamlResponse = <-encodedSamlResponseChan
	errFromGoroutine = <-errChan

	if errFromGoroutine != nil {
		return authenticateByExternalBrowserResult{nil, nil, errFromGoroutine}
	}

	escapedSamlResponse, err := url.QueryUnescape(encodedSamlResponse)
	if err != nil {
		logger.WithContext(ctx).Errorf("unable to unescape saml response. err: %v", err)
		return authenticateByExternalBrowserResult{nil, nil, err}
	}
	return authenticateByExternalBrowserResult{[]byte(escapedSamlResponse), []byte(proofKey), nil}
}

type samlResponseProvider interface {
	// run drives the user to the login URL. It returns an empty token when the
	// browser opened and the SAML response will arrive on the local listener,
	// or a non-empty token when the user supplied the redirect URL by hand.
	run(loginURL string) (string, error)
}

type externalBrowserSamlResponseProvider struct {
}

// dbt-only: not upstream. Upstream fails the whole login when no browser can be
// opened; headless shells and remote containers are then unusable. Falling back
// to a pasted redirect URL keeps external-browser auth available there.
func (e externalBrowserSamlResponseProvider) run(loginURL string) (string, error) {
	logger.Info("Initiating login request in browser with your identity provider.")

	if err := openBrowser(loginURL); err == nil {
		return "", nil
	}

	logger.Warnf("external-browser auth: could not open browser automatically.")
	logger.Warnf("manual authentication URL: %s", loginURL)

	fmt.Printf("\n%s\n\nWe were unable to open a browser window for you.\n"+
		"Please open the URL above manually, complete the sign-in, then paste\n"+
		"the URL you were finally redirected to here.\n\n", loginURL)

	return manualTokenFallback(os.Stdin)
}

// manualTokenFallback prompts for the post-login redirect URL and extracts its
// token. The terminal is switched to raw mode so that term.Terminal, rather
// than the tty line discipline, does the editing: canonical mode truncates
// input at 4096 bytes on Linux, and a redirect URL carrying a SAML response is
// routinely longer than that.
func manualTokenFallback(in *os.File) (string, error) {
	fd := int(in.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("cannot switch tty to raw mode: %w", err)
	}
	defer func() {
		if restoreErr := term.Restore(fd, oldState); restoreErr != nil {
			logger.Warnf("could not restore terminal state. %v", restoreErr)
		}
	}()

	t := term.NewTerminal(in, "Paste redirect URL: ")
	for {
		line, err := t.ReadLine()
		if errors.Is(err, io.EOF) {
			return "", errors.New("user aborted external browser authentication")
		}
		if err != nil {
			return "", err
		}
		if line == "" {
			return "", errors.New("no URL provided for external browser authentication")
		}
		if token, ok := extractToken(line); ok {
			return token, nil
		}
		fmt.Fprintln(t, "Token not found. Please try again.")
	}
}

// extractToken pulls the "token" query parameter out of the redirect URL the
// user pasted. The bool reports whether a non-empty token was present, so that
// a well-formed URL carrying no token is retried rather than accepted.
func extractToken(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	t := u.Query().Get("token")
	return t, t != ""
}

var defaultSamlResponseProvider = func() samlResponseProvider {
	return &externalBrowserSamlResponseProvider{}
}
