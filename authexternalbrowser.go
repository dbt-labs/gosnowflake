package gosnowflake

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
// able to bind to a free port. Specifying a fixed port may cause race condition.
func createLocalTCPListener(ctx context.Context, port int) (*net.TCPListener, error) {
	logger.Debugf("creating local TCP listener on port %v", port)

	var lc net.ListenConfig
	allAddressesListener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%v", port))

	if err != nil {
		logger.Warnf("unable to bind to 0.0.0.0:%v — possible permission or firewall issue: %v", port, err)
		return nil, err
	}
	logger.Debugf("Successfully bound to 0.0.0.0:%v; closing test listener", port)

	if err := allAddressesListener.Close(); err != nil {
		logger.Errorf("error while closing TCP listener. %v", err)
		return nil, err
	}

	l, err := lc.Listen(ctx, "tcp", fmt.Sprintf("localhost:%v", port))
	if err != nil {
		logger.Warnf("Error while setting up listener. Unable to bind to localhost:%v: %v", port, err)
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

	clientEnvironment := authRequestClientEnvironment{
		Application: application,
		Os:          operatingSystem,
		OsVersion:   platform,
	}

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
		logger.WithContext(ctx).Errorln("Authentication FAILED")
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
			Message:     errMsgFailedToParseResponse,
			MessageArgs: []interface{}{response},
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

func authenticateByExternalBrowser(
	ctx context.Context,
	sr *snowflakeRestful,
	authenticator string,
	application string,
	account string,
	user string,
	password string,
	externalBrowserTimeout time.Duration,
	disableConsoleLogin ConfigBool,
) ([]byte, []byte, error) {
	resultChan := make(chan authenticateByExternalBrowserResult, 1)
	go GoroutineWrapper(
		ctx,
		func() {
			resultChan <- doAuthenticateByExternalBrowser(ctx, sr, authenticator, application, account, user, password, disableConsoleLogin)
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
func doAuthenticateByExternalBrowser(
	ctx context.Context,
	sr *snowflakeRestful,
	authenticator string,
	application string,
	account string,
	user string,
	password string,
	disableConsoleLogin ConfigBool,
) authenticateByExternalBrowserResult {
	l, err := createLocalTCPListener(ctx, 0)
	if err != nil {
		return authenticateByExternalBrowserResult{nil, nil, err}
	}
	defer l.Close()

	callbackPort := l.Addr().(*net.TCPAddr).Port

	var loginURL, proofKey string
	if disableConsoleLogin == ConfigBoolTrue {
		loginURL, proofKey, err = getIdpURLProofKey(
			ctx, sr, authenticator, application, account, user, callbackPort)
	} else {
		loginURL, proofKey, err = getLoginURL(sr, user, callbackPort)
	}

	if err != nil {
		// Multiple SAML way to do authentication via console login
		return authenticateByExternalBrowserResult{nil, nil, err}
	}

	fmt.Printf("\tInitiating login request in browser with your identity provider.")
	if err := openBrowser(loginURL); err == nil {
		// ---- AUTOMATIC PATH
		// Block until the browser redirect hits the listener.
		token, readErr := waitForSamlResponse(ctx, l, application)
		if readErr != nil {
			return authenticateByExternalBrowserResult{nil, nil, readErr}
		}

		unescaped, err := url.QueryUnescape(token)
		if err != nil {
			logger.WithContext(ctx).Errorf("unable to unescape saml response: %v", err)
			return authenticateByExternalBrowserResult{nil, nil, err}
		}
		return authenticateByExternalBrowserResult{[]byte(unescaped), []byte(proofKey), nil}

	} else {
		// ----- MANUAL FALLBACK
		logger.WithContext(ctx).Warnf("external-browser auth: could not open browser: %v", err)
		logger.WithContext(ctx).Warnf("manual authentication URL: %s", loginURL)

		// Listener not needed; close it so Snowflake cannot connect.
		_ = l.Close()

		fmt.Printf("\t\n\t%s\n\n"+
		    "\tWe were unable to open a browser window for you.\n"+
		    "\tPlease open the URL above manually, complete the sign-in, then paste\n"+
		    "\tthe URL you were finally redirected to here.\n\n", loginURL)

		token, perr := manualTokenFallback()
		if perr != nil {
			return authenticateByExternalBrowserResult{
				nil, nil, &SnowflakeError{
					Number:      ErrFailedToGetExternalBrowserResponse,
					SQLState:    SQLStateConnectionRejected,
					Message:     "Unable to open a browser in this environment and the provided URL contained no token",
					MessageArgs: []interface{}{perr},
				},
			}
		}

		unescaped, err := url.QueryUnescape(token)
		if err != nil {
			logger.WithContext(ctx).Errorf("unable to unescape saml response: %v", err)
			return authenticateByExternalBrowserResult{nil, nil, err}
		}
		return authenticateByExternalBrowserResult{[]byte(unescaped), []byte(proofKey), nil}
	}
}

func waitForSamlResponse(ctx context.Context, l net.Listener, application string) (string, error) {
	encodedChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			errChan <- err
			return
		}
		defer conn.Close()

		var buf bytes.Buffer
		total := 0
		var encoded string
		var acceptErr error

		for {
			b := make([]byte, bufSize)
			n, err := conn.Read(b)
			if err != nil {
				if err != io.EOF {
					acceptErr = &SnowflakeError{
						Number:      ErrFailedToGetExternalBrowserResponse,
						SQLState:    SQLStateConnectionRejected,
						Message:     errMsgFailedToGetExternalBrowserResponse,
						MessageArgs: []interface{}{err},
					}
				}
				break
			}
			total += n
			buf.Write(b)
			if n < bufSize {
				encoded, acceptErr = getTokenFromResponse(string(buf.Bytes()[:total]))
				break
			}
			buf.Grow(bufSize)
		}

		if encoded != "" {
			body := fmt.Sprintf(samlSuccessHTML, application)
			httpResp, err := buildResponse(body)
			if err != nil && acceptErr == nil {
				acceptErr = err
			}
			if _, err = conn.Write(httpResp.Bytes()); err != nil && acceptErr == nil {
				acceptErr = err
			}
		}

		if acceptErr != nil {
			errChan <- acceptErr
			return
		}
		encodedChan <- encoded
	}()

	select {
	case s := <-encodedChan:
		return s, nil
	case e := <-errChan:
		return "", e
	}
}

// canonical mode OFF, echo ON
func manualTokenFallback() (string, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return "", fmt.Errorf("cannot switch tty to raw mode: %w", err)
	}
	defer term.Restore(fd, oldState)

	// Now safe to run the VT-100 line editor.
	t := term.NewTerminal(os.Stdin, "Paste redirect URL: ")

	for {
	        // ReadLine echoes & handles Ctrl-C/Z
		line, err := t.ReadLine()
		if err == io.EOF { return "", errors.New("user aborted") }
		if err != nil   { return "", err }

		if line == ""   { return "", errors.New("no URL provided") }

		if token, ok := extractToken(line); ok {
			return token, nil
		}
		fmt.Fprintln(t, "Token not found. Please try again.")
	}
}

func extractToken(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	t := u.Query().Get("token")
	return t, t != ""
}
