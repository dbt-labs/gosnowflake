package logger

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	awsKeyPattern          = `(?i)(aws_key_id|aws_secret_key|access_key_id|secret_access_key)\s*=\s*'([^']+)'`
	awsTokenPattern        = `(?i)(accessToken|tempToken|keySecret)"\s*:\s*"([a-z0-9/+]{32,}={0,2})"`
	sasTokenPattern        = `(?i)(sig|signature|AWSAccessKeyId|password|passcode)=(?P<secret>[a-z0-9%/+]{16,})`
	privateKeyPattern      = `(?im)-----BEGIN PRIVATE KEY-----\\n([a-z0-9/+=\\n]{32,})\\n-----END PRIVATE KEY-----` // pragma: allowlist secret
	privateKeyDataPattern  = `(?i)"privateKeyData": "([a-z0-9/+=\\n]{10,})"`
	privateKeyParamPattern = `(?i)privateKey=([A-Za-z0-9/+=_%-]+)(&|$|\s)`
	// connectionTokenPattern's value class admits ':' because every documented
	// Snowflake session-token format begins "ver:" - per GlobalServices
	// SecurityToken.java these are ver:1-hint:<keyId>-<encrypted>,
	// ver:2-hint:<keyId>-did:<deployId>-<encrypted>, and the V3/V4 equivalents
	// currently minted, with V2 and V4 carrying a further ':' in "-did:". Without
	// ':' the match ended after "ver", three characters in and below the
	// 8-character minimum, so the pattern matched no version of the format it is
	// named for.
	connectionTokenPattern = `(?i)(token|assertion content)([\'\"\s:=]+)([a-z0-9=/_\-\+:]{8,})`
	passwordPattern        = `(?i)(password|pwd)([\'\"\s:=]+)([a-z0-9!\"#\$%&\\\'\(\)\*\+\,-\./:;<=>\?\@\[\]\^_\{\|\}~]{8,})`
	dsnPasswordPattern     = `([^/:]+):([^@/:]{3,})@` // Matches user:password@host format in DSN strings
	clientSecretPattern    = `(?i)(clientSecret)([\'\"\s:= ]+)([a-z0-9!\"#\$%&\\\'\(\)\*\+\,-\./:;<=>\?\@\[\]\^_\{\|\}~]+)`
	jwtTokenPattern        = `(?i)(jwt|bearer)[\s:=]*([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)` // pragma: allowlist secret
	// sseCustomerKeyPattern masks the S3 SSE-C customer-key header value, which the
	// generic patterns above do not cover (SNOW-3649835).
	sseCustomerKeyPattern = `(?i)(x-amz-server-side-encryption-customer-key)((?:\s*,?\s*value)?\s*[:=]\s*)([a-z0-9+/]{16,}={0,2})` // pragma: allowlist secret
	// awsSigV4ParamPattern masks the X-Amz-Credential and X-Amz-Security-Token query
	// parameters (the signature is handled by sasTokenPattern) (SNOW-3649835).
	awsSigV4ParamPattern = `(?i)(x-amz-credential|x-amz-security-token)=([a-z0-9%/+=._-]{8,})` // pragma: allowlist secret
)

type patternAndReplace struct {
	regex       *regexp.Regexp
	replacement string
}

var secretDetectorPatterns = []patternAndReplace{
	// These two must precede connectionTokenPattern so an X-Amz-Security-Token value
	// (which contains the substring "token" and a '%') is masked in full first.
	{regexp.MustCompile(sseCustomerKeyPattern), "${1}${2}****"},
	{regexp.MustCompile(awsSigV4ParamPattern), "${1}=****"},
	// The second capture group of awsKeyPattern and awsTokenPattern is the secret
	// itself, so the replacement must not reference it.
	{regexp.MustCompile(awsKeyPattern), "${1}='****'"},
	{regexp.MustCompile(awsTokenPattern), `${1}":"XXXX"`},
	{regexp.MustCompile(sasTokenPattern), "${1}=****"},
	{regexp.MustCompile(privateKeyPattern), "-----BEGIN PRIVATE KEY-----\\\\\\\\nXXXX\\\\\\\\n-----END PRIVATE KEY-----"}, // pragma: allowlist secret
	{regexp.MustCompile(privateKeyDataPattern), `"privateKeyData": "XXXX"`},
	{regexp.MustCompile(privateKeyParamPattern), "privateKey=****$2"},
	{regexp.MustCompile(connectionTokenPattern), "$1${2}****"},
	{regexp.MustCompile(passwordPattern), "$1${2}****"},
	{regexp.MustCompile(dsnPasswordPattern), "$1:****@"},
	{regexp.MustCompile(clientSecretPattern), "$1${2}****"},
	{regexp.MustCompile(jwtTokenPattern), "$1 ****"},
}

// MaskSecrets masks secrets in text (exported for use by main package and secret masking logger)
func MaskSecrets(text string) (masked string) {
	res := maskGoShapes(text)
	for _, pattern := range secretDetectorPatterns {
		res = pattern.regex.ReplaceAllString(res, pattern.replacement)
	}
	return res
}

// Secrets reach log messages inside values formatted with %v, whose rendering
// the patterns above do not recognise. Two shapes matter:
//
//   - http.Header (alone or inside a formatted *http.Response) renders as
//     map[Name:[value] Other:[v1 v2]]; header values carry session tokens,
//     storage credentials and the SSE-C key (qrmk).
//   - []byte (response bodies) renders as [123 34 116 ...], so a token in a
//     JSON body never appears as text.
//
// maskGoShapes rewrites both shapes before the patterns run, so every log call
// is covered by MaskSecrets instead of at each call site.
var (
	// A canonical header key followed by its rendered value slice, inside a map.
	headerEntryRegexp = regexp.MustCompile(`([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*):\[[^\]]*\]`)
	headerMapRegexp   = regexp.MustCompile(`map\[(?:[A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*:\[[^\]]*\] ?)+\]`)
	// At least 8 space-separated decimal bytes inside brackets.
	byteSliceRegexp = regexp.MustCompile(`\[(?:\d{1,3} ){7,}\d{1,3}\]`)
)

func maskHeaderMaps(text string) string {
	return headerMapRegexp.ReplaceAllStringFunc(text, func(m string) string {
		return headerEntryRegexp.ReplaceAllString(m, "$1:[****]")
	})
}

// decodeByteSlices turns a rendered []byte back into text so the secret
// patterns can see it; anything that is not printable stays as rendered.
func decodeByteSlices(text string) string {
	return byteSliceRegexp.ReplaceAllStringFunc(text, func(m string) string {
		fields := strings.Fields(m[1 : len(m)-1])
		out := make([]byte, 0, len(fields))
		for _, f := range fields {
			n, err := strconv.Atoi(f)
			if err != nil || (n < 0x20 && n != '\n' && n != '\r' && n != '\t') || n > 0x7e {
				return m
			}
			out = append(out, byte(n))
		}
		return string(out)
	})
}

func maskGoShapes(text string) string {
	return maskHeaderMaps(decodeByteSlices(text))
}
