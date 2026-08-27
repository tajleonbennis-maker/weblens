package keydetect

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
)

// minEntropyTokenLen is the shortest candidate value considered for entropy
// detection. Shorter values are too ambiguous to flag.
const minEntropyTokenLen = 16

// entropyThreshold is the bits-per-character above which a value is flagged.
// Because detection is anchored to a sensitive field name (see
// sensitiveFieldRe), the threshold can be lower than a full-text scan.
const entropyThreshold = 3.5

// sensitiveFieldRe anchors entropy detection to a sensitive field name
// followed by a quoted value (group 1 = field name, group 2 = value). This is
// what keeps the signal-to-noise ratio usable: variable names, file paths and
// base64 RSC flight payloads are high-entropy too, but they never appear as the
// value of an api_key/token/secret assignment, so they are excluded by design.
var sensitiveFieldRe = regexp.MustCompile(`(?i)["']?(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|app[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|private[_-]?key|password|credential|bearer)["']?\s*[:=]\s*["']([^"'\\]{16,})["']`)

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[byte]int)
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// isFalsePositive rejects values that are identifiers or paths rather than
// secrets. Real secrets almost always mix letters and digits; a purely
// alphabetic camelCase identifier is not one.
func isFalsePositive(s string) bool {
	hasDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if c == '/' || c == ' ' || c == '\\' {
			return true
		}
	}
	return !hasDigit
}

// isBase64ish reports whether s looks like a base64 payload: standard base64
// alphabet plus optional padding, with a length that is a plausible base64
// block size (>= minLen and a multiple of 4).
func isBase64ish(s string, minLen int) bool {
	if len(s) < minLen || len(s)%4 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '=':
		default:
			return false
		}
	}
	return true
}

// decodeOnce attempts a strict base64 decode of s (std or raw) and reports the
// decoded string and whether it succeeded. Padding is required for std unless
// the raw form is clean.
func decodeOnce(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if out, err := enc.DecodeString(s); err == nil {
			return string(out), true
		}
		if out, err := enc.DecodeString(trimmed); err == nil {
			return string(out), true
		}
	}
	return "", false
}

// isBase64AlphabetOnly reports whether every character of s belongs to the
// base64 alphabet (A-Z a-z 0-9 + /), with optional trailing '=' padding.
func isBase64AlphabetOnly(s string) bool {
	if s == "" {
		return false
	}
	padding := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			padding = false
		case c == '=':
			padding = true
		default:
			return false
		}
	}
	_ = padding
	return true
}

// isDoubleEncodedNumber rejects values that are base64-of-base64 encodings of a
// short numeric/identifier token (e.g. chat-nav templates store user IDs as
// base64(base64("220208250@0"))). These are high-entropy strings but are not
// secrets. A real key decodes to readable text or binary; only a nested
// encoding decodes to text that is itself entirely base64 alphabet.
func isDoubleEncodedNumber(s string) bool {
	if !isBase64ish(s, 16) {
		return false
	}
	once, ok := decodeOnce(s)
	if !ok || !isBase64AlphabetOnly(once) {
		return false
	}
	if !isBase64ish(once, 8) {
		// Pure base64 alphabet but length is not a multiple of 4: a nested
		// template-blob fragment, not a real key.
		return true
	}
	twice, ok := decodeOnce(once)
	if !ok {
		// Cannot decode again: nested blob, not a real key.
		return true
	}
	// A real secret never decodes to a short all-numeric/user-id token.
	if len(twice) == 0 || len(twice) > 24 {
		return false
	}
	digits := 0
	for i := 0; i < len(twice); i++ {
		c := twice[i]
		if c >= '0' && c <= '9' {
			digits++
		}
	}
	// Mostly numeric (or a short alphanumeric handle like "abn2527").
	return digits*2 >= len(twice)
}

// navTemplateMarkers are fragments that identify chat-nav template pages
// (col-xxl-* grid markup + apikey + isHome). These templates embed user-ID
// blobs in the apikey field; the surrounding markup is a reliable signal that
// the value is not a real credential. All markers are lowercase (the context
// is lowercased before matching).
var navTemplateMarkers = []string{
	"col-xxl-", "ishome", "themety", "nav-group", "navlist", "site-config",
}

// isNavTemplateContext reports whether the content around an entropy match
// looks like a chat-nav template page, whose apikey values are user-ID blobs.
func isNavTemplateContext(content string, start, end int) bool {
	lo := start - 200
	if lo < 0 {
		lo = 0
	}
	hi := end + 200
	if hi > len(content) {
		hi = len(content)
	}
	ctx := strings.ToLower(content[lo:hi])
	hits := 0
	for _, m := range navTemplateMarkers {
		if strings.Contains(ctx, m) {
			hits++
		}
	}
	return hits >= 2
}

// detectEntropy flags high-entropy values found in sensitive assignments. It is
// the fallback for providers we do not have a shape rule for.
func detectEntropy(content string) []Finding {
	var out []Finding
	for _, m := range sensitiveFieldRe.FindAllStringSubmatchIndex(content, -1) {
		if len(m) < 6 || m[4] < 0 {
			continue
		}
		start, end := m[4], m[5]
		val := content[start:end]
		if len(val) < minEntropyTokenLen {
			continue
		}
		if isFalsePositive(val) {
			continue
		}
		if isDoubleEncodedNumber(val) {
			continue
		}
		if isNavTemplateContext(content, start, end) {
			continue
		}
		if isDocExample(val) {
			continue
		}
		if shannonEntropy(val) < entropyThreshold {
			continue
		}
		out = append(out, Finding{
			Provider:    classify(val, content, start),
			Kind:        "entropy",
			MaskedKey:   Mask(val),
			Fingerprint: Fingerprint(val),
			Confidence:  "low",
			Offset:      start,
			Context:     contextAround(content, start, end, val),
		})
	}
	return out
}
