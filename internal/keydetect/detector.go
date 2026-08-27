// Package keydetect implements API-key leakage detection over rendered page
// content. It is intentionally self-contained (standard library only) so it can
// be unit-tested and reused independently of the browser control plane.
package keydetect

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Finding is a single detected key exposure, already masked. The full key is
// never retained: only a masked prefix/suffix and a one-way fingerprint.
type Finding struct {
	Provider    string `json:"provider,omitempty"` // attributed provider, empty if unknown
	Kind        string `json:"kind"`               // "rule" or "entropy"
	MaskedKey   string `json:"maskedKey"`          // e.g. "sk-****abcd"
	Fingerprint string `json:"fingerprint"`        // sha256 hex of the full key
	Confidence  string `json:"confidence"`         // "high" | "medium" | "low"
	Offset      int    `json:"offset"`             // byte offset in the source content
	Context     string `json:"context,omitempty"`  // short masked surrounding text
}

// Detect scans content for leaked API keys using both pattern rules and
// Shannon-entropy heuristics. Results are deduplicated by fingerprint and
// sorted by offset.
func Detect(content string) []Finding {
	var out []Finding

	for _, r := range rules {
		for _, m := range r.re.FindAllStringSubmatchIndex(content, -1) {
			start, end := m[0], m[1]
			if r.group > 0 && r.group*2+1 < len(m) && m[r.group*2] >= 0 {
				start, end = m[r.group*2], m[r.group*2+1]
			}
			if start < 0 || end <= start {
				continue
			}
			full := content[start:end]
			if isPlaceholder(full) {
				continue
			}
			// Shape rules like sk- are shared by several providers; reclassify
			// from surrounding context when a more specific provider is known.
			provider := r.provider
			if p := classify(full, content, start); p != "" {
				provider = p
			}
			out = append(out, Finding{
				Provider:    provider,
				Kind:        "rule",
				MaskedKey:   Mask(full),
				Fingerprint: Fingerprint(full),
				Confidence:  r.confidence,
				Offset:      start,
				Context:     contextAround(content, start, end, full),
			})
		}
	}

	out = append(out, detectEntropy(content)...)
	out = dedupe(out)
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// Mask keeps a short prefix and suffix and blanks the middle. Very short values
// are fully redacted.
func Mask(full string) string {
	if len(full) <= 8 {
		return strings.Repeat("*", len(full))
	}
	return full[:3] + "****" + full[len(full)-4:]
}

// Fingerprint returns the sha256 hex of the full key (one-way, unsalted). A
// keyed HMAC can replace this later if a server-side secret is available.
func Fingerprint(full string) string {
	sum := sha256.Sum256([]byte(full))
	return hex.EncodeToString(sum[:])
}

// isPlaceholder reports whether a matched value is a redaction placeholder
// (e.g. "nvapi-xxxx...") rather than a real secret.
func isPlaceholder(s string) bool {
	if len(s) < 8 {
		return false
	}
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == 'x' || s[i] == 'X' || s[i] == '*' {
			count++
		}
	}
	if count*5 >= len(s)*3 {
		return true
	}
	return isDocExample(s)
}

// isDocExample reports whether a matched value looks like documentation
// placeholder text rather than a live secret. Matches real-world noise seen in
// API docs and tutorials: "sk-xxxx-key", "AKIA...MPLE", "Bearer YOUR_KEY",
// "ghp_XXXXXXXXXXXXXXXXXXXXXX", trailing "..." and the _KEY / _TOKEN suffixes.
// Chinese placeholders ("sk-你的-key") are covered too.
func isDocExample(s string) bool {
	lower := strings.ToLower(s)
	for _, frag := range []string{
		"your", "example", "placeholder", "sample", "demo",
		"xxxx", "xxx", "....", "...", "your_key", "your-key",
		"akey", "put here", "here", "redacted",
		"你的", "真实", "示例", "样例", "请填入", "请替换", "替换为", "占位", "测试",
	} {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	if strings.HasSuffix(lower, "_key") || strings.HasSuffix(lower, "-key") {
		return true
	}
	if strings.HasSuffix(lower, "mple") && len(lower) <= 24 {
		return true
	}
	return false
}

func contextAround(content string, start, end int, secret string) string {
	lo := start - 24
	if lo < 0 {
		lo = 0
	}
	hi := end + 24
	if hi > len(content) {
		hi = len(content)
	}
	s := content[lo:hi]
	s = strings.ReplaceAll(s, secret, Mask(secret))
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		if f.Fingerprint == "" || seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		out = append(out, f)
	}
	return out
}
