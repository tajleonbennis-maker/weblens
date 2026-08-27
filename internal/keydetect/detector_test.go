package keydetect

import (
	"strings"
	"testing"
)

func TestDetectOpenAIKey(t *testing.T) {
	content := `const key = "sk-abcdefghijklmnopqrstuvwxyz123456";`
	findings := Detect(content)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	found := false
	for _, f := range findings {
		if f.Kind == "rule" && f.Provider == "OpenAI" {
			found = true
			if f.MaskedKey != "sk-****3456" {
				t.Fatalf("unexpected mask: %q", f.MaskedKey)
			}
			if f.Fingerprint == "" {
				t.Fatal("expected non-empty fingerprint")
			}
			if strings.Contains(f.Context, "abcdefghijklmnopqrstuvwxyz123456") {
				t.Fatalf("context leaked the complete key: %q", f.Context)
			}
		}
	}
	if !found {
		t.Fatalf("no OpenAI rule finding, got %+v", findings)
	}
}

func TestDetectAWSKey(t *testing.T) {
	findings := Detect("aws_access_key_id = AKIAIOSFODNN7ABCDEFG")
	for _, f := range findings {
		if f.Provider == "AWS" {
			return
		}
	}
	t.Fatal("expected AWS finding")
}

func TestDetectBearerToken(t *testing.T) {
	findings := Detect("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
	for _, f := range findings {
		if f.Kind == "rule" && f.MaskedKey == "abc****wxyz" {
			return
		}
	}
	t.Fatal("expected masked Bearer token finding")
}

func TestMask(t *testing.T) {
	if Mask("sk-abcdefghijklmnop") != "sk-****mnop" {
		t.Fatalf("unexpected mask %q", Mask("sk-abcdefghijklmnop"))
	}
	if Mask("short") != "*****" {
		t.Fatalf("unexpected short mask %q", Mask("short"))
	}
}

func TestEntropyAnchoredToSensitiveField(t *testing.T) {
	// A high-entropy value behind a sensitive field name is flagged.
	content := `{"api_key": "b4eb9b9063f24daf9e84075ec6aa5366"}`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "entropy" {
			return
		}
	}
	t.Fatalf("expected entropy finding for api_key value, got %+v", findings)
}

func TestEntropyIgnoresNonSensitiveContext(t *testing.T) {
	// High-entropy text that is not a sensitive assignment must not be flagged.
	content := `normalizeCodeBlockShowLineNumbers /_next/static/chunks/145f069teoa7h.js`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "entropy" {
			t.Fatalf("unexpected entropy finding: %+v", f)
		}
	}
}

func TestPlaceholderExcluded(t *testing.T) {
	findings := Detect(`{"api_key": "nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`)
	for _, f := range findings {
		if f.MaskedKey == "nva****xxxx" {
			t.Fatalf("placeholder should be excluded, got %+v", f)
		}
	}
}

func TestDocExampleExcluded(t *testing.T) {
	cases := []string{
		`{"api_key": "sk-xxxx-key"}`,
		`Authorization: Bearer YOUR_API_KEY`,
		`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
		`{"apiKey": "AIza...2-3g", "authDomain": "example"}`,
		`{"api_key": "ghp_XXXXXXXXXXXXXXXXXXXXXX"}`,
	}
	for _, content := range cases {
		if findings := Detect(content); len(findings) > 0 {
			t.Fatalf("doc example should be excluded for %q, got %+v", content, findings)
		}
	}
}

func TestDoubleBase64NumberExcluded(t *testing.T) {
	// chat-nav templates store user IDs as base64(base64("220208250@0")).
	content := `col-xxl-6a ","apikey":"TWpJd01qQTRNalVBTUE9PQ==","isHome":"1"`
	if findings := Detect(content); len(findings) > 0 {
		t.Fatalf("double-base64 user id should be excluded, got %+v", findings)
	}
}

func TestDoubleBase64RealKeyStillDetected(t *testing.T) {
	// A base64-encoded real API key (not a number) must still be flagged.
	content := `{"apikey": "c2stYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="}`
	found := false
	for _, f := range Detect(content) {
		if f.Kind == "entropy" {
			found = true
		}
	}
	if !found {
		t.Fatal("base64-encoded real key should still be detected")
	}
}

func TestVolcengineKeyDetected(t *testing.T) {
	content := `"api_key":"sk-ws-abcd1234efgh5678ijkl9012mnop"`
	findings := Detect(content)
	for _, f := range findings {
		if f.Provider == "火山引擎方舟" {
			return
		}
	}
	t.Fatal("expected volcengine ark finding")
}

func TestIsDocExample(t *testing.T) {
	real := []string{
		"sk-abcdefghijklmnopqrstuvwxyz123456",
		"AKIAIOSFODNN7ABCDEFG",
		"sk-ws-abcd1234efgh5678ijkl9012mnop",
	}
	for _, s := range real {
		if isDocExample(s) {
			t.Fatalf("real key %q misclassified as doc example", s)
		}
	}
	docs := []string{
		"sk-xxxx-key",
		"YOUR_API_KEY",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_XXXXXXXXXXXXXXXXXXXXXX",
		"nvapi-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	for _, s := range docs {
		if !isDocExample(s) {
			t.Fatalf("doc example %q not classified", s)
		}
	}
}

// TestRealWorldRegression guards against regressions observed in the 8081
// all-AI-web scan: chat-nav template user IDs (double base64) and doc examples
// must be excluded, while a genuinely exposed sk- key must survive.
func TestRealWorldRegression(t *testing.T) {
	// Real noise from the production scan (work.zhizengzeng.com etc).
	noise := []string{
		` col-xxl-6a ","apikey":"TWpJd01qQTRNalVBTUE9PQ==","isHome":"1","version"`,
		` col-xxl-6a ","apikey":"TURNeU56Y3pOdz09","isHome":true,"themeTy`,
		`",           "apiKey": "sk-xxxx-key",           "headers":`,
		`e>Authorization: Bearer YOUR_API_KEY</code>.</li><li>Return `,
	}
	for i, content := range noise {
		if findings := Detect(content); len(findings) > 0 {
			t.Fatalf("noise case %d should be excluded: %q -> %+v", i, content, findings)
		}
	}
	// A real exposed key from xyblog.xianyuw.cn style front-end JS must survive.
	real := `const CHAT_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456";`
	found := false
	for _, f := range Detect(real) {
		if f.Kind == "rule" && f.Provider == "OpenAI" && f.MaskedKey == "sk-****3456" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real key must still be detected in %q", real)
	}
}

// TestRealWorldRegressionV2 guards the second wave of noise found after the
// first fix shipped: a longer double-base64 user-ID blob and Chinese
// placeholder text, both observed live on production targets.
func TestRealWorldRegressionV2(t *testing.T) {
	noise := []string{
		// work.zhizengzeng.com: 60-char double-base64 that fails second decode.
		` col-xxl-6a ","apikey":"TWpBeU1USTJNemd4TWpZM0d6RS9oUWpCWk5FWnVVVGhVVUdOMFVFWmhSWE14","isHome":"1","version"`,
		// doc.reddoctor.work: Chinese placeholders.
		`",           "apiKey": "sk-你的-sub2api-key",           "headers":`,
		`",           "apiKey": "sk-你的真实API-Key",           "headers":`,
	}
	for i, content := range noise {
		if findings := Detect(content); len(findings) > 0 {
			t.Fatalf("v2 noise case %d should be excluded: %q -> %+v", i, content, findings)
		}
	}
}

func TestIsNavTemplateContext(t *testing.T) {
	content := ` col-xxl-6a ","apikey":"whatever","isHome":"1","version"`
	if !isNavTemplateContext(content, strings.Index(content, "whatever"), strings.Index(content, "whatever")+len("whatever")) {
		t.Fatal("expected nav-template context to be detected")
	}
	plain := `var apiKey = "abcdefghijklmnopqrstuvwxyz123456";`
	if isNavTemplateContext(plain, 0, len(plain)) {
		t.Fatal("plain JS should not be treated as nav-template context")
	}
}

func TestProviderReclassified(t *testing.T) {
	content := `"base_url":"https://api.deepseek.com","api_key":"sk-b4eb9b9063f24daf9e84075ec6aa5366"`
	findings := Detect(content)
	for _, f := range findings {
		if f.Kind == "rule" {
			if f.Provider != "DeepSeek" {
				t.Fatalf("expected DeepSeek provider, got %q", f.Provider)
			}
			return
		}
	}
	t.Fatal("expected rule finding")
}
