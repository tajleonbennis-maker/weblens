package aiassets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScriptURLsSameOrigin(t *testing.T) {
	got := scriptURLs("https://ai.example/a", `<script src="/app.js"></script><script src="https://evil.test/x.js"></script>`, 8)
	if len(got) != 1 || got[0] != "https://ai.example/app.js" {
		t.Fatalf("%#v", got)
	}
}

func TestIsHTTPSuccess(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   bool
	}{{199, false}, {200, true}, {204, true}, {299, true}, {300, false}, {404, false}, {500, false}} {
		if got := isHTTPSuccess(tc.status); got != tc.want {
			t.Errorf("isHTTPSuccess(%d) = %t, want %t", tc.status, got, tc.want)
		}
	}
}

func TestFetchReturnsNonSuccessStatusWithoutTransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream failed"))
	}))
	defer srv.Close()

	s := NewScanner("", false)
	body, status, _, _, err := s.fetch(context.Background(), srv.URL, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusBadGateway || string(body) != "upstream failed" {
		t.Fatalf("status = %d, body = %q", status, body)
	}
}

func TestProbeConfigEndpointsPlatformAware(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/settings", "/api/v1/config", "/api/settings", "/api/config":
			// generic endpoints return nothing sensitive
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ui":{"theme":"snow"}}`))
		case "/api/auth/session":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user":{"name":"x"},"apiKey":"sk-abcdefghijklmnopqrstuvwxyz123456"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := NewScanner("", false)
	// LibreChat platform should probe /api/auth/session before generic list.
	exposures := s.probeConfigEndpoints(context.Background(), srv.URL, []Technology{{Name: "LibreChat"}})
	if len(exposures) == 0 {
		t.Fatalf("expected an exposure from /api/auth/session, seen paths: %v", seen)
	}
	found := false
	for _, e := range exposures {
		if e.MaskedKey == "sk-****3456" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected masked key sk-****3456, got %+v", exposures)
	}
	// The LibreChat-specific /api/auth/session must have been probed (generic
	// list alone has no exposure on this server).
	probedSession := false
	for _, p := range seen {
		if p == "/api/auth/session" {
			probedSession = true
		}
	}
	if !probedSession {
		t.Fatalf("LibreChat-specific endpoint should be probed, seen: %v", seen)
	}
}

func TestProbeConfigEndpointsGenericFallback(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		if r.URL.Path == "/api/v1/settings" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"catalog":{"services":{"llm":{"profiles":[{"api_key":"sk-abcdefghijklmnopqrstuvwxyz123456"}]}}}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	s := NewScanner("", false)
	// Unknown platform: only the generic list runs and /api/v1/settings hits.
	exposures := s.probeConfigEndpoints(context.Background(), srv.URL, []Technology{{Name: "Next.js"}})
	if len(exposures) == 0 {
		t.Fatalf("expected generic endpoint exposure, seen paths: %v", seen)
	}
}

func TestIsSensitiveCookieFiltering(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
	}{
		{"csrftoken", "abc123def456ghi", false},
		{"XSRF-TOKEN", "abc123def456ghi", false},
		{"X_CACHE_KEY", "abc123def456ghi", false},
		{"lang", "zh-CN", false},
		{"theme", "dark", false},
		{"is_home", "1", false},
		{"session", "abc", false}, // 太短
		{"session", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature", true},
		{"access_token", "sk-abcdefghijklmnopqrstuvwxyz123456", true},
		{"api_key", "abcdefghijklmnopqrstuvwxyz1234567890", true},
		{"token", "abcdefghijklmnopqrstuvwxyz1234567890", true},
	}
	for _, tc := range cases {
		if got := isSensitiveCookie(tc.name, tc.value); got != tc.want {
			t.Errorf("isSensitiveCookie(%q, %q) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}
