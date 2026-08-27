package main

import (
	"encoding/json"
	"github.com/tajleonbennis-maker/weblens/internal/aiassets"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReadState(t *testing.T) {
	d := t.TempDir()
	a := aiassets.Asset{AssetURL: "https://ai.example", Reachable: true, AIChat: true, Technologies: []aiassets.Technology{{Name: "Open WebUI"}}, Models: []aiassets.Model{{Provider: "OpenAI"}}}
	b, _ := json.Marshal(a)
	if err := os.WriteFile(filepath.Join(d, "assets.jsonl"), append(b, '\n'), 0640); err != nil {
		t.Fatal(err)
	}
	s, err := readState(d)
	if err != nil || s.Scanned != 1 || s.AIAssets != 1 || len(s.Technologies) != 1 || len(s.Assets) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestBasicAuth(t *testing.T) {
	h := basicAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "weblens", "secret")

	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("weblens", "secret")
	h.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusNoContent {
		t.Fatalf("authorized status = %d", authorized.Code)
	}
}
