package aiassets

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFOFAKeyOnly(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("key") != "secret" {
			t.Fatal("missing key")
		}
		if req.URL.Query().Has("email") {
			t.Fatal("email should be omitted")
		}
		if req.URL.Query().Get("page") != "1" {
			t.Fatal("missing page")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"error":false,"results":[["https://ai.example"]]}`)), Header: make(http.Header)}, nil
	})}
	got, err := (FOFAClient{Key: "secret", Client: client}).Search(context.Background(), `body="Open WebUI"`, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
