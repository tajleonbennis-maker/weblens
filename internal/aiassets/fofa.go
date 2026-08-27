package aiassets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type FOFAClient struct {
	Email, Key string
	Client     *http.Client
}

// DefaultQueries is the FOFA discovery surface for the AI-asset collector.
// It covers the most common self-hosted / SaaS AI chat platforms plus the
// widely-deployed API-relay gateways that often embed provider keys. The list
// is the extension point for scaling the node across the internet.
var DefaultQueries = []string{
	// AI chat front-ends / platforms
	`body="Open WebUI"`,
	`body="LobeChat"`,
	`body="LibreChat"`,
	`body="Dify"`,
	`body="ChatGPT Next Web"`,
	`body="nextchat"`,
	// API relay / key-gateway panels (One API family and clones)
	`body="One API"`,
	`body="new-api"`,
	`body="uni-api"`,
	`body="new-api-panel"`,
	// Local model runtimes
	`body="SillyTavern"`,
	`body="text-generation-webui"`,
	`body="koboldcpp"`,
	`body="ollama"`,
	// Popular AI front-ends / aggregators
	`body="ChatGPT-Next-Web"`,
	`body="chatgpt-web"`,
	`body="free-chatgpt"`,
	`body="chatbot-ui"`,
	`body="vercel-ai"`,
	`body="gradio"`,
	// Agent frameworks (OpenClaw — huge public exposure surface per QAX TI:
	// ~34k instances, 82 CVEs). Added 2026-08-27.
	`body="OpenClaw"`,
	`title="OpenClaw"`,
	`body="openclaw"`,
	// Self-hosted MCP / agent gateways (fast-growing agent-security surface)
	`body="mcp-server"`,
	`body="MCP Server"`,
}

func (c FOFAClient) Search(ctx context.Context, query string, size int) ([]Candidate, error) {
	return c.SearchPage(ctx, query, size, 1)
}

// FOFAResult is one matched asset row from a FOFA search (host/ip/port/title).
type FOFAResult struct {
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Port  string `json:"port"`
	Title string `json:"title"`
}

// Count runs a FOFA search and returns the total number of matches plus a
// sample of the first `size` results with metadata. Used by the LLM agent so
// a user can ask "how many X assets are there on the internet" in plain words.
func (c FOFAClient) Count(ctx context.Context, query string, size int) (int, []FOFAResult, error) {
	if strings.TrimSpace(c.Key) == "" {
		return 0, nil, fmt.Errorf("FOFA_KEY is required")
	}
	if size < 1 {
		size = 10
	}
	q := url.Values{}
	if strings.TrimSpace(c.Email) != "" {
		q.Set("email", c.Email)
	}
	q.Set("key", c.Key)
	q.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	q.Set("fields", "host,ip,port,title")
	q.Set("size", fmt.Sprint(size))
	q.Set("page", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fofa.info/api/v1/search/all?"+q.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("FOFA request failed")
	}
	defer resp.Body.Close()
	var body struct {
		Error   bool      `json:"error"`
		Message string    `json:"errmsg"`
		Size    int       `json:"size"`
		Results [][]any   `json:"results"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != 200 || body.Error {
		return 0, nil, fmt.Errorf("FOFA search failed: %s", body.Message)
	}
	var sample []FOFAResult
	for _, row := range body.Results {
		var r FOFAResult
		if len(row) > 0 {
			r.Host, _ = row[0].(string)
		}
		if len(row) > 1 {
			r.IP, _ = row[1].(string)
		}
		if len(row) > 2 {
			r.Port, _ = row[2].(string)
		}
		if len(row) > 3 {
			r.Title, _ = row[3].(string)
		}
		sample = append(sample, r)
	}
	return body.Size, sample, nil
}

func (c FOFAClient) SearchPage(ctx context.Context, query string, size, page int) ([]Candidate, error) {
	if strings.TrimSpace(c.Key) == "" {
		return nil, fmt.Errorf("FOFA_KEY is required")
	}
	if size < 1 {
		size = 100
	}
	if page < 1 {
		page = 1
	}
	q := url.Values{}
	if strings.TrimSpace(c.Email) != "" {
		q.Set("email", c.Email)
	}
	q.Set("key", c.Key)
	q.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	q.Set("fields", "host,ip,port,title,domain,server")
	q.Set("size", fmt.Sprint(size))
	q.Set("page", fmt.Sprint(page))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fofa.info/api/v1/search/all?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// net/http errors can include the complete URL. FOFA authenticates in
		// its query string, so returning that error could disclose the API key.
		return nil, fmt.Errorf("FOFA request failed")
	}
	defer resp.Body.Close()
	var body struct {
		Error   bool    `json:"error"`
		Message string  `json:"errmsg"`
		Results [][]any `json:"results"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 || body.Error {
		return nil, fmt.Errorf("FOFA search failed: %s", body.Message)
	}
	seen := map[string]bool{}
	var out []Candidate
	for _, row := range body.Results {
		if len(row) == 0 {
			continue
		}
		host, _ := row[0].(string)
		host = strings.TrimSpace(host)
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			continue
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, Candidate{URL: host, DiscoveredBy: "fofa:" + query})
		}
	}
	return out, nil
}
