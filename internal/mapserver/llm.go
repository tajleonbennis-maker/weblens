package mapserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LLMClient is a minimal DeepSeek (OpenAI-compatible) chat client used by the
// natural-language mapping agent. The API key is read from the environment at
// startup (DEEPSEEK_API_KEY) and never written into code or reports.
type LLMClient struct {
	apiKey string
	model  string
	hc     *http.Client
}

// NewLLMClient returns a client for the given DeepSeek API key.
func NewLLMClient(apiKey string) *LLMClient {
	return &LLMClient{
		apiKey: apiKey,
		model:  "deepseek-chat",
		hc:     &http.Client{Timeout: 45 * time.Second},
	}
}

type llmMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Chat sends a single-turn system+user request and returns the assistant
// text. When jsonMode is true, response_format is pinned to JSON so the agent
// can parse plans; when false the model answers in plain prose.
func (l *LLMClient) Chat(ctx context.Context, sys, user string, jsonMode bool) (string, error) {
	bodyMap := map[string]any{
		"model":       l.model,
		"temperature": 0.2,
		"max_tokens":  1200,
		"messages": []llmMsg{
			{Role: "system", Content: sys},
			{Role: "user", Content: user},
		},
	}
	if jsonMode {
		bodyMap["response_format"] = map[string]string{"type": "json_object"}
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.deepseek.com/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+l.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := l.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("deepseek: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("deepseek HTTP %d: %s", resp.StatusCode, string(raw[:min(len(raw), 300)]))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("deepseek decode: %w", err)
	}
	if len(out.Choices) == 0 || out.Choices[0].Message.Content == "" {
		return "", fmt.Errorf("deepseek: empty response")
	}
	return out.Choices[0].Message.Content, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
