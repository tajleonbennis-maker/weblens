package mapserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// TikHubClient talks to TikHub.io — a data API that can read closed social
// platforms (WeChat 公众号, Douyin, TikTok, Xiaohongshu ...) that traditional
// web mapping cannot reach. This is a core moat of the platform.
//
// Auth is `Authorization: Bearer <key>`. A browser User-Agent is required to
// pass TikHub's Cloudflare edge (plain Go/py UAs get HTTP 1010/403).
// Mainland China users should swap base to https://api.tikhub.dev.
//
// Cost controls:
//   - search retries reuse the FREE cache URL TikHub returns for 24h
//   - article details are cached locally on disk (url -> detail), so
//     re-downloading the same article costs nothing
type TikHubClient struct {
	key       string
	base      string
	hc        *http.Client
	cachePath string

	mu      sync.Mutex
	artCache map[string]WeChatArticleDetail
}

// NewTikHubClient returns a client for the given API token.
func NewTikHubClient(key string) *TikHubClient {
	t := &TikHubClient{
		key:       key,
		base:      "https://api.tikhub.io",
		hc:        &http.Client{Timeout: 60 * time.Second},
		cachePath: "/var/lib/weblens/tikhub-cache.jsonl",
		artCache:  map[string]WeChatArticleDetail{},
	}
	t.loadCache()
	return t
}

func (t *TikHubClient) loadCache() {
	f, err := os.Open(t.cachePath)
	if err != nil {
		return
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec struct {
			URL string               `json:"url"`
			Det WeChatArticleDetail  `json:"det"`
		}
		if err := dec.Decode(&rec); err != nil {
			break
		}
		if rec.URL != "" && rec.Det.Title != "" {
			t.artCache[rec.URL] = rec.Det
		}
	}
}

func (t *TikHubClient) saveCache(url string, det WeChatArticleDetail) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.artCache[url] = det
	f, err := os.OpenFile(t.cachePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewEncoder(f).Encode(map[string]any{"url": url, "det": det})
}

// cacheURL hits the free 24h cache endpoint TikHub attaches to every paid
// response — retrying a search through the cache costs nothing.
func (t *TikHubClient) cacheURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	resp, err := t.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cache HTTP %d", resp.StatusCode)
	}
	return raw, nil
}

// postJSON returns the cache_url alongside the decoded payload so callers can
// retry for free.
func (t *TikHubClient) postJSON(ctx context.Context, path string, payload map[string]any, out any) (cacheURL string, err error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.base+path, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+t.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://tikhub.io/")
	resp, err := t.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("tikhub request failed")
	}
	defer resp.Body.Close()
	raw := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if err != nil {
			break
		}
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("tikhub HTTP %d: %s", resp.StatusCode, string(trunc(raw, 300)))
	}
	var wrapped struct {
		Code     int             `json:"code"`
		Data     json.RawMessage `json:"data"`
		MsgZH    string          `json:"message_zh"`
		CacheURL string          `json:"cache_url"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return "", fmt.Errorf("tikhub decode: %w", err)
	}
	if wrapped.Code != 200 {
		return "", fmt.Errorf("tikhub code %d: %s", wrapped.Code, wrapped.MsgZH)
	}
	if out != nil && len(wrapped.Data) > 0 && string(wrapped.Data) != "null" {
		if err := json.Unmarshal(wrapped.Data, out); err != nil {
			return "", fmt.Errorf("tikhub data decode: %w", err)
		}
	}
	return wrapped.CacheURL, nil
}

func trunc(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// WeChatArticle is one 公众号 search hit.
type WeChatArticle struct {
	Title   string `json:"title"`
	Source  string `json:"source"` // official-account display name
	DocURL  string `json:"doc_url"`
	DocID   string `json:"doc_id"`
	Publish string `json:"publish"`
}

// WeChatSearch searches 公众号 articles via 微信搜一搜. WeChat's search is
// flaky (often returns nothing), so it retries until it gets a non-empty page
// or the retry budget is exhausted. An empty final result is an error — the
// agent must NOT invent an article URL from nothing.
func (t *TikHubClient) WeChatSearch(ctx context.Context, keyword string) ([]WeChatArticle, error) {
	payload := map[string]any{"keyword": keyword}
	var lastHits []WeChatArticle
	var cacheURL string
	// WeChat search mixes 视频号 (no doc_url) and 公众号 items; hit rate per
	// call is low. First attempt is a paid API call; subsequent retries reuse
	// TikHub's free 24h cache URL so repeated probing costs nothing.
	for attempt := 0; attempt < 6; attempt++ {
		var data struct {
			Results struct {
				Data []struct {
					Items []struct {
						Title    string `json:"title"`
						Source   struct {
							Title string `json:"title"`
						} `json:"source"`
						DocURL   string `json:"doc_url"`
						DocID    string `json:"docID"`
						DateTime string `json:"dateTime"`
					} `json:"items"`
				} `json:"data"`
			} `json:"results"`
		}
		var err error
		if cacheURL == "" {
			cacheURL, err = t.postJSON(ctx, "/api/v1/wechat_search/v2/fetch_search", payload, &data)
		} else {
			// free retry through cache
			var raw []byte
			raw, err = t.cacheURL(ctx, cacheURL)
			if err == nil {
				err = json.Unmarshal(raw, &data)
			}
		}
		if err != nil {
			return nil, err
		}
		hits := lastHits[:0]
		seen := map[string]bool{}
		for _, sub := range data.Results.Data {
			for _, it := range sub.Items {
				url := it.DocURL
				if url == "" || seen[url] {
					continue
				}
				seen[url] = true
				hits = append(hits, WeChatArticle{
					Title:   stripHighlight(it.Title),
					Source:  it.Source.Title,
					DocURL:  url,
					DocID:   it.DocID,
					Publish: it.DateTime,
				})
			}
		}
		lastHits = hits
		if len(hits) > 0 {
			return hits, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("微信搜索未返回结果（接口不稳定），请换关键词或稍后重试")
}

func stripHighlight(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '<' {
			for i < len(s) && s[i] != '>' {
				i++
			}
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// WeChatArticleDetail is the full article content.
type WeChatArticleDetail struct {
	URL        string `json:"url"`
	Title      string `json:"title"`
	Author     string `json:"author"`
	Nickname   string `json:"nickname"`
	CreateTime string `json:"create_time"`
	Content    string `json:"content"` // plain text body
}

// WeChatArticleDetail fetches a 公众号 article's full text by its mp.weixin
// URL. Already-downloaded articles are served from the local disk cache
// (free + fast); otherwise it calls TikHub ($0.01) and caches the result.
func (t *TikHubClient) WeChatArticleDetail(ctx context.Context, url string) (WeChatArticleDetail, error) {
	var out WeChatArticleDetail
	t.mu.Lock()
	if det, ok := t.artCache[url]; ok {
		t.mu.Unlock()
		return det, nil
	}
	t.mu.Unlock()

	var data struct {
		URL     string `json:"url"`
		Content struct {
			Title       string `json:"title"`
			Author      string `json:"author"`
			NickName    string `json:"nick_name"`
			UserName    string `json:"user_name"`
			CreateTime  string `json:"create_time"`
			ContentText string `json:"content_text"`
		} `json:"content"`
	}
	if _, err := t.postJSON(ctx, "/api/v1/wechat_mp/v2/fetch_article_detail",
		map[string]any{"url": url, "raw": false}, &data); err != nil {
		return out, err
	}
	nick := data.Content.NickName
	if nick == "" {
		nick = data.Content.UserName
	}
	out = WeChatArticleDetail{
		URL:        data.URL,
		Title:      data.Content.Title,
		Author:     data.Content.Author,
		Nickname:   nick,
		CreateTime: data.Content.CreateTime,
		Content:    data.Content.ContentText,
	}
	if out.Title != "" && len(out.Content) > 0 {
		t.saveCache(url, out)
	}
	return out, nil
}
