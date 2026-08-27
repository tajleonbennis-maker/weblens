package aiassets

import (
	"context"
	"fmt"
	"github.com/tajleonbennis-maker/weblens/internal/keydetect"
	"github.com/tajleonbennis-maker/weblens/internal/lightpanda"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	maxPageBytes   = 2 << 20
	maxScriptBytes = 1 << 20
	maxScripts     = 8
)

type Scanner struct {
	Client         *http.Client
	LightpandaAddr string
	Dynamic        bool
}

func NewScanner(lp string, dynamic bool) *Scanner {
	s := &Scanner{LightpandaAddr: lp, Dynamic: dynamic}
	c := &http.Client{Timeout: 20 * time.Second}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return fmt.Errorf("too many redirects")
		}
		return validatePublicURL(r.Context(), r.URL)
	}
	s.Client = c
	return s
}
func (s *Scanner) Scan(ctx context.Context, c Candidate) Asset {
	a := Asset{AssetURL: c.URL, DiscoveredBy: c.DiscoveredBy, CollectedAt: time.Now().UTC()}
	u, err := url.Parse(c.URL)
	if err != nil || u.Hostname() == "" {
		a.Error = "invalid URL"
		return a
	}
	if err = validatePublicURL(ctx, u); err != nil {
		a.Error = err.Error()
		return a
	}
	a.Origin = u.Scheme + "://" + u.Host
	body, status, finalURL, headers, err := s.fetch(ctx, c.URL, maxPageBytes)
	if err != nil {
		a.Error = err.Error()
		return a
	}
	a.Reachable = true
	a.HTTPStatus = status
	a.FinalURL = finalURL
	a.StaticBytes = int64(len(body))
	static := headers + "\n" + string(body)
	a.Blocked = LooksBlocked(static, status)
	a.Title = pageTitle(string(body))
	if !isHTTPSuccess(status) {
		a.Error = fmt.Sprintf("HTTP %d", status)
		a.Technologies, a.Models, a.AIChat = Fingerprint(static)
		a.KeyExposures = dedupeExposures(findExposures(static, finalURL))
		return a
	}
	a.ResourceURLs = scriptURLs(finalURL, string(body), maxScripts)
	combined := static
	for _, resource := range a.ResourceURLs {
		script, resourceStatus, _, _, e := s.fetch(ctx, resource, maxScriptBytes)
		if e != nil || !isHTTPSuccess(resourceStatus) {
			continue
		}
		combined += "\n" + string(script)
		a.KeyExposures = append(a.KeyExposures, findExposures(string(script), resource)...)
	}
	a.KeyExposures = append(a.KeyExposures, findExposures(static, finalURL)...)
	if s.Dynamic && !a.Blocked && s.LightpandaAddr != "" {
		lp, e := lightpanda.Connect(ctx, s.LightpandaAddr)
		if e == nil {
			rendered, re := lp.Render(ctx, finalURL)
			if re == nil {
				a.DynamicBytes = int64(len(rendered))
				a.Blocked = LooksBlocked(rendered, status)
				combined += "\n" + rendered
				for _, f := range keydetect.Detect(rendered) {
					a.KeyExposures = append(a.KeyExposures, exposureFromFinding(f, finalURL+"#rendered"))
				}
				// 整页能力：交互触发后再检测（懒加载的设置面板/菜单常藏 key）
				interacted := lp.Interact(ctx)
				if interacted != "" && interacted != rendered {
					combined += "\n" + interacted
					for _, f := range keydetect.Detect(interacted) {
						a.KeyExposures = append(a.KeyExposures, exposureFromFinding(f, finalURL+"#interacted"))
					}
				}
				// 整页能力：读取 localStorage/sessionStorage/cookies 中的 key
				snap, se := lp.Storage(ctx)
				if se == nil {
					for k, v := range snap.LocalStorage {
						for _, f := range keydetect.Detect(k + "=" + v) {
							a.KeyExposures = append(a.KeyExposures, exposureFromFinding(f, finalURL+"#localStorage"))
						}
					}
					for k, v := range snap.SessionStorage {
						for _, f := range keydetect.Detect(k + "=" + v) {
							a.KeyExposures = append(a.KeyExposures, exposureFromFinding(f, finalURL+"#sessionStorage"))
						}
					}
					for k, v := range snap.Cookies {
						if isSensitiveCookie(k, v) {
							a.KeyExposures = append(a.KeyExposures, exposureFromFinding(keydetect.Finding{
								Kind: "rule", MaskedKey: maskValue(v), Fingerprint: keydetect.Fingerprint(v),
								Confidence: "medium", Context: "cookie " + k + "=" + maskValue(v),
							}, finalURL+"#cookie"))
						}
					}
				}
				// 整页能力：捕获页面加载时所有 API/配置响应体（登录后可见的 key）
				nb, ne := lp.NetworkCapture(ctx, finalURL, maxConfigEndpointBytes)
				if ne == nil {
					for _, n := range nb {
						for _, f := range keydetect.Detect(n.Body) {
							a.KeyExposures = append(a.KeyExposures, exposureFromFinding(f, n.URL))
						}
					}
				}
			}
			_ = lp.Close()
		}
	}
	a.Technologies, a.Models, a.AIChat = Fingerprint(combined)
	a.KeyExposures = append(a.KeyExposures, s.probeConfigEndpoints(ctx, finalURL, a.Technologies)...)
	a.KeyExposures = dedupeExposures(a.KeyExposures)
	return a
}

// cookieNoiseNames are cookie names that frequently appear in the wild but are
// session bookkeeping / CSRF protection / localization, not credentials.
// Matching one of these excludes the cookie from exposure reporting.
var cookieNoiseNames = []string{
	"csrftoken", "csrf_token", "xsrf-token", "xsrf_token", "x-cache-key", "xcachekey", "x_cache_key", "cache_key",
	"lang", "locale", "language", "theme", "theme-type", "color-scheme",
	"cookie_consent", "cookieconsent", "gdpr", "is_home", "ishome", "home",
	"phpsessid-visited", "visited", "first_visit", "referrer", "utm_source",
	"has_js", "js_enabled", "sessionid_short", "sentry-session", "sentrysession",
}

// isSensitiveCookie reports whether a cookie name hints at credentials that
// would be valuable to an attacker if exposed (auth/session/API tokens). It
// excludes known noise names (CSRF tokens, localization, cache keys) and
// requires the value to be reasonably long, since real credentials are
// high-entropy strings rather than short flags.
func isSensitiveCookie(name, value string) bool {
	low := strings.ToLower(name)
	for _, n := range cookieNoiseNames {
		if strings.Contains(low, n) {
			return false
		}
	}
	if len(value) < 12 {
		return false
	}
	for _, frag := range []string{"token", "session", "auth", "api", "key", "jwt", "access", "secret"} {
		if strings.Contains(low, frag) {
			return true
		}
	}
	return false
}

// maskValue redacts a candidate secret value, mirroring keydetect.Mask.
func maskValue(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:3] + "****" + v[len(v)-4:]
}

func isHTTPSuccess(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func findExposures(content, location string) []Exposure {
	findings := keydetect.Detect(content)
	out := make([]Exposure, 0, len(findings))
	for _, f := range findings {
		out = append(out, exposureFromFinding(f, location))
	}
	return out
}

// platformConfigEndpoints maps a recognized platform (matched against the
// fingerprint Technology.Name) to its well-known configuration endpoints.
// Endpoints are probed with a lightweight GET; only JSON-ish 200 responses are
// scanned for key exposures. Different AI platforms expose provider keys on
// different paths, so the probe list is platform-aware.
var platformConfigEndpoints = []struct {
	match string   // substring of Technology.Name to match against
	eps   []string // candidate endpoint paths for that platform
}{
	// FastAPI-style AI backends (DeepTutor and similar) return the full
	// provider catalog with credentials on /api/v1/settings.
	{"", []string{"/api/v1/settings", "/api/v1/config", "/api/settings", "/api/config"}},
	// LibreChat exposes its configuration (including model/LLM provider
	// settings) under /api/config.
	{"LibreChat", []string{"/api/config", "/api/auth/session"}},
	// Open WebUI serves front-end configuration from /api/config.
	{"Open WebUI", []string{"/api/config", "/api/v1/config"}},
	// Dify console setup endpoint can reveal admin state and backend config.
	{"Dify", []string{"/console/api/setup", "/api/console/api/setup", "/api/v1/config"}},
	// LobeChat is a Next.js app; configuration mostly lives in chunks, but the
	// /api/config path is cheap to probe.
	{"LobeChat", []string{"/api/config"}},
}

const maxConfigEndpointBytes = 512 << 10 // 512 KiB per endpoint response

// probeConfigEndpoints fetches known config endpoints on the same origin and
// scans their JSON responses for leaked keys. The endpoint list is chosen by
// the recognized platform (technologies); the generic FastAPI list always runs
// as a fallback. It is intentionally best-effort: failures are ignored, and
// probing stops at the first endpoint that yields an exposure to bound volume.
func (s *Scanner) probeConfigEndpoints(ctx context.Context, origin string, technologies []Technology) []Exposure {
	var out []Exposure
	u, err := url.Parse(origin)
	if err != nil {
		return out
	}

	// Build the ordered, de-duplicated probe list: platform-specific first,
	// then the generic fallback list.
	var eps []string
	seen := map[string]bool{}
	for _, tec := range technologies {
		for _, pe := range platformConfigEndpoints {
			if pe.match == "" {
				continue
			}
			if strings.Contains(tec.Name, pe.match) {
				for _, ep := range pe.eps {
					if !seen[ep] {
						seen[ep] = true
						eps = append(eps, ep)
					}
				}
			}
		}
	}
	for _, ep := range platformConfigEndpoints[0].eps { // generic fallback
		if !seen[ep] {
			seen[ep] = true
			eps = append(eps, ep)
		}
	}

	for _, ep := range eps {
		body, status, _, _, err := s.fetch(ctx, u.Scheme+"://"+u.Host+ep, maxConfigEndpointBytes)
		if err != nil || !isHTTPSuccess(status) {
			continue
		}
		trimmed := strings.TrimSpace(string(body))
		if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
			continue // not a JSON payload; skip
		}
		loc := origin + ep
		found := findExposures(trimmed, loc)
		if len(found) > 0 {
			out = append(out, found...)
			break // first endpoint with an exposure is enough
		}
	}
	return out
}
func (s *Scanner) fetch(ctx context.Context, raw string, limit int64) ([]byte, int, string, string, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return nil, 0, raw, "", e
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WebLensAssetResearch/1.0; +https://github.com/tajleonbennis-maker/weblens)")
	resp, e := s.Client.Do(req)
	if e != nil {
		return nil, 0, raw, "", e
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, resp.StatusCode, resp.Request.URL.String(), "", e
	}
	if int64(len(body)) > limit {
		body = body[:limit]
	}
	var h strings.Builder
	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "set-cookie" || lk == "authorization" || lk == "x-api-key" {
			continue
		}
		fmt.Fprintf(&h, "%s: %s\n", k, strings.Join(v, ","))
	}
	return body, resp.StatusCode, resp.Request.URL.String(), h.String(), nil
}
func validatePublicURL(ctx context.Context, u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme")
	}
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", u.Hostname())
	if e != nil {
		return fmt.Errorf("resolve: %w", e)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return fmt.Errorf("private or local address refused")
		}
	}
	return nil
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var scriptRE = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)

func pageTitle(html string) string {
	m := titleRE.FindStringSubmatch(html)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(m[1], ""))
}
func scriptURLs(baseURL, html string, limit int) []string {
	base, e := url.Parse(baseURL)
	if e != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range scriptRE.FindAllStringSubmatch(html, -1) {
		u, e := base.Parse(strings.TrimSpace(m[1]))
		if e != nil || u.Hostname() != base.Hostname() {
			continue
		}
		if (u.Scheme == "http" || u.Scheme == "https") && !seen[u.String()] {
			seen[u.String()] = true
			out = append(out, u.String())
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}
func dedupeExposures(in []Exposure) []Exposure {
	seen := map[string]bool{}
	var out []Exposure
	for _, e := range in {
		if e.Fingerprint != "" && !seen[e.Fingerprint] {
			seen[e.Fingerprint] = true
			out = append(out, e)
		}
	}
	return out
}
