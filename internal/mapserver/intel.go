package mapserver

import (
	"regexp"
	"sort"
	"strings"
)

// PageIntel is the structured mapping intel extracted from a live page:
// title, API endpoints, technology fingerprints, exposure paths and
// login/register entry points (which can be clicked interactively).
type PageIntel struct {
	Title        string       `json:"title"`
	APIS         []string     `json:"apis"`
	Fingerprints []string     `json:"fingerprints"`
	Exposures    []string     `json:"exposures"`
	Entrypoints  []Entrypoint `json:"entrypoints"`
}

// Entrypoint is a login/register door on the page. Selector can be handed to
// /api/live/interact to actually click it in the live browser.
type Entrypoint struct {
	Type     string `json:"type"`              // login | register
	Label    string `json:"label"`             // human text, e.g. "登录", "Sign in"
	Selector string `json:"selector"`          // CSS selector (best-effort unique)
	URL      string `json:"url,omitempty"`     // href of the door link, if any
	Action   string `json:"action,omitempty"`  // form action, if any
	Method   string `json:"method,omitempty"`  // form method, if any
}

var (
	reAPIQuoted   = regexp.MustCompile(`["'](/[A-Za-z0-9_\-./]{2,}(?:api|v\d+)[A-Za-z0-9_\-./?=&]*?)["']`)
	reAPIAbs      = regexp.MustCompile(`["'](https?://[^"'\s]+(?:/api/|/v\d+/)[^"'\s]*)["']`)
	reFetchCall   = regexp.MustCompile(`fetch\(\s*["']([^"']+)["']`)
	reAxiosCall   = regexp.MustCompile(`axios\.(?:get|post|put|patch|delete)\(\s*["']([^"']+)["']`)
	reJQueryURL   = regexp.MustCompile(`url\s*:\s*["']([^"']+)["']`)
	reGenMeta     = regexp.MustCompile(`<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	reScriptSrc   = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	reLinkHref    = regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]{0,40})</a>`)
	reFormAction  = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["'][^>]*method=["']([^"']*)["']`)
	rePasswordIn  = regexp.MustCompile(`(?i)<input[^>]+type=["']password["']`)
	reFormLogin   = regexp.MustCompile(`(?i)<form[^>]+action=["'][^"']*(?:login|signin|auth|sso|passport)[^"']*["']`)
)

// simple fingerprint signature table: substring (case-insensitive) -> label.
var fingerprintSignatures = []struct {
	needle string
	label  string
}{
	{"wp-content", "WordPress"},
	{"wp-includes", "WordPress"},
	{"thinkphp", "ThinkPHP"},
	{"laravel", "Laravel"},
	{"drupal", "Drupal"},
	{"joomla", "Joomla"},
	{"shiro", "Apache Shiro"},
	{"spring boot", "Spring Boot"},
	{"struts2", "Apache Struts2"},
	{"vue.js", "Vue.js"},
	{"__vue__", "Vue.js"},
	{"react", "React"},
	{"angular", "Angular"},
	{"jquery", "jQuery"},
	{"bootstrap", "Bootstrap"},
	{"element-ui", "Element UI"},
	{"elementplus", "Element Plus"},
	{"layui", "Layui"},
	{"ant design", "Ant Design"},
	{"echarts", "ECharts"},
	{"nginx", "Nginx"},
	{"apache", "Apache"},
	{"tomcat", "Apache Tomcat"},
	{"iis", "IIS"},
	{"宝塔", "宝塔面板"},
	{"bt.cn", "宝塔面板"},
	{"phpmyadmin", "phpMyAdmin"},
	{"wordfence", "Wordfence WAF"},
	{"cloudflare", "Cloudflare"},
	{"recaptcha", "reCAPTCHA"},
	{"hcaptcha", "hCaptcha"},
	{"geetest", "极验验证码"},
	{"oss-", "阿里云 OSS"},
	{"qcloud", "腾讯云"},
	{"aliyun", "阿里云"},
	{"openai", "OpenAI"},
	{"deepseek", "DeepSeek"},
	{"anthropic", "Anthropic"},
	{"qwen", "通义千问"},
	{"minio", "MinIO"},
	{"swagger", "Swagger API"},
	{"openapi", "OpenAPI"},
	{"graphql", "GraphQL"},
}

// sensitive exposure paths that indicate an exposed surface when present in
// links, forms or scripts (path fragment matched).
var exposurePathFragments = []string{
	"/admin", "/manage", "/manager", "/console", "/backend", "/system",
	"/login", "/signin", "/auth", "/config", "/settings", "/debug",
	"/phpinfo", "/phpmyadmin", "/wp-admin", "/wp-login", "/.env",
	"/actuator", "/swagger", "/api-docs", "/graphql", "/server-status",
	"/robots.txt", "/sitemap.xml", "/.git", "/.svn", "/backup", "/dump",
	"/upload", "/files", "/download", "/webroot", "/shell",
}

// AnalyzePage turns a page's outerHTML into structured mapping intel.
func AnalyzePage(html, pageURL string) PageIntel {
	low := strings.ToLower(html)
	intel := PageIntel{
		APIS:         []string{},
		Fingerprints: []string{},
		Exposures:    []string{},
		Entrypoints:  []Entrypoint{},
	}

	// Title: prefer <title>, fall back to meta og:title.
	if m := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`).FindStringSubmatch(html); len(m) > 1 {
		intel.Title = strings.TrimSpace(stripTags(m[1]))
	}
	if intel.Title == "" {
		if m := regexp.MustCompile(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']`).FindStringSubmatch(html); len(m) > 1 {
			intel.Title = strings.TrimSpace(m[1])
		}
	}

	// API endpoints: from quoted paths, absolute URLs, fetch/axios/$ajax calls.
	seen := map[string]bool{}
	addAPI := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		// ignore pure asset files
		if strings.Contains(u, ".css") || strings.Contains(u, ".js") ||
			strings.Contains(u, ".png") || strings.Contains(u, ".jpg") ||
			strings.Contains(u, ".svg") || strings.Contains(u, ".woff") ||
			strings.Contains(u, ".ico") || strings.Contains(u, ".gif") {
			return
		}
		seen[u] = true
		intel.APIS = append(intel.APIS, u)
	}
	for _, re := range []*regexp.Regexp{reAPIAbs, reFetchCall, reAxiosCall, reJQueryURL} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			if len(m) > 1 {
				addAPI(m[1])
			}
		}
	}
	for _, m := range reAPIQuoted.FindAllStringSubmatch(html, -1) {
		if len(m) > 1 {
			addAPI(m[1])
		}
	}
	sort.Strings(intel.APIS)
	if len(intel.APIS) > 30 {
		intel.APIS = intel.APIS[:30]
	}

	// Fingerprints: generator meta + signature table.
	fpSeen := map[string]bool{}
	addFP := func(label string) {
		if label == "" || fpSeen[label] {
			return
		}
		fpSeen[label] = true
		intel.Fingerprints = append(intel.Fingerprints, label)
	}
	if m := reGenMeta.FindStringSubmatch(html); len(m) > 1 {
		addFP(strings.TrimSpace(m[1]))
	}
	for _, sig := range fingerprintSignatures {
		if strings.Contains(low, sig.needle) {
			addFP(sig.label)
		}
	}
	sort.Strings(intel.Fingerprints)

	// Exposures: sensitive path fragments found in the page.
	expSeen := map[string]bool{}
	for _, frag := range exposurePathFragments {
		if strings.Contains(low, frag) {
			expSeen[frag] = true
		}
	}
	for k := range expSeen {
		intel.Exposures = append(intel.Exposures, k)
	}
	sort.Strings(intel.Exposures)

	// Entry points: login / register doors with best-effort selectors.
	intel.Entrypoints = detectEntrypoints(html)

	return intel
}

func detectEntrypoints(html string) []Entrypoint {
	eps := []Entrypoint{}
	seen := map[string]bool{}
	add := func(ep Entrypoint) {
		key := ep.Type + "|" + ep.Selector
		if seen[key] {
			return
		}
		seen[key] = true
		eps = append(eps, ep)
	}
	low := strings.ToLower(html)

	// 1. Password input → login door. Lightpanda's querySelector is limited
	// (attribute selectors like input[type=...] break its evaluator), so we
	// target the first form — clicking it focuses the login area.
	if rePasswordIn.MatchString(html) {
		sel := "form"
		action, method := "", ""
		if m := reFormAction.FindStringSubmatch(html); len(m) > 1 {
			action, method = m[1], m[2]
		}
		add(Entrypoint{Type: "login", Label: "登录表单（含密码框）", Selector: sel, Action: action, Method: method})
	}
	if m := reFormLogin.FindStringSubmatch(html); len(m) > 0 {
		add(Entrypoint{Type: "login", Label: "登录表单", Selector: "form[action*='login'], form[action*='signin'], form[action*='auth']"})
	}

	// 2. Links / buttons whose text or href smells like login / register.
	for _, m := range reLinkHref.FindAllStringSubmatch(html, -1) {
		if len(m) < 3 {
			continue
		}
		href, text := m[1], strings.TrimSpace(stripTags(m[2]))
		hl, tl := strings.ToLower(href), strings.ToLower(text)
		kind := ""
		switch {
		case strings.Contains(hl, "login") || strings.Contains(hl, "signin") ||
			strings.Contains(hl, "auth") || strings.Contains(tl, "登录") ||
			strings.Contains(tl, "登入") || strings.Contains(tl, "sign in") ||
			strings.Contains(tl, "signin"):
			kind = "login"
		case strings.Contains(hl, "register") || strings.Contains(hl, "signup") ||
			strings.Contains(tl, "注册") || strings.Contains(tl, "sign up") ||
			strings.Contains(tl, "signup") || strings.Contains(tl, "join"):
			kind = "register"
		}
		if kind == "" {
			continue
		}
		label := text
		if label == "" {
			label = href
		}
		// Use TEXT: search (reliable in Lightpanda) rather than attribute
		// selectors like a[href*='login'], which its evaluator rejects.
		sel := "TEXT:" + label
		if text == "" {
			// No visible text: can't text-search; fall back to clicking the
			// first form if present, otherwise skip (user can open the link
			// from the Links tab).
			continue
		}
		add(Entrypoint{Type: kind, Label: label, Selector: sel, URL: href})
	}

	// 3. Generic buttons with login/register text (no href).
	if strings.Contains(low, "注册") || strings.Contains(low, "sign up") {
		add(Entrypoint{Type: "register", Label: "注册入口", Selector: "TEXT:注册"})
	}
	if strings.Contains(low, "登录") || strings.Contains(low, "登入") {
		add(Entrypoint{Type: "login", Label: "登录入口", Selector: "TEXT:登录"})
	}
	return eps
}

var reTags = regexp.MustCompile(`(?s)<[^>]+>`)

func stripTags(s string) string {
	return strings.TrimSpace(reTags.ReplaceAllString(s, " "))
}
