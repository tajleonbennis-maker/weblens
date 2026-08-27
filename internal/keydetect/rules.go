package keydetect

import "regexp"

// rule is a provider key pattern. When group > 0, the finding is the named
// submatch group instead of the whole match (used to strip a "Bearer " prefix).
type rule struct {
	name       string
	provider   string
	re         *regexp.Regexp
	group      int
	confidence string
}

// rules holds the shape-based provider patterns. These cover the most common
// AI / cloud / SaaS key formats. This list is the extension point for
// provider-specific rules (e.g. the SecretWatcher provider rule set).
var rules = []rule{
	{name: "openai_sk", provider: "OpenAI", re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,48}\b`), confidence: "high"},
	{name: "anthropic_sk", provider: "Anthropic", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9-]{20,}\b`), confidence: "high"},
	{name: "aws_access_key_id", provider: "AWS", re: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), confidence: "high"},
	{name: "google_api_key", provider: "Google", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), confidence: "high"},
	{name: "github_token", provider: "GitHub", re: regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`), confidence: "high"},
	{name: "nvidia_nim", provider: "NVIDIA NIM", re: regexp.MustCompile(`\bnvapi-[A-Za-z0-9]{20,}\b`), confidence: "high"},
	{name: "slack_token", provider: "Slack", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), confidence: "high"},
	{name: "deepseek_sk", provider: "DeepSeek", re: regexp.MustCompile(`\bsk-[0-9a-f]{32}\b`), confidence: "high"},
	{name: "volcengine_ark", provider: "火山引擎方舟", re: regexp.MustCompile(`\bsk-ws-[A-Za-z0-9-]{20,}\b`), confidence: "high"},
	{name: "zhipu_glm", provider: "智谱", re: regexp.MustCompile(`\b[a-f0-9]{8}\.[A-Za-z0-9]{32,}\b`), confidence: "medium"},
	{name: "moonshot_kimi", provider: "月之暗面 Kimi", re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), confidence: "medium"},
	{name: "qwen_dashscope", provider: "阿里云百炼", re: regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`), confidence: "medium"},
	{name: "generic_bearer", provider: "", re: regexp.MustCompile(`(?i)\bBearer[ \t]+([A-Za-z0-9._-]{20,})`), group: 1, confidence: "medium"},
}
