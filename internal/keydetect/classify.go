package keydetect

import "strings"

// providerKeywords maps a lowercase context keyword to a provider name for
// classifying entropy hits (which have no recognizable shape of their own).
var providerKeywords = []struct {
	keyword  string
	provider string
}{
	{"deepseek", "DeepSeek"},
	{"dashscope", "阿里云百炼"},
	{"openai", "OpenAI"},
	{"zhipu", "智谱"},
	{"moonshot", "月之暗面 Kimi"},
	{"kimi", "月之暗面 Kimi"},
	{"qianfan", "百度千帆"},
	{"hunyuan", "腾讯混元"},
	{"minimax", "MiniMax"},
	{"volcengine", "火山引擎方舟"},
	{"siliconflow", "硅基流动"},
	{"anthropic", "Anthropic"},
}

// classify attributes a provider by scanning nearby context for known keywords.
// Returns "" when no keyword matches.
func classify(token, content string, offset int) string {
	lo := offset - 128
	if lo < 0 {
		lo = 0
	}
	hi := offset + len(token) + 128
	if hi > len(content) {
		hi = len(content)
	}
	ctx := strings.ToLower(content[lo:hi])
	for _, k := range providerKeywords {
		if strings.Contains(ctx, k.keyword) {
			return k.provider
		}
	}
	return ""
}
