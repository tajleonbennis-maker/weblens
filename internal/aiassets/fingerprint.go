package aiassets

import "strings"

type signature struct {
	name, category string
	needles        []string
}

var technologySignatures = []signature{
	{"Open WebUI", "ai-web", []string{"open webui", "open-webui", "/api/v1/auths"}}, {"Dify", "ai-web", []string{"dify", "x-app-code"}}, {"LobeChat", "ai-web", []string{"lobechat", "lobe-chat"}},
	{"LibreChat", "ai-web", []string{"librechat", "/api/agents"}}, {"ChatGPT Next Web", "ai-web", []string{"chatgpt-next-web", "nextchat"}}, {"Gradio", "ai-web", []string{"gradio_config", "gradio-app"}},
	{"Streamlit", "framework", []string{"streamlit", "_stcore"}}, {"Next.js", "framework", []string{"__next_data__", "/_next/static/"}}, {"Nuxt", "framework", []string{"__nuxt__", "/_nuxt/"}},
	{"React", "framework", []string{"react-dom", "data-reactroot"}}, {"Vue", "framework", []string{"vue.js", "data-v-"}}, {"Svelte", "framework", []string{"svelte", "/_app/immutable/"}},
	{"Vite", "build-tool", []string{"/@vite/", "vite.svg"}}, {"Cloudflare", "cdn-waf", []string{"cf-ray", "cloudflare"}}, {"Vercel", "hosting", []string{"x-vercel-id", "vercel.app"}},
}
var modelSignatures = []struct {
	provider string
	models   []string
}{
	{"OpenAI", []string{"gpt-4o", "gpt-4.1", "gpt-3.5", "openai"}}, {"Anthropic", []string{"claude-3", "claude sonnet", "anthropic"}}, {"Google", []string{"gemini-", "google generative ai"}},
	{"DeepSeek", []string{"deepseek-chat", "deepseek-reasoner", "deepseek"}}, {"Alibaba Qwen", []string{"qwen-", "通义千问", "dashscope"}}, {"Zhipu GLM", []string{"glm-4", "chatglm", "智谱"}},
	{"Meta Llama", []string{"llama-3", "meta-llama"}}, {"Mistral", []string{"mistral-", "mixtral-"}}, {"Ollama", []string{"ollama", "/api/tags"}}, {"vLLM", []string{"vllm", "x-vllm"}},
}

func Fingerprint(content string) ([]Technology, []Model, bool) {
	lower := strings.ToLower(content)
	var tech []Technology
	var models []Model
	for _, s := range technologySignatures {
		for _, n := range s.needles {
			if strings.Contains(lower, strings.ToLower(n)) {
				tech = append(tech, Technology{Name: s.name, Category: s.category, Confidence: 85, Evidence: []Evidence{{Source: "content", Detail: "matched " + n}}})
				break
			}
		}
	}
	for _, s := range modelSignatures {
		for _, n := range s.models {
			if strings.Contains(lower, strings.ToLower(n)) {
				models = append(models, Model{Provider: s.provider, Model: n, Confidence: 75, Status: "observed", Evidence: []Evidence{{Source: "content", Detail: "matched " + n}}})
				break
			}
		}
	}
	chat := len(models) > 0
	for _, t := range tech {
		if t.Category == "ai-web" {
			chat = true
		}
	}
	if !chat {
		hits := 0
		for _, w := range []string{"chat", "assistant", "prompt", "model", "对话", "聊天", "发送消息"} {
			if strings.Contains(lower, w) {
				hits++
			}
		}
		chat = hits >= 2
	}
	return tech, models, chat
}
func LooksBlocked(content string, status int) bool {
	if status == 401 || status == 403 || status == 405 || status == 429 {
		return true
	}
	lower := strings.ToLower(content)
	for _, m := range []string{"request has been blocked", "access denied", "captcha", "访问被拒绝", "请求被拦截", "potential threats to the server"} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}
