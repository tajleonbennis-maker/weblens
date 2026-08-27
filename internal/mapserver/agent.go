package mapserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tajleonbennis-maker/weblens/internal/aiassets"
)

// AgentPlan is the JSON object the LLM returns: a bounded sequence of actions
// to run against the live session, plus an optional immediate answer.
type AgentPlan struct {
	Actions []AgentAction `json:"actions"`
	Answer  string        `json:"answer,omitempty"`
	Note    string        `json:"note,omitempty"`
}

// AgentAction is one step the agent executes on the live Lightpanda session.
//   - op=scroll   dy>0 down / dy<0 up
//   - op=interact selector is a CSS selector or "TEXT:<label>" search; clicks
//     the located element in the real browser
//   - op=snapshot re-capture DOM + mapping intel
//   - op=fofa     query a FOFA asset search (e.g. 宝塔面板); returns total+sample
//   - op=tikhub   query closed social platforms via TikHub:
//     kind=mp_search keyword=... -> search 公众号 articles
//     kind=mp_detail url=...     -> fetch a 公众号 article full text
type AgentAction struct {
	Op       string `json:"op"`
	Dy       int    `json:"dy,omitempty"`
	Selector string `json:"selector,omitempty"`
	Label    string `json:"label,omitempty"`
	Query    string `json:"query,omitempty"`
	Size     int    `json:"size,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Keyword  string `json:"keyword,omitempty"`
	URL      string `json:"url,omitempty"`
}

// agentSystemPrompt tells the LLM what it can do and the JSON contract.
const agentSystemPrompt = `你是 WebLens 交互式网络空间测绘平台的操作员。用户会用一句话描述想对某个网络资产（或网络空间）做的事情，你负责把它拆解成平台上可执行的动作序列。

平台可执行动作（只能使用这些）：
1. {"op":"scroll","dy":600} —— 页面向下滚动 600px；dy 为负向上滚动
2. {"op":"interact","selector":"form"} —— 在真实浏览器中点击某个元素。selector 必须是以下两种之一：
   - CSS 标签/ID/类选择器，如 "form"、"#password"（注意：不支持属性选择器如 a[href*='login']）
   - 文本搜索，如 "TEXT:登录"、"TEXT:Sign in"（会匹配 a/button 上包含该文字的可见元素）
3. {"op":"snapshot"} —— 重新抓取页面内容与测绘情报（标题/API/指纹/暴露点/入口）
4. {"op":"fofa","query":"宝塔面板","size":5} —— 用 FOFA 网络空间搜索引擎查询互联网上的资产数量。query 写 FOFA 语法（如 body="宝塔面板"、app="BaoTa-Panel"、title="Open WebUI"、ip="1.2.3.0/24"）。当用户提到"在 fofa.info / FOFA 上查 X"或"互联网上有多少 X 资产"时使用此动作。返回匹配总数和样例列表。
5. {"op":"tikhub","kind":"mp_search","keyword":"关键词"} —— 用 TikHub 搜索微信公众号文章（当用户提到"公众号文章 / 微信文章 / 某篇文章（微信）"或给出文章标题要下载时使用），返回匹配的文章标题、公众号名称和链接。注意：①微信搜索不稳定，一次可能返回空，可重试或换关键词；②**优先搜索公众号名称**（如果用户提到或可推断公众号名，搜公众号名命中率远高于搜标题）。
6. {"op":"tikhub","kind":"mp_detail","url":"mp.weixin.qq.com/s/..."} —— 用 TikHub 获取一篇微信公众号文章的完整正文（标题/作者/公众号/发布时间/全文）。**当用户要求"下载 / 获取 / 保存 / 看全文"某篇公众号文章时，这是唯一能拿到正文的途径**：必须先用 mp_search 找到文章的 doc_url，再对该 url 执行 mp_detail 获取全文，最后在回答中说明全文已获取、可点击下载按钮保存为 Markdown。

约束：
- 动作不超过 8 个，只规划必要步骤
- 若用户的需求在当前页面信息已足够回答，直接给出 answer，actions 可以为空数组
- 对当前打开的资产操作时，不要导航到无关网址；FOFA / TikHub 查询是独立动作，与当前页面无关
- 输出必须是合法 JSON：{"actions":[...], "answer":"（可选的直接回答）"}，不要输出 JSON 以外的内容`

// agentSummarizePrompt asks the LLM to turn the executed step log into a
// concise answer for the user.
const agentSummarizePrompt = `以下是 WebLens 测绘 Agent 针对用户请求执行的动作与结果。请用简体中文、简洁地总结：完成了什么、发现了什么（如指纹/API/暴露点/登录注册入口）、对用户有什么建议。若执行中有失败步骤，也如实说明。

用户请求：%s

执行记录：
%s`

// AskAgent runs a natural-language instruction, optionally against a live
// session:
// 1) if a session is given, capture current intel + visible text;
// 2) LLM parses into a bounded plan;
// 3) execute each action on the real browser (and FOFA when configured);
// 4) LLM summarizes the outcome.
// sess may be nil — then only fofa queries and plain answers are possible
// (scroll/interact/snapshot report "no asset open"). This powers the global
// task input on the landing view.
// It never forwards raw HTML to the model — only intel + truncated text.
// fofa / tikhub may be nil (the corresponding op then reports unavailable).
func (m *Manager) AskAgent(ctx context.Context, sess *Session, prompt string, llm *LLMClient, fofa *aiassets.FOFAClient, tikhub *TikHubClient) (map[string]any, error) {
	// --- 1. current state ------------------------------------------------
	var user string
	cur := ""
	if sess != nil {
		snap, err := sess.Snapshot(ctx, false)
		if err != nil {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
		intel, _ := snap["intel"].(PageIntel)
		html, _ := snap["html"].(string)
		cur, _ = snap["url"].(string)
		intelJSON, _ := json.Marshal(intel)
		text := plainText(html)
		if len(text) > 2500 {
			text = text[:2500]
		}
		user = fmt.Sprintf(`当前资产: %s
页面可见文本(截断): %s
当前测绘情报: %s
用户请求: %s`,
			cur, text, string(intelJSON), prompt)
	} else {
		user = fmt.Sprintf(`（当前没有打开任何资产。你只能：1) 使用 fofa 查询互联网上的资产（当用户提到 fofa / 查有多少 X 资产 / 互联网上有多少 X 时）；2) 直接回答通用问题；3) 如果用户想操作某个网页或下载某篇文章，请告诉用户提供一个 URL，并说明你可以用 URL 打开目标进行测绘。你无法使用 scroll / interact / snapshot。）
用户请求: %s`, prompt)
	}

	// --- 2. LLM parses the plan ------------------------------------------
	planRaw, err := llm.Chat(ctx, agentSystemPrompt, user, true)
	if err != nil {
		return nil, fmt.Errorf("llm plan: %w", err)
	}
	var plan AgentPlan
	if err := json.Unmarshal([]byte(planRaw), &plan); err != nil {
		// Try to salvage a JSON object embedded in the reply.
		if i := strings.IndexByte(planRaw, '{'); i >= 0 {
			if j := strings.LastIndexByte(planRaw, '}'); j > i {
				if err2 := json.Unmarshal([]byte(planRaw[i:j+1]), &plan); err2 == nil {
					err = nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("llm plan decode: %w: %s", err, planRaw[:min(len(planRaw), 200)])
		}
	}
	if len(plan.Actions) > 8 {
		plan.Actions = plan.Actions[:8]
	}

	// --- 3. execute actions ----------------------------------------------
	steps := []map[string]any{}
	noSess := func(a AgentAction) map[string]any {
		return map[string]any{"op": a.Op, "ok": false, "error": "当前未打开任何资产；如需操作网页请提供 URL"}
	}
	for _, a := range plan.Actions {
		step := map[string]any{"op": a.Op}
		switch a.Op {
		case "scroll":
			if sess == nil {
				step = noSess(a)
				break
			}
			if a.Dy == 0 {
				a.Dy = 400
			}
			if _, _, err := sess.Scroll(ctx, 0, a.Dy); err != nil {
				step["ok"] = false
				step["error"] = err.Error()
			} else {
				step["ok"] = true
				step["note"] = fmt.Sprintf("scroll %d", a.Dy)
			}
		case "interact":
			if sess == nil {
				step = noSess(a)
				break
			}
			if a.Selector == "" {
				step["ok"] = false
				step["error"] = "no selector"
				break
			}
			actCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			out, err := sess.Interact(actCtx, a.Selector)
			cancel()
			if err != nil {
				step["ok"] = false
				step["error"] = err.Error()
			} else {
				step["ok"] = true
				if cl, _ := out["clicked"].(map[string]any); cl != nil {
					step["clicked"] = cl
				}
				if ni, ok := out["intel"].(PageIntel); ok {
					step["intel"] = intelSummary(ni)
				}
			}
		case "snapshot":
			if sess == nil {
				step = noSess(a)
				break
			}
			ns, err := sess.Snapshot(ctx, false)
			if err != nil {
				step["ok"] = false
				step["error"] = err.Error()
			} else {
				step["ok"] = true
				if ni, ok := ns["intel"].(PageIntel); ok {
					step["intel"] = intelSummary(ni)
				}
			}
		case "fofa":
			if fofa == nil {
				step["ok"] = false
				step["error"] = "FOFA 未配置（服务端缺 FOFA_KEY）"
				break
			}
			q := strings.TrimSpace(a.Query)
			if q == "" {
				q = strings.TrimSpace(a.Label)
			}
			if q == "" {
				step["ok"] = false
				step["error"] = "no fofa query"
				break
			}
			sz := a.Size
			if sz < 1 || sz > 20 {
				sz = 5
			}
			fctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			defer cancel()
			total, sample, err := fofa.Count(fctx, q, sz)
			qUsed := q
			// FOFA error 820300 = app fingerprint name not recognized by this
			// account; retry with the body= form, which is widely supported.
			if err != nil && strings.Contains(err.Error(), "820300") && strings.HasPrefix(q, "app=") {
				alt := "body=" + q[len("app="):]
				time.Sleep(3 * time.Second)
				total, sample, err = fofa.Count(fctx, alt, sz)
				if err == nil {
					qUsed = alt
				}
			}
			// Rate limit / dropped connection: longer backoff, then retry the
			// best query form we have (never fall back to the failing app=).
			if err != nil && (strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "EOF") ||
				strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "45012") ||
				strings.Contains(err.Error(), "请求速度过快")) {
				time.Sleep(12 * time.Second)
				total, sample, err = fofa.Count(fctx, qUsed, sz)
			}
			step["query"] = qUsed
			if err != nil {
				step["ok"] = false
				step["error"] = err.Error()
			} else {
				step["ok"] = true
				step["query"] = q
				step["total"] = total
				step["sample"] = sample
			}
		case "tikhub":
			if tikhub == nil {
				step["ok"] = false
				step["error"] = "TikHub 未配置（服务端缺 TIKHUB_API_KEY）"
				break
			}
			tctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			switch a.Kind {
			case "mp_detail":
				u := strings.TrimSpace(a.URL)
				if u == "" {
					u = strings.TrimSpace(a.Query)
				}
				if u == "" {
					step["ok"] = false
					step["error"] = "no article url"
					break
				}
				// Normalize: the model may drop the scheme; TikHub requires
				// http(s)://mp.weixin.qq.com/...
				if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					u = "https://" + u
				}
				det, err := tikhub.WeChatArticleDetail(tctx, u)
				if err != nil {
					step["ok"] = false
					step["error"] = err.Error()
					break
				}
				step["ok"] = true
				step["kind"] = "mp_detail"
				step["title"] = det.Title
				step["author"] = det.Author
				step["nickname"] = det.Nickname
				step["create_time"] = det.CreateTime
				step["source_url"] = det.URL
				content := det.Content
				if len(content) > 20000 {
					content = content[:20000] + "\n…（全文过长已截断）"
				}
				step["content"] = content
				step["summary"] = det.Content
				if len(step["summary"].(string)) > 3000 {
					step["summary"] = det.Content[:3000]
				}
			case "mp_search", "":
				kw := strings.TrimSpace(a.Keyword)
				if kw == "" {
					kw = strings.TrimSpace(a.Query)
				}
				if kw == "" {
					kw = strings.TrimSpace(a.Label)
				}
				if kw == "" {
					step["ok"] = false
					step["error"] = "no search keyword"
					break
				}
				arts, err := tikhub.WeChatSearch(tctx, kw)
				if err != nil {
					step["ok"] = false
					step["error"] = err.Error()
					break
				}
				step["ok"] = true
				step["kind"] = "mp_search"
				step["count"] = len(arts)
				if len(arts) > 8 {
					arts = arts[:8]
				}
				step["items"] = arts
			default:
				step["ok"] = false
				step["error"] = "unknown tikhub kind " + a.Kind
			}
		default:
			step["ok"] = false
			step["error"] = "unknown op " + a.Op
		}
		steps = append(steps, step)
	}

	// --- 4. LLM summarizes the outcome ------------------------------------
	stepLog, _ := json.MarshalIndent(steps, "", "  ")
	sumCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	answer := plan.Answer
	if len(steps) > 0 {
		// Plain-text prompt here: we want prose, not JSON.
		sumSys := "你是 WebLens 交互式网络空间测绘助手。根据用户的请求和下方执行记录，用简体中文简洁自然地回答（150 字以内），说明完成了什么、发现了什么、有什么建议。直接输出正文，不要输出 JSON。"
		if sum, err := llm.Chat(sumCtx, sumSys,
			fmt.Sprintf(agentSummarizePrompt, prompt, string(stepLog)), false); err == nil {
			answer = sum
		}
	}
	if answer == "" {
		answer = "已完成请求中的操作，详见操作轨迹。"
	}

	return map[string]any{
		"answer": answer,
		"steps":  steps,
		"url":    cur,
		"plan":   plan.Actions,
	}, nil
}

func cleanAnswer(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '{'); i == 0 {
		return s
	}
	return s
}

func intelSummary(i PageIntel) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// plainText strips tags from HTML and collapses whitespace.
func plainText(html string) string {
	var b strings.Builder
	inTag := false
	for _, r := range html {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
			b.WriteByte(' ')
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
