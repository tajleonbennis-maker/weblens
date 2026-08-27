package mapserver

import (
	"bytes"
	"fmt"
	"html"
	"strings"
	"time"
)

// RenderTraceHTML builds a self-contained HTML intel report from an L4
// operation trace plus the latest mapping intel. It shows the asset, the
// structured intelligence (title / API endpoints / fingerprints / exposures /
// login-register doors), then every operation step with timestamps.
func RenderTraceHTML(assetURL string, trace []Step, intel PageIntel) string {
	var b bytes.Buffer
	b.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebLens · 资产情报报告</title><style>
:root{color-scheme:dark;font-family:Inter,"PingFang SC","Microsoft YaHei",system-ui,sans-serif;background:#081018;color:#d7e3f4}
body{margin:0;padding:28px 36px;max-width:900px;margin:0 auto}
h1{font-size:20px;color:#7dd3fc;margin:0 0 4px;word-break:break-all}
.sub{color:#64748b;font-size:12px;margin-bottom:20px;word-break:break-all}
.sec{font-size:13px;color:#7dd3fc;font-weight:700;margin:22px 0 8px;border-bottom:1px solid #1c2c44;padding-bottom:4px}
.card{background:#0d1b2e;border:1px solid #1e3a5f;border-radius:12px;padding:14px 16px;margin:10px 0}
.card .a{color:#67e8f9;font-weight:700;font-size:13px}
.card .t{color:#94a3b8;font-size:12px;margin-top:4px;word-break:break-all}
.card .u{color:#475569;font-size:10.5px;margin-top:3px}
.card.found{border-left:3px solid #fb7185}
.badge{display:inline-block;padding:1px 8px;border-radius:9px;font-size:10.5px;margin-right:6px}
.b-open{background:#1d3b33;color:#4ade80}.b-click{background:#3b2f1d;color:#fbbf24}
.b-scroll{background:#1e293b;color:#94a3b8}.b-snapshot{background:#312e81;color:#a5b4fc}
.stat{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0}
.stat .n{background:#0d1b2e;border:1px solid #1e3a5f;border-radius:10px;padding:10px 16px}
.stat .v{font-size:20px;font-weight:700;color:#67e8f9}
.stat .l{font-size:10.5px;color:#64748b}
.intel-line{font-size:12.5px;line-height:1.8;color:#bcd0ea;margin:4px 0}
.intel-line .k{color:#7dd3fc;font-weight:700;margin-right:8px}
.tag{display:inline-block;padding:1px 8px;border-radius:9px;font-size:10.5px;margin:2px 4px 2px 0;background:#12213a;border:1px solid #274060;color:#94a3b8}
.tag.hl{background:#312e81;border-color:#6366f1;color:#a5b4fc}
.tag.warn{background:#3b1d1d;border-color:#7f1d1d;color:#fb7185}
.door{display:inline-block;padding:3px 10px;border-radius:7px;font-size:11px;margin:2px 4px 2px 0;background:#3b2f1d;border:1px solid #7f6a1d;color:#fbbf24}
</style></head><body>`)

	title := html.EscapeString(assetURL)
	fmt.Fprintf(&b, `<h1>🛰 资产情报报告</h1><div class="sub">%s · 生成于 %s</div>`, title, time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))

	// ---- 测绘情报卡片 ------------------------------------------------
	if intel.Title != "" || len(intel.APIS) > 0 || len(intel.Fingerprints) > 0 ||
		len(intel.Exposures) > 0 || len(intel.Entrypoints) > 0 {
		b.WriteString(`<div class="sec">🧬 测绘情报</div>`)
		fmt.Fprintf(&b, `<div class="intel-line"><span class="k">📌 标题</span>%s</div>`,
			html.EscapeString(intel.Title))
		if len(intel.APIS) > 0 {
			fmt.Fprintf(&b, `<div class="intel-line"><span class="k">🔗 API 端点 (%d)</span>%s</div>`, len(intel.APIS),
				joinTags(intel.APIS, "hl"))
		}
		if len(intel.Fingerprints) > 0 {
			fmt.Fprintf(&b, `<div class="intel-line"><span class="k">🧬 技术指纹</span>%s</div>`,
				joinTags(intel.Fingerprints, ""))
		}
		if len(intel.Exposures) > 0 {
			fmt.Fprintf(&b, `<div class="intel-line"><span class="k">🛡 暴露点</span>%s</div>`,
				joinTags(intel.Exposures, "warn"))
		}
		if len(intel.Entrypoints) > 0 {
			var doors []string
			for _, ep := range intel.Entrypoints {
				kind := "🔐"
				if ep.Type == "register" {
					kind = "📝"
				}
				extra := ep.Action
				if extra == "" {
					extra = ep.URL
				}
				txt := kind + " " + html.EscapeString(ep.Label)
				if extra != "" {
					txt += " <span style='color:#64748b'>" + html.EscapeString(extra) + "</span>"
				}
				doors = append(doors, `<span class="door">`+txt+`</span>`)
			}
			fmt.Fprintf(&b, `<div class="intel-line"><span class="k">🚪 登录/注册入口</span>%s</div>`, strings.Join(doors, ""))
		}
	}

	// ---- 操作统计 ------------------------------------------------------
	var clicks, scrolls, snaps, found int
	for _, s := range trace {
		switch s.Action {
		case "click":
			clicks++
		case "interact":
			clicks++
		case "scroll":
			scrolls++
		case "snapshot":
			snaps++
			if strings.Contains(s.Note, "exposure") {
				found++
			}
		}
	}
	b.WriteString(`<div class="sec">📋 操作轨迹 (L4)</div>`)
	b.WriteString(`<div class="stat">`)
	fmt.Fprintf(&b, `<div class="n"><div class="v">%d</div><div class="l">操作步数</div></div>`, len(trace))
	fmt.Fprintf(&b, `<div class="n"><div class="v">%d</div><div class="l">点击/交互</div></div>`, clicks)
	fmt.Fprintf(&b, `<div class="n"><div class="v">%d</div><div class="l">滚动</div></div>`, scrolls)
	fmt.Fprintf(&b, `<div class="n"><div class="v">%d</div><div class="l">快照</div></div>`, snaps)
	b.WriteString(`</div>`)

	for _, s := range trace {
		cls := "card"
		badge := ""
		switch s.Action {
		case "open":
			badge = `<span class="badge b-open">OPEN</span>`
		case "click":
			badge = fmt.Sprintf(`<span class="badge b-click">CLICK %d,%d</span>`, s.X, s.Y)
		case "interact":
			badge = fmt.Sprintf(`<span class="badge b-click">INTERACT %d,%d</span>`, s.X, s.Y)
		case "scroll":
			badge = fmt.Sprintf(`<span class="badge b-scroll">SCROLL %d,%d</span>`, s.DX, s.DY)
		case "snapshot":
			badge = `<span class="badge b-snapshot">SNAPSHOT</span>`
			if strings.Contains(s.Note, "exposure") {
				cls += " found"
			}
		}
		fmt.Fprintf(&b, `<div class="%s">%s<div class="a">#%d %s</div><div class="t">%s</div><div class="u">%s · %s</div></div>`,
			cls, badge, s.Seq, html.EscapeString(s.Action), html.EscapeString(s.Note),
			html.EscapeString(s.URL), s.At)
	}
	b.WriteString(`</body></html>`)
	return b.String()
}

func joinTags(items []string, cls string) string {
	var sb strings.Builder
	for _, it := range items {
		sb.WriteString(`<span class="tag ` + cls + `">` + html.EscapeString(it) + `</span>`)
	}
	return sb.String()
}
