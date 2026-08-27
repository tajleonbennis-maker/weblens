# WebLens · 交互式网络空间测绘平台

**我们核心做两件事：**

1. **给任何网页装上手脚** —— 基于 Pinchtab + Lightpanda 真实浏览器引擎，任何网页都能被打开、浏览、滚动、点击、交互（真身操作），并把页面内容与结构化情报拉下来
2. **把封闭系统的数据拉出来** —— 接入 TikHub，突破微信 / 抖音 / 小红书等封闭平台的围墙：搜公众号文章、取全文下载，让"封闭"的数据面变得可测绘

在这两件事之上，叠加 **AI（DeepSeek）一句话驱动**（说人话，平台自动执行动作链）、**FOFA 全网资产查询**、**可分享的情报报告**，形成一个对话式的网络空间测绘工作台。

> 一句话：**公开网络可操作，封闭平台可拉取，一切皆可对话驱动。**

## 核心能力

| 能力 | 说明 |
|---|---|
| 🛰 **FOFA 暴露面测绘** | 一句话查询全网资产：宝塔面板、Open WebUI、代理节点……返回总数 + 样例 + 分析 |
| 🖥 **真身浏览** | Lightpanda 真实浏览器渲染任意目标，自动抓取页面文本 / 链接 / HTML 源码 |
| 🧬 **结构化情报** | 自动提取：网站标题、API 端点、技术指纹、暴露路径、登录/注册入口 |
| 🚪 **入口交互** | 识别登录/注册表单后，在真实浏览器中点击它（CSS / 文本定位），观察页面变化 |
| 🤖 **AI 一句话驱动** | 接入 DeepSeek：用户说"看看这个登录页有哪些字段"，AI 自动规划并执行滚动 / 点击 / 抓取 / 查询动作链 |
| 📱 **封闭平台获取（TikHub）** | 突破微信风控：按标题搜公众号文章、取全文下载（抖音 / 视频号可扩展） |
| 📄 **情报报告** | 一次会话的操作轨迹 + 测绘情报，一键导出为可分享的 HTML 报告 |

## 快速开始

### 环境要求
- Go 1.26+
- Lightpanda 浏览器（CDP 模式，默认 `127.0.0.1:9222`）
- 可选：DeepSeek API Key、FOFA API Key、TikHub API Token

### 构建

```bash
go build -o aiassetsweb ./cmd/aiassetsweb
```

### 运行

```bash
# 最小运行（只需 Lightpanda）
./aiassetsweb -data /var/lib/weblens/ai-assets \
  -map-data /var/lib/weblens/bwh-scan \
  -geo /var/lib/weblens/bwh-geo.json \
  -lp 127.0.0.1:9222

# 全功能（AI / FOFA / TikHub 通过环境变量启用）
export DEEPSEEK_API_KEY=sk-xxx
export FOFA_KEY=xxx
export TIKHUB_API_KEY=xxx
./aiassetsweb -listen 0.0.0.0:8081
```

打开 `http://<host>:8081/map/` 进入交互式测绘面板。

### 环境变量

| 变量 | 用途 |
|---|---|
| `DEEPSEEK_API_KEY` | DeepSeek，驱动 AI Agent 一句话操作 |
| `FOFA_KEY` / `FOFA_EMAIL` | FOFA 全网资产查询 |
| `TIKHUB_API_KEY` | TikHub，公众号 / 视频号 / 抖音等封闭平台数据 |

## 界面

首页是 FOFA 风格的极简搜索：居中大搜索框 + 三张能力卡片（FOFA 测绘 / 网页文章下载 / 公众号文章），点击即体验。

- **搜索框**：输入域名 / IP / 一句话任务，AI 自动判断执行方式
- **资产列表**：扫描资产全景（归属国家 / ISP / 端口 / HTTP 状态 / 技术栈），支持搜索与分类筛选
- **资产视图**：结构化情报卡片（标题 / API / 指纹 / 暴露点 / 登录注册入口）+ 文本 / 链接 / 源码三视图 + 操作轨迹
- **情报报告**：一键导出会话的完整情报 + 操作留痕

## API 概览

| 接口 | 说明 |
|---|---|
| `GET /api/map/assets` | 资产列表（含归属 / 状态 / 技术栈） |
| `POST /api/live/open` | 为资产建立 Lightpanda 真身会话 |
| `POST /api/live/snapshot` | 抓取当前页 DOM + 结构化情报 |
| `POST /api/live/interact` | 定位并点击登录/注册入口（CSS / TEXT 定位） |
| `POST /api/live/scroll` | 页面滚动 |
| `POST /api/live/ask` | **AI 一句话驱动**：DeepSeek 解析意图 → 执行动作链（scroll / interact / snapshot / fofa / tikhub）→ 总结 |
| `POST /api/live/report` | 导出 HTML 情报报告（测绘情报 + 操作轨迹） |

## 架构

```
┌─────────────────────────────────────────────────────┐
│  前端 map.html（FOFA 风格搜索 + 资产视图 + AI 输入）    │
├─────────────────────────────────────────────────────┤
│  aiassetsweb（Go HTTP 服务）                          │
│  ├── mapserver（会话管理 / 情报提取 / AI Agent / 工具）│
│  │    ├── intel.go   结构化情报（标题/API/指纹/暴露/入口）│
│  │    ├── agent.go   AI 动作链（DeepSeek 解析+执行+总结）│
│  │    ├── llm.go     DeepSeek 客户端                   │
│  │    ├── fofa → aiassets  FOFA 全网资产查询           │
│  │    └── tikhub.go  TikHub（公众号搜索/全文，本地缓存） │
│  ├── lightpanda（真实浏览器 CDP 客户端）                │
│  └── aiassets（资产扫描 / FOFA / 指纹）                │
└─────────────────────────────────────────────────────┘
```

## 目录结构

```
cmd/aiassetsweb/   主服务（HTTP 路由 + 前端页面）
internal/mapserver/  交互测绘核心（会话 / 情报 / AI Agent / FOFA / TikHub）
internal/lightpanda/ Lightpanda CDP 客户端
internal/aiassets/   资产模型 / FOFA 客户端 / 指纹识别
internal/keydetect/  Key 泄露检测引擎（扫描管道内部能力）
```

## 设计要点

- **不截图**：Lightpanda 无图形渲染引擎，产品交互围绕「DOM / 文本 / 情报」而非截图设计
- **AI 工具白名单**：LLM 只能规划预定义动作（scroll / interact / snapshot / fofa / tikhub），不能自由导航
- **上下文最小化**：只把结构化情报 + 截断文本发给 LLM，不传完整 DOM
- **成本控制**：TikHub 搜索重试走免费缓存 URL；公众号文章本地磁盘缓存，重复下载零成本
- **凭据隔离**：所有 API Key 从环境变量读取，不进代码、不进日志

## 安全声明

WebLens 是安全研究与防御用途的测绘平台，请仅对**你有权评估的目标**使用。禁止用于未授权扫描、攻击或任何违法用途。项目作者不对工具的滥用行为负责。
