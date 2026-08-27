// Package mapserver implements the interactive mapping panel (L3) and the
// operation-trace recorder (L4) of WebLens. It manages one live Lightpanda
// browser session per user request, forwarding human interactions (click,
// scroll) to the real page and recording every step so a session can be
// replayed as an asset-intelligence trace.
package mapserver

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tajleonbennis-maker/weblens/internal/keydetect"
	"github.com/tajleonbennis-maker/weblens/internal/lightpanda"
)

// Step is one recorded interaction in a live session (L4 trace entry).
type Step struct {
	Seq      int    `json:"seq"`
	Action   string `json:"action"`   // open | click | scroll | snapshot | interact
	URL      string `json:"url"`      // page URL after the action
	Title    string `json:"title"`    // page title after the action
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
	DX       int    `json:"dx,omitempty"`
	DY       int    `json:"dy,omitempty"`
	Note     string `json:"note,omitempty"` // e.g. key exposure found
	At       string `json:"at"`             // RFC3339 timestamp
	ShotSize int    `json:"shotSize,omitempty"`
}

// Session is one live browser session for one asset. It owns a Lightpanda
// connection and appends to an in-memory trace.
type Session struct {
	mu              sync.Mutex
	lp              *lightpanda.Client
	AssetURL        string
	Current         string // current page URL (may change after clicks)
	Trace           []Step
	seq             int
	closed          bool
	shotUnavailable bool          // true once we know Lightpanda can't render PNG
	lastIntel       PageIntel     // latest mapping intel (for the HTML report)
}

// IsPlaceholderShot returns true when the given base64 PNG matches the
// Lightpanda "no graphical rendering engine" placeholder signature
// (1920x1080, 4-bit indexed color, very small payload). Real page screenshots
// either have 24/32-bit color types or grow far beyond this size, so the
// check is reliable.
func IsPlaceholderShot(b64 string) bool {
	if len(b64) < 64 {
		return true
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 26 {
		return true
	}
	// PNG signature 89 50 4E 47 0D 0A 1A 0A
	if !bytesEq(raw[:8], 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) {
		return true
	}
	// IHDR width(4) height(4) bit_depth(1) color_type(1)
	w := binary.BigEndian.Uint32(raw[16:20])
	h := binary.BigEndian.Uint32(raw[20:24])
	bitDepth := raw[24]
	colorType := raw[25]
	// Known Lightpanda placeholder: 1920x1080 4-bit colormap (color type 3),
	// stays around 10 KB across pages. Real pages either compress bigger or
	// use direct-color (type 2/6). Height == 1080 with such low entropy on
	// every page is also a tell.
	if w == 1920 && h == 1080 && bitDepth == 4 && colorType == 3 {
		return true
	}
	// Defensive fallback: any screenshot under 24 KB that mentions typical
	// placeholder color types counts as a placeholder. Real screenshots of
	// any modern page exceed this easily.
	if len(raw) < 24*1024 && (colorType == 3 && bitDepth <= 4) {
		return true
	}
	return false
}

func bytesEq(b []byte, want ...byte) bool {
	if len(b) != len(want) {
		return false
	}
	for i, v := range want {
		if b[i] != v {
			return false
		}
	}
	return true
}

// Manager hands out live sessions and keeps them until closed. It maintains a
// pool of Lightpanda endpoints so multiple assets can be browsed concurrently
// (each Lightpanda process serves exactly one browsing context).
type Manager struct {
	mu       sync.Mutex
	lpAddrs  []string
	next     int // round-robin index
	sessions map[string]*Session
}

// NewManager returns a Manager bound to the given Lightpanda address(es).
// Comma-separated addresses are supported for concurrency, e.g.
// "127.0.0.1:9222,127.0.0.1:9223,127.0.0.1:9224".
func NewManager(lpAddr string) *Manager {
	addrs := []string{}
	for _, a := range strings.Split(lpAddr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1:9222"}
	}
	return &Manager{lpAddrs: addrs, sessions: map[string]*Session{}}
}

// pickAddr round-robins over the Lightpanda pool.
func (m *Manager) pickAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	addr := m.lpAddrs[m.next%len(m.lpAddrs)]
	m.next++
	return addr
}

// tryShot captures a screenshot, returning ("", true) when Lightpanda has no
// graphical engine (placeholder image detected) so callers can stop asking.
// Errors are surfaced as-is so unexpected failures aren't masked.
func (s *Session) tryShot(ctx context.Context) (string, bool) {
	if s.shotUnavailable {
		return "", true
	}
	shot, err := s.lp.Screenshot(ctx)
	if err != nil {
		s.shotUnavailable = true
		return "", true
	}
	if IsPlaceholderShot(shot) {
		s.shotUnavailable = true
		return "", true
	}
	return shot, false
}

// Open creates a session, navigates to url, and returns the first screenshot.
// When Lightpanda has no graphical rendering engine, shot will be empty and
// shotAvailable will be false; callers should switch to a DOM/keys view.
func (m *Manager) Open(ctx context.Context, url string) (*Session, string, bool, error) {
	// Reuse an existing session for the same asset (idempotent open).
	if s := m.Get(url); s != nil {
		s.mu.Lock()
		shot, unavail := s.tryShot(ctx)
		avail := !unavail
		s.mu.Unlock()
		return s, shot, avail, nil
	}
	addr := m.pickAddr()
	lp, err := lightpanda.Connect(ctx, addr)
	if err != nil {
		return nil, "", false, fmt.Errorf("connect lightpanda: %w", err)
	}
	html, err := lp.Render(ctx, url)
	if err != nil {
		_ = lp.Close()
		return nil, "", false, fmt.Errorf("render %s: %w", url, err)
	}
	_ = html
	cur := lp.CurrentURL(ctx)
	title := lp.PageTitle(ctx)
	s := &Session{
		lp:       lp,
		AssetURL: url,
		Current:  cur,
		seq:      0,
	}
	shot, unavail := s.tryShot(ctx)
	if unavail {
		// Page still loads and is interactive; only screenshots are missing.
		s.addStep(Step{
			Action: "open", URL: cur, Title: title,
			Note: fmt.Sprintf("rendered %d bytes (screenshot unavailable: Lightpanda has no graphical rendering engine)", len(html)),
		})
	} else {
		s.addStep(Step{
			Action: "open", URL: cur, Title: title,
			Note:     fmt.Sprintf("rendered %d bytes", len(html)),
			ShotSize: len(shot),
		})
	}
	m.mu.Lock()
	m.sessions[url] = s
	m.mu.Unlock()
	return s, shot, !unavail, nil
}

// Get returns an existing session for url, or nil.
func (m *Manager) Get(url string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[url]
}

// Close tears down a session and returns its trace for archival.
func (m *Manager) Close(url string) []Step {
	m.mu.Lock()
	s := m.sessions[url]
	delete(m.sessions, url)
	m.mu.Unlock()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.lp != nil {
		_ = s.lp.Close()
	}
	out := make([]Step, len(s.Trace))
	copy(out, s.Trace)
	return out
}

// Click forwards a mouse click to the live page and returns a new screenshot.
// When shotAvailable is false the screenshot is omitted but the click and
// trace step still happen — Lightpanda IS executing the interaction.
func (s *Session) Click(ctx context.Context, x, y int) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false, fmt.Errorf("session closed")
	}
	if err := s.lp.Click(ctx, float64(x), float64(y)); err != nil {
		return "", false, err
	}
	_ = s.lp.WaitSettle(ctx)
	shot, unavail := s.tryShot(ctx)
	s.Current = s.lp.CurrentURL(ctx)
	step := Step{
		Action: "click", URL: s.Current, Title: s.lp.PageTitle(ctx),
		X: x, Y: y,
	}
	if !unavail {
		step.ShotSize = len(shot)
	}
	s.addStepLocked(step)
	return shot, !unavail, nil
}

// Scroll scrolls the live page and returns a new screenshot when available.
func (s *Session) Scroll(ctx context.Context, dx, dy int) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", false, fmt.Errorf("session closed")
	}
	s.lp.ScrollBy(ctx, float64(dx), float64(dy))
	shot, unavail := s.tryShot(ctx)
	s.Current = s.lp.CurrentURL(ctx)
	step := Step{
		Action: "scroll", URL: s.Current, Title: s.lp.PageTitle(ctx),
		DX: dx, DY: dy,
	}
	if !unavail {
		step.ShotSize = len(shot)
	}
	s.addStepLocked(step)
	return shot, !unavail, nil
}

// Snapshot returns the current state (URL, title, mapping intel and raw DOM)
// and records an L4 trace point. The intel is the structured extraction —
// title, API endpoints, fingerprints, exposure paths and login/register
// entry points — that the interactive mapping panel shows instead of a
// screenshot. A missing graphical engine never fails this call.
func (s *Session) Snapshot(ctx context.Context, findKeys bool) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("session closed")
	}
	shot, unavail := s.tryShot(ctx)
	cur := s.lp.CurrentURL(ctx)
	title := s.lp.PageTitle(ctx)
	html := s.lp.DOM(ctx)
	intel := AnalyzePage(html, cur)
	step := Step{
		Action: "snapshot", URL: cur, Title: title,
	}
	if !unavail {
		step.ShotSize = len(shot)
	} else {
		step.Note = "DOM captured; intel extracted"
	}
	out := map[string]any{
		"url":           cur,
		"title":         title,
		"shot":          shot,
		"shotAvailable": !unavail,
		"html":          html,
		"intel":         intel,
		"found":         []map[string]string{},
	}
	s.lastIntel = intel
	if findKeys && len(html) > 0 {
		for _, f := range keydetect.Detect(html) {
			out["found"] = append(out["found"].([]map[string]string), map[string]string{
				"kind": f.Kind, "provider": f.Provider, "masked": f.MaskedKey,
				"confidence": f.Confidence,
			})
		}
	}
	step.Note = fmt.Sprintf("%d api · %d fp · %d exp · %d doors",
		len(intel.APIS), len(intel.Fingerprints), len(intel.Exposures), len(intel.Entrypoints))
	s.addStepLocked(step)
	return out, nil
}

// Interact locates a DOM element (CSS selector or "TEXT:..." search) in the
// live page and clicks it at its center, then returns the refreshed DOM plus
// mapping intel. This is how the panel "helps the user interact" with
// login/register doors and other controls — no screenshot needed.
func (s *Session) Interact(ctx context.Context, selector string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, fmt.Errorf("session closed")
	}
	loc, err := s.locateElement(ctx, selector)
	if err != nil {
		return nil, err
	}
	if err := s.lp.Click(ctx, loc.X, loc.Y); err != nil {
		return nil, err
	}
	_ = s.lp.WaitSettle(ctx)
	cur := s.lp.CurrentURL(ctx)
	title := s.lp.PageTitle(ctx)
	html := s.lp.DOM(ctx)
	s.Current = cur
	intel := AnalyzePage(html, cur)
	s.lastIntel = intel
	s.addStepLocked(Step{
		Action: "interact", URL: cur, Title: title,
		X: int(loc.X), Y: int(loc.Y),
		Note: fmt.Sprintf("clicked %q → %s", loc.Tag, cur),
	})
	return map[string]any{
		"url":     cur,
		"title":   title,
		"html":    html,
		"intel":   intel,
		"clicked": map[string]any{"x": loc.X, "y": loc.Y, "tag": loc.Tag},
	}, nil
}

type elementLoc struct{ X, Y float64; Tag string }

// locateElement finds a visible element via CSS selector or "TEXT:..." search
// and returns its viewport center. Visibility is judged by bounding-box size
// (Lightpanda's offsetParent is unreliable) and the element is scrolled into
// view before measuring so the click lands inside the viewport.
func (s *Session) locateElement(ctx context.Context, selector string) (elementLoc, error) {
	expr := ""
	if strings.HasPrefix(selector, "TEXT:") {
		pat := strings.TrimPrefix(selector, "TEXT:")
		pat = strings.ReplaceAll(pat, "'", "\\'")
		expr = fmt.Sprintf(`(() => {
			try {
				const re = new RegExp(%q, 'i');
				const els = document.querySelectorAll('a,button,input[type=submit],[role=button]');
				for (const el of els) {
					if (!re.test(el.textContent || '')) continue;
					const r = el.getBoundingClientRect();
					if (r.width <= 0 && r.height <= 0) continue;
					try { el.scrollIntoView({block:'center'}); } catch(e) {}
					const r2 = el.getBoundingClientRect();
					return JSON.stringify({found:true,x:r2.x+r2.width/2,y:r2.y+r2.height/2,tag:(el.tagName+':'+(el.textContent||'').trim().slice(0,30))});
				}
				return JSON.stringify({found:false});
			} catch(e) { return JSON.stringify({found:false,err:String(e)}); }
		})()`, pat)
	} else {
		sel := strings.ReplaceAll(selector, "'", "\\'")
		expr = fmt.Sprintf(`(() => {
			try {
				const el = document.querySelector(%q);
				if (!el) return JSON.stringify({found:false});
				const r = el.getBoundingClientRect();
				if (r.width <= 0 && r.height <= 0) return JSON.stringify({found:false});
				try { el.scrollIntoView({block:'center'}); } catch(e) {}
				const r2 = el.getBoundingClientRect();
				return JSON.stringify({found:true,x:r2.x+r2.width/2,y:r2.y+r2.height/2,tag:(el.tagName+':'+(el.textContent||'').trim().slice(0,30))});
			} catch(e) { return JSON.stringify({found:false,err:String(e)}); }
		})()`, sel)
	}
	out := s.lp.EvalJS(ctx, expr)
	var res struct {
		Found bool    `json:"found"`
		X     float64 `json:"x"`
		Y     float64 `json:"y"`
		Tag   string  `json:"tag"`
		Err   string  `json:"err"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || !res.Found {
		if res.Err != "" {
			return elementLoc{}, fmt.Errorf("locate %s: js error: %s", selector, res.Err)
		}
		return elementLoc{}, fmt.Errorf("element not found or not visible: %s (eval=%q)", selector, out)
	}
	return elementLoc{X: res.X, Y: res.Y, Tag: res.Tag}, nil
}

// LastIntel returns the latest mapping intel captured in this session.
func (s *Session) LastIntel() PageIntel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastIntel
}

// Trace returns a copy of the recorded operation steps (L4).
func (s *Session) TraceCopy() []Step {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Step, len(s.Trace))
	copy(out, s.Trace)
	return out
}

func (s *Session) addStep(st Step) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addStepLocked(st)
}

func (s *Session) addStepLocked(st Step) {
	s.seq++
	st.Seq = s.seq
	st.At = time.Now().UTC().Format(time.RFC3339)
	s.Trace = append(s.Trace, st)
}

// ShotDataURL wraps a base64 PNG into a data URL for direct <img> use.
func ShotDataURL(b64 string) string {
	return "data:image/png;base64," + b64
}

// DecodeShot decodes a base64 screenshot to raw bytes.
func DecodeShot(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}
