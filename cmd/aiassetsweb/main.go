package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tajleonbennis-maker/weblens/internal/aiassets"
	"github.com/tajleonbennis-maker/weblens/internal/mapserver"
)

//go:embed index.html
var indexHTML string

//go:embed map.html
var mapHTML string

type state struct {
	UpdatedAt      time.Time           `json:"updatedAt"`
	Scanned        int                 `json:"scanned"`
	AIAssets       int                 `json:"aiAssets"`
	ExposureAssets int                 `json:"exposureAssets"`
	Blocked        int                 `json:"blocked"`
	Reachable      int                 `json:"reachable"`
	DataBytes      int64               `json:"dataBytes"`
	Checkpoint     aiassets.Checkpoint `json:"checkpoint"`
	Technologies   []count             `json:"technologies"`
	Models         []count             `json:"models"`
	Assets         []aiassets.Asset    `json:"assets"`
	Recent         []aiassets.Asset    `json:"recent"`
}
type count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func main() {
	dir := flag.String("data", "/var/lib/weblens/ai-assets", "collector result directory")
	reportsDir := flag.String("reports", "/var/lib/weblens/reports", "directory of key-report HTML files served at /report/")
	mapData := flag.String("map-data", "/var/lib/weblens/bwh-scan", "interactive map asset source (assets.jsonl)")
	geoFile := flag.String("geo", "/var/lib/weblens/bwh-geo.json", "IP->geo cache JSON for map assets")
	lpAddr := flag.String("lp", "127.0.0.1:9222", "Lightpanda CDP address for live sessions")
	addr := flag.String("listen", "127.0.0.1:8081", "listen address")
	user := flag.String("user", os.Getenv("WEBLENS_DASHBOARD_USER"), "HTTP Basic Auth username")
	password := flag.String("password", os.Getenv("WEBLENS_DASHBOARD_PASSWORD"), "HTTP Basic Auth password")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexHTML))
	})
	// Interactive mapping panel (L3 live browser + L4 trace)
	mux.HandleFunc("GET /map/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(mapHTML))
	})
	// Serve generated key-report HTML files from the reports directory so the
	// dashboard doubles as the report viewer: /report/report-deeptutor.html
	if *reportsDir != "" {
		fs := http.StripPrefix("/report/", http.FileServer(http.Dir(*reportsDir)))
		mux.Handle("GET /report/", fs)
	}
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		s, err := readState(*dir)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(s)
	})
	// ---- Interactive mapping API (L3 + L4) ----
	loadGeoCache(*geoFile)
	mgr := mapserver.NewManager(*lpAddr)
	mux.HandleFunc("GET /api/map/assets", func(w http.ResponseWriter, r *http.Request) {
		assets, err := readMapAssets(*mapData)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]any{"assets": assets, "count": len(assets)})
	})
	mux.HandleFunc("POST /api/live/open", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
			http.Error(w, "url required", 400)
			return
		}
		ctx := r.Context()
		sess, shot, shotAvailable, err := mgr.Open(ctx, req.URL)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, map[string]any{
			"session": map[string]any{"url": sess.AssetURL, "current": sess.Current},
			"shot":         shot,
			"shotAvailable": shotAvailable,
		})
	})
	mux.HandleFunc("POST /api/live/click", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
			X   int    `json:"x"`
			Y   int    `json:"y"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		shot, shotAvailable, err := sess.Click(r.Context(), req.X, req.Y)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, map[string]any{
			"shot": shot, "current": sess.Current, "shotAvailable": shotAvailable,
		})
	})
	mux.HandleFunc("POST /api/live/scroll", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
			DX  int    `json:"dx"`
			DY  int    `json:"dy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		shot, shotAvailable, err := sess.Scroll(r.Context(), req.DX, req.DY)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, map[string]any{
			"shot": shot, "current": sess.Current, "shotAvailable": shotAvailable,
		})
	})
	mux.HandleFunc("POST /api/live/snapshot", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL      string `json:"url"`
			FindKeys bool   `json:"findKeys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		out, err := sess.Snapshot(r.Context(), req.FindKeys)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /api/live/interact", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL      string `json:"url"`
			Selector string `json:"selector"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" || req.Selector == "" {
			http.Error(w, "url and selector required", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		out, err := sess.Interact(r.Context(), req.Selector)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /api/live/ask", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL    string `json:"url"`
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Prompt) == "" {
			http.Error(w, "prompt required", 400)
			return
		}
		apiKey := os.Getenv("DEEPSEEK_API_KEY")
		if apiKey == "" {
			http.Error(w, "DEEPSEEK_API_KEY not configured on server", 503)
			return
		}
		// url may be empty: global task mode (fofa queries / plain answers).
		var sess *mapserver.Session
		if req.URL != "" {
			sess = mgr.Get(req.URL)
			if sess == nil {
				http.Error(w, "session not open", 404)
				return
			}
		}
		llm := mapserver.NewLLMClient(apiKey)
		var fofa *aiassets.FOFAClient
		if fk := os.Getenv("FOFA_KEY"); fk != "" {
			fofa = &aiassets.FOFAClient{
				Email:  os.Getenv("FOFA_EMAIL"),
				Key:    fk,
				Client: &http.Client{Timeout: 25 * time.Second},
			}
		}
		var tikhub *mapserver.TikHubClient
		if tk := os.Getenv("TIKHUB_API_KEY"); tk != "" {
			tikhub = mapserver.NewTikHubClient(tk)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		out, err := mgr.AskAgent(ctx, sess, strings.TrimSpace(req.Prompt), llm, fofa, tikhub)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("POST /api/live/trace", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		writeJSON(w, map[string]any{"trace": sess.TraceCopy(), "assetUrl": req.URL})
	})
	mux.HandleFunc("POST /api/live/report", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		sess := mgr.Get(req.URL)
		if sess == nil {
			http.Error(w, "session not open", 404)
			return
		}
		// Close the session (report is the terminal action) and render the
		// full trace + mapping intel as a self-contained HTML intel page.
		intel := sess.LastIntel()
		trace := mgr.Close(req.URL)
		html := mapserver.RenderTraceHTML(req.URL, trace, intel)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", "asset-trace.html"))
		_, _ = w.Write([]byte(html))
	})
	mux.HandleFunc("POST /api/live/close", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		trace := mgr.Close(req.URL)
		writeJSON(w, map[string]any{"closed": true, "steps": len(trace)})
	})
	fmt.Println("WebLens asset dashboard:", *addr)
	if err := http.ListenAndServe(*addr, basicAuth(mux, *user, *password)); err != nil {
		panic(err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// readMapAssets reads the interactive map asset list from a scan result dir.
type mapAsset struct {
	URL       string `json:"url"`
	IP        string `json:"ip"`
	Port      string `json:"port"`
	Title     string `json:"title"`
	Reachable bool   `json:"reachable"`
	AIChat    bool   `json:"aiChat"`
	Exposures int    `json:"exposures"`
	Tech      string `json:"tech"`
	HTTPStatus int   `json:"httpStatus,omitempty"`
	// geo enrichment (from bwh-geo.json cache)
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Region      string `json:"region,omitempty"`
	City        string `json:"city,omitempty"`
}

// geoCache maps IP -> geo fields, loaded once from the cache file.
var geoCache = map[string]map[string]string{}

func loadGeoCache(path string) {
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	_ = json.NewDecoder(f).Decode(&geoCache)
}

func readMapAssets(dir string) ([]mapAsset, error) {
	var out []mapAsset
	f, err := os.Open(filepath.Join(dir, "assets.jsonl"))
	if err != nil {
		return out, err
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64<<10), 4<<20)
	for scan.Scan() {
		var a aiassets.Asset
		if json.Unmarshal(scan.Bytes(), &a) != nil {
			continue
		}
		ma := mapAsset{
			URL: a.AssetURL, Title: a.Title, Reachable: a.Reachable,
			AIChat: a.AIChat, Exposures: len(a.KeyExposures),
			HTTPStatus: a.HTTPStatus,
		}
		// Extract host:port from the asset URL for the badge & filter.
		if u, err := url.Parse(a.AssetURL); err == nil {
			ma.IP = u.Hostname()
			ma.Port = u.Port()
			if g, ok := geoCache[ma.IP]; ok {
				ma.Country = g["country"]
				ma.CountryCode = g["countryCode"]
				ma.ISP = g["isp"]
				ma.ASN = g["as"]
				ma.Region = g["regionName"]
				ma.City = g["city"]
			}
		}
		var techs []string
		for _, t := range a.Technologies {
			techs = append(techs, t.Name)
		}
		ma.Tech = strings.Join(techs, "|")
		out = append(out, ma)
	}
	return out, scan.Err()
}

func basicAuth(next http.Handler, expectedUser, expectedPassword string) http.Handler {
	if expectedUser == "" && expectedPassword == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(expectedUser)) == 1
		passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(expectedPassword)) == 1
		if !ok || !userOK || !passwordOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebLens", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func readState(dir string) (state, error) {
	s := state{UpdatedAt: time.Now().UTC(), Checkpoint: aiassets.LoadCheckpoint(dir)}
	tech := map[string]int{}
	models := map[string]int{}
	f, err := os.Open(filepath.Join(dir, "assets.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return s, err
	}
	if f != nil {
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 64<<10), 4<<20)
		for scan.Scan() {
			var a aiassets.Asset
			if json.Unmarshal(scan.Bytes(), &a) != nil {
				continue
			}
			s.Scanned++
			if a.AIChat {
				s.AIAssets++
			}
			if a.Reachable {
				s.Reachable++
			}
			if a.Blocked {
				s.Blocked++
			}
			if len(a.KeyExposures) > 0 {
				s.ExposureAssets++
			}
			s.Assets = append(s.Assets, a)
			for _, t := range a.Technologies {
				tech[t.Name]++
			}
			for _, m := range a.Models {
				models[m.Provider]++
			}
			if len(s.Recent) >= 30 {
				s.Recent = s.Recent[1:]
			}
			s.Recent = append(s.Recent, a)
		}
		if err := scan.Err(); err != nil {
			return s, err
		}
	}
	s.Technologies = sortedCounts(tech)
	s.Models = sortedCounts(models)
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			s.DataBytes += info.Size()
		}
		return nil
	})
	return s, nil
}
func sortedCounts(m map[string]int) []count {
	out := make([]count, 0, len(m))
	for n, c := range m {
		out = append(out, count{Name: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}
