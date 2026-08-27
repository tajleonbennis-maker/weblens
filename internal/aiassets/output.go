package aiassets

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Output struct {
	dir            string
	limit, written int64
	assets, urls   *os.File
}

func NewOutput(dir string, limit int64) (*Output, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("byte limit must be positive")
	}
	if e := os.MkdirAll(dir, 0750); e != nil {
		return nil, e
	}
	a, e := os.OpenFile(filepath.Join(dir, "assets.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if e != nil {
		return nil, e
	}
	u, e := os.OpenFile(filepath.Join(dir, "asset-urls.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if e != nil {
		a.Close()
		return nil, e
	}
	written, e := directorySize(dir)
	if e != nil {
		a.Close()
		u.Close()
		return nil, e
	}
	if written > limit {
		a.Close()
		u.Close()
		return nil, fmt.Errorf("existing output exceeds data limit")
	}
	return &Output{dir: dir, limit: limit, written: written, assets: a, urls: u}, nil
}
func (o *Output) Write(a Asset) error {
	raw, e := json.Marshal(a)
	if e != nil {
		return e
	}
	need := int64(len(raw) + len(a.AssetURL) + 2)
	if o.written+need > o.limit {
		return fmt.Errorf("data limit reached")
	}
	if _, e = o.assets.Write(append(raw, '\n')); e != nil {
		return e
	}
	if _, e = fmt.Fprintln(o.urls, a.AssetURL); e != nil {
		return e
	}
	o.written += need
	return nil
}
func (o *Output) Written() int64 { return o.written }
func (o *Output) Limit() int64   { return o.limit }

type Checkpoint struct {
	Page      int       `json:"page"`
	Query     int       `json:"query"`
	Offset    int       `json:"offset"`
	Scanned   int       `json:"scanned"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (o *Output) Checkpoint(state Checkpoint) error {
	state.UpdatedAt = time.Now().UTC()
	body, _ := json.MarshalIndent(state, "", "  ")
	path := filepath.Join(o.dir, "checkpoint.json")
	projected := o.written - fileSize(path) + int64(len(body)+1)
	if projected > o.limit {
		return nil
	}
	if err := os.WriteFile(path, append(body, '\n'), 0640); err != nil {
		return err
	}
	o.written = projected
	return nil
}

func LoadCheckpoint(dir string) Checkpoint {
	body, err := os.ReadFile(filepath.Join(dir, "checkpoint.json"))
	if err != nil {
		return Checkpoint{Page: 1}
	}
	var state Checkpoint
	if json.Unmarshal(body, &state) != nil || state.Page < 1 {
		return Checkpoint{Page: 1}
	}
	return state
}

func LoadSeen(dir string) map[string]bool {
	seen := map[string]bool{}
	f, err := os.Open(filepath.Join(dir, "asset-urls.txt"))
	if err != nil {
		return seen
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if u := strings.TrimSpace(sc.Text()); u != "" {
			seen[u] = true
		}
	}
	return seen
}
func (o *Output) Finish(s Summary) error {
	s.WrittenBytes = o.written
	s.LimitBytes = o.limit
	body, _ := json.MarshalIndent(s, "", "  ")
	path := filepath.Join(o.dir, "summary.json")
	if o.written-fileSize(path)+int64(len(body)+1) > o.limit {
		return fmt.Errorf("data limit leaves no room for summary")
	}
	return os.WriteFile(path, append(body, '\n'), 0640)
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func directorySize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
func (o *Output) Close() error {
	_ = o.assets.Sync()
	_ = o.urls.Sync()
	e1 := o.assets.Close()
	e2 := o.urls.Close()
	if e1 != nil {
		return e1
	}
	return e2
}
func ReadSeeds(path string) ([]Candidate, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var out []Candidate
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if u := strings.TrimSpace(sc.Text()); u != "" && !strings.HasPrefix(u, "#") {
			out = append(out, Candidate{URL: u, DiscoveredBy: "seed:" + path})
		}
	}
	return out, sc.Err()
}
