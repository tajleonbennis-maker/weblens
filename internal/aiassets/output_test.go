package aiassets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOutputHonorsLimit(t *testing.T) {
	dir := t.TempDir()
	o, e := NewOutput(dir, 200)
	if e != nil {
		t.Fatal(e)
	}
	defer o.Close()
	a := Asset{AssetURL: "https://example.test", DiscoveredBy: "test"}
	if e = o.Write(a); e != nil {
		t.Fatal(e)
	}
	for o.Write(a) == nil {
	}
	if o.Written() > o.Limit() {
		t.Fatal("limit exceeded")
	}
	if _, e = os.Stat(filepath.Join(dir, "assets.jsonl")); e != nil {
		t.Fatal(e)
	}
}
