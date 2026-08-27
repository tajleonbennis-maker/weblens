package aiassets

import "testing"

func TestFingerprintAIChat(t *testing.T) {
	tech, models, chat := Fingerprint(`<script src="/_next/static/app.js"></script><div>Open WebUI</div><option>deepseek-chat</option>`)
	if !chat || len(tech) < 2 || len(models) == 0 {
		t.Fatalf("unexpected result: %v %+v %+v", chat, tech, models)
	}
}
func TestLooksBlocked(t *testing.T) {
	if !LooksBlocked("request has been blocked as it may cause potential threats to the server", 200) {
		t.Fatal("expected block")
	}
}
