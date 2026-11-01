package dbrijsecrets

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Key management from Go: the envelope format byte for byte as the Node SDK writes it
// (testdata/kms-fixture.json, from packages/secrets/scripts/kms-fixture.mjs), and the
// requests sent with the machine token.

type kmsCase struct {
	DataKeyHex        string            `json:"dataKeyHex"`
	DataKeyCiphertext string            `json:"dataKeyCiphertext"`
	IvHex             string            `json:"ivHex"`
	Plaintext         string            `json:"plaintext"`
	Context           map[string]string `json:"context"`
	CanonicalContext  string            `json:"canonicalContext"`
	Envelope          string            `json:"envelope"`
}

func loadKmsFixture(t *testing.T) []kmsCase {
	raw, err := os.ReadFile("testdata/kms-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []kmsCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnvelopeMatchesTheNodeSDK(t *testing.T) {
	for _, c := range loadKmsFixture(t) {
		if got := CanonicalKmsContext(c.Context); got != c.CanonicalContext {
			t.Fatalf("context %q, want %q", got, c.CanonicalContext)
		}
		env, err := SealEnvelope(unhex(t, c.DataKeyHex), c.DataKeyCiphertext, unhex(t, c.IvHex), []byte(c.Plaintext), c.Context)
		if err != nil || env != c.Envelope {
			t.Fatalf("envelope %q (%v), want %q", env, err, c.Envelope)
		}
		dk, body, err := ParseEnvelope(c.Envelope)
		if err != nil || dk != c.DataKeyCiphertext {
			t.Fatalf("parse: %q %v", dk, err)
		}
		out, err := OpenEnvelope(unhex(t, c.DataKeyHex), body, c.Context)
		if err != nil || string(out) != c.Plaintext {
			t.Fatalf("open: %v", err)
		}
	}
}

func TestEnvelopeRefusesAnotherContextOrAChange(t *testing.T) {
	c := loadKmsFixture(t)[1]
	_, body, _ := ParseEnvelope(c.Envelope)
	if _, err := OpenEnvelope(unhex(t, c.DataKeyHex), body, map[string]string{"table": "other"}); err == nil || !strings.Contains(err.Error(), "context differs") {
		t.Fatalf("another context opened: %v", err)
	}
	changed := append([]byte{}, body...)
	changed[len(changed)-1] ^= 1
	if _, err := OpenEnvelope(unhex(t, c.DataKeyHex), changed, c.Context); err == nil {
		t.Fatal("a changed body opened")
	}
	if _, _, err := ParseEnvelope("dkms1.nope"); err == nil {
		t.Fatal("not an envelope, parsed")
	}
}

func TestKeysCallTheMachineAPIAndRoundTripLargeData(t *testing.T) {
	var paths []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		bodies = append(bodies, body)
		if got := r.Header.Get("Authorization"); !strings.HasPrefix(got, "Bearer dbs_") {
			t.Errorf("authorization %q", got)
		}
		var data any
		switch {
		case strings.HasSuffix(r.URL.Path, "/data-key"):
			key := make([]byte, 32)
			data = map[string]any{"plaintext": base64.StdEncoding.EncodeToString(key), "ciphertext": "dkms1.x.1." + base64.StdEncoding.EncodeToString(key), "keyVersion": 1}
		case strings.HasSuffix(r.URL.Path, "/decrypt"):
			ct, _ := body["ciphertext"].(string)
			data = map[string]any{"plaintext": strings.SplitN(ct, ".", 4)[3], "keyVersion": 1}
		default:
			data = map[string]any{"ciphertext": "dkms1.k.1.abc", "keyVersion": 1}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}))
	defer srv.Close()
	raw, err := os.ReadFile("testdata/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(raw, &f)
	c, err := New(Options{Token: f.Token, BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	const key = "11111111-2222-3333-4444-555555555555"
	if _, err := c.Keys().Encrypt(context.Background(), key, []byte("héllo"), map[string]string{"a": "1"}); err != nil {
		t.Fatal(err)
	}
	if paths[0] != "/secrets/machine/kms/keys/"+key+"/encrypt" || bodies[0]["plaintext"] != base64.StdEncoding.EncodeToString([]byte("héllo")) {
		t.Fatalf("sent %s %v", paths[0], bodies[0])
	}
	big := []byte(strings.Repeat("x", 200000))
	env, err := c.Keys().EncryptLarge(context.Background(), key, big, map[string]string{"file": "report.pdf"})
	if err != nil || !strings.HasPrefix(env, "dkenv1.") {
		t.Fatalf("envelope %q %v", env, err)
	}
	back, err := c.Keys().DecryptLarge(context.Background(), key, env, map[string]string{"file": "report.pdf"})
	if err != nil || string(back) != string(big) {
		t.Fatalf("round trip: %v", err)
	}
}
