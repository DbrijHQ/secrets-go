package dbrijsecrets

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The fixture is written by the Node SDK (packages/secrets/scripts/python-fixture.mjs), so
// these tests prove the Go SDK opens the Node SDK's work, as the Python SDK does.
type fixture struct {
	Token    string            `json:"token"`
	Bundle   json.RawMessage   `json:"bundle"`
	Expected map[string]string `json:"expected"`
}

func loadFixture(t *testing.T) (fixture, *bundle) {
	t.Helper()
	raw, err := os.ReadFile("testdata/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal(f.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	return f, &b
}

func TestReadsATokenAndSendsOnlyTwoParts(t *testing.T) {
	f, _ := loadFixture(t)
	tok, err := ParseToken(f.Token)
	if err != nil {
		t.Fatal(err)
	}
	if tok.CredentialID != "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" || tok.Kind != "token" || len(tok.keySecret) != 32 {
		t.Fatalf("parsed wrong: %+v", tok)
	}
	bearer, _ := tok.Bearer()
	if bearer != "dbs_0f1e2d3c4b5a69788796a5b4c3d2e1f0_"+strings.Repeat("a", 39) {
		t.Fatalf("bearer %q", bearer)
	}
	if strings.Contains(bearer, base32(tok.keySecret)) {
		t.Fatal("the key half must never be in the bearer")
	}
}

func TestATokenCutShortIsCaught(t *testing.T) {
	f, _ := loadFixture(t)
	tok, _ := ParseToken(f.Token)
	bearer, _ := tok.Bearer()
	for input, want := range map[string]string{
		f.Token[:len(f.Token)-1]:   "cut short",
		bearer:                     "incomplete",
		"dbs_" + tok.CredentialHex: "missing its key half",
		"ghp_x":                    "not a Dbrij Secrets token",
	} {
		if _, err := ParseToken(input); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", input, err, want)
		}
	}
}

func TestALoginKeyHasNoBearerOfItsOwn(t *testing.T) {
	f, _ := loadFixture(t)
	tok, _ := ParseToken(f.Token)
	key, err := ParseToken(formatKey(tok.CredentialHex, tok.keySecret))
	if err != nil {
		t.Fatal(err)
	}
	if key.Kind != "key" || string(key.keySecret) != string(tok.keySecret) {
		t.Fatalf("key parsed wrong: %+v", key)
	}
	if _, err := key.Bearer(); err == nil {
		t.Fatal("a key alone must not sign in")
	}
}

func TestOpensWhatTheNodeSDKSealed(t *testing.T) {
	f, b := loadFixture(t)
	tok, _ := ParseToken(f.Token)
	priv, err := openMachinePrivateKey(tok.keySecret, b.Holder.KeySalt, b.Holder.EncryptedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	envKey, err := unwrapEnvironmentKey(b.Wraps[0].Wrapped, priv)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range b.Items {
		p, ok := openValue(envKey, secretsAAD(b.Environment.ID, item.FolderID, item.Key, nil), item.Ciphertext, item.IV)
		if !ok || p.V != f.Expected[item.FolderPath+":"+item.Key] {
			t.Errorf("%s: got %q", item.Key, p.V)
		}
	}
	first := b.Items[0]
	if p, _ := openValue(envKey, secretsAAD(b.Environment.ID, nil, first.Key, nil), first.Ciphertext, first.IV); p.N != "primary" {
		t.Errorf("note %q", p.N)
	}
	// Moved to another name, it does not open.
	if _, ok := openValue(envKey, secretsAAD(b.Environment.ID, nil, "OTHER", nil), first.Ciphertext, first.IV); ok {
		t.Error("a value moved to another name must not open")
	}
	// Another machine's key half does not open the machine key.
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	if _, err := openMachinePrivateKey(other, b.Holder.KeySalt, b.Holder.EncryptedPrivateKey); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Errorf("wrong key half: %v", err)
	}
}

func TestAValueSealedHereOpensWithTheSameKey(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	folder := "f"
	aad := secretsAAD("env", &folder, "K", nil)
	ct, iv, err := sealValue(key, aad, "naira ₦ <&>", "note")
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := openValue(key, aad, ct, iv); !ok || p.V != "naira ₦ <&>" || p.N != "note" {
		t.Fatalf("round trip: %+v %v", p, ok)
	}
	if _, ok := openValue(key, secretsAAD("env", nil, "K", nil), ct, iv); ok {
		t.Fatal("a value must not open in another folder")
	}
}

func TestBase32MatchesTheOtherSDKs(t *testing.T) {
	data := []byte{0, 1, 2, 250, 251, 252, 253, 254, 255}
	back, ok := unbase32(base32(data))
	if !ok || string(back) != string(data) {
		t.Fatalf("round trip %v", back)
	}
	if _, ok := unbase32("ilou"); ok {
		t.Fatal("letters outside Crockford's alphabet are refused")
	}
}

// Templates, imports and another environment: the same values and problems as the Node SDK.
func TestFillsTemplatesExactlyAsTheNodeSDKDoes(t *testing.T) {
	raw, err := os.ReadFile("testdata/fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Token      string `json:"token"`
		References struct {
			Bundle     json.RawMessage   `json:"bundle"`
			Paths      []string          `json:"paths"`
			Values     map[string]string `json:"values"`
			Problems   []string          `json:"problems"`
			Collisions []string          `json:"collisions"`
		} `json:"references"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal(f.References.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Token: f.Token, Paths: f.References.Paths, BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	values, err := c.open(&b)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != len(f.References.Values) {
		t.Fatalf("values %v, want %v", values, f.References.Values)
	}
	for k, v := range f.References.Values {
		if values[k] != v {
			t.Errorf("%s = %q, want %q", k, values[k], v)
		}
	}
	if strings.Join(c.problems, "\n") != strings.Join(f.References.Problems, "\n") {
		t.Errorf("problems %q, want %q", c.problems, f.References.Problems)
	}
	if strings.Join(c.collisions, ",") != strings.Join(f.References.Collisions, ",") {
		t.Errorf("collisions %q, want %q", c.collisions, f.References.Collisions)
	}
}
