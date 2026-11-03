package dbrijsecrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAPI holds only what Dbrij holds: the fixture's ciphertext and wrapped keys.
type fakeAPI struct {
	t       *testing.T
	mu      sync.Mutex
	bundle  map[string]any
	bearer  string
	down    bool
	saved   []byte
	moved   chan int
	logins  []map[string]any
	answers int
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server, fixture) {
	f, _ := loadFixture(t)
	var b map[string]any
	if err := json.Unmarshal(f.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	tok, _ := ParseToken(f.Token)
	bearer, _ := tok.Bearer()
	api := &fakeAPI{t: t, bundle: b, bearer: bearer, moved: make(chan int, 8)}
	srv := httptest.NewServer(http.StripPrefix("/api/v1", api))
	t.Cleanup(srv.Close)
	return api, srv, f
}

func (a *fakeAPI) send(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data == nil {
		return
	}
	if status < 400 {
		data = map[string]any{"success": true, "data": data}
	}
	_ = json.NewEncoder(w).Encode(data)
}

func (a *fakeAPI) env() map[string]any { return a.bundle["environment"].(map[string]any) }

func (a *fakeAPI) version() int { return int(a.env()["version"].(float64)) }

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case r.URL.Path == "/secrets/machine/login/hint":
		a.send(w, 200, map[string]any{"kind": "kubernetes", "audience": "https://secrets.dbrij.com"})
		return
	case r.URL.Path == "/secrets/machine/login/federated":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.logins = append(a.logins, body)
		if body["token"] != "k.8.s" {
			a.send(w, 403, map[string]any{"message": "Only shop/api may log in as this machine"})
			return
		}
		a.send(w, 201, map[string]any{"accessToken": "dbsa_from_kubernetes", "expiresAt": time.Now().Add(time.Hour).Format(time.RFC3339)})
		return
	}
	if a.down {
		a.send(w, 503, map[string]any{"message": "down"})
		return
	}
	if auth := r.Header.Get("Authorization"); auth != "Bearer "+a.bearer && auth != "Bearer dbsa_from_kubernetes" {
		a.send(w, 401, map[string]any{"message": "That machine token is not valid"})
		return
	}
	switch r.URL.Path {
	case "/secrets/machine/bundle":
		a.answers++
		etag := fmt.Sprintf(`W/"v%d"`, a.version())
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		q := r.URL.Query()
		paths := q["path"]
		if len(paths) == 0 {
			paths = []string{"/"}
		}
		recursive := q.Get("recursive") == "true"
		items := []any{}
		for _, raw := range a.bundle["items"].([]any) {
			it := raw.(map[string]any)
			fp := it["folderPath"].(string)
			for _, p := range paths {
				if fp == p || (recursive && (p == "/" || strings.HasPrefix(fp, p+"/"))) {
					items = append(items, it)
					break
				}
			}
		}
		out := map[string]any{}
		for k, v := range a.bundle {
			out[k] = v
		}
		out["items"], out["etag"] = items, etag
		w.Header().Set("ETag", etag)
		a.send(w, 200, out)
	case "/secrets/machine/changes":
		if r.Header.Get("If-Match") != fmt.Sprintf(`"v%d"`, a.version()) {
			a.send(w, 409, map[string]any{"message": "moved", "code": "environment_changed"})
			return
		}
		var body struct {
			Ops []map[string]any `json:"ops"`
		}
		raw, _ := io.ReadAll(r.Body)
		a.saved = raw
		_ = json.Unmarshal(raw, &body)
		items := a.bundle["items"].([]any)
		for _, op := range body.Ops {
			if op["op"] == "delete" {
				kept := []any{}
				for _, it := range items {
					if it.(map[string]any)["id"] != op["itemId"] {
						kept = append(kept, it)
					}
				}
				items = kept
				continue
			}
			found := false
			for _, it := range items {
				m := it.(map[string]any)
				if m["key"] == op["key"] && m["folderId"] == op["folderId"] {
					m["ciphertext"], m["iv"], m["version"] = op["ciphertext"], op["iv"], m["version"].(float64)+1
					found = true
				}
			}
			if !found {
				items = append(items, map[string]any{"id": fmt.Sprintf("item-%d", len(items)+10), "folderId": op["folderId"], "folderPath": "/", "key": op["key"], "type": "shared", "ownerUserId": nil, "version": 1.0, "keyVersion": 1.0, "ciphertext": op["ciphertext"], "iv": op["iv"]})
			}
		}
		a.bundle["items"] = items
		a.env()["version"] = float64(a.version() + 1)
		a.moved <- a.version()
		a.send(w, 201, map[string]any{"environmentVersion": a.version()})
	case "/secrets/machine/watch":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		a.mu.Unlock()
		defer a.mu.Lock()
		for {
			select {
			case <-r.Context().Done():
				return
			case v := <-a.moved:
				fmt.Fprintf(w, "event: version\ndata: {\"version\":%d}\n\n", v)
				w.(http.Flusher).Flush()
			}
		}
	default:
		a.send(w, 404, map[string]any{"message": "no such route"})
	}
}

func clientFor(t *testing.T, srv *httptest.Server, token string, opts Options) *Client {
	t.Helper()
	opts.Token, opts.BaseURL = token, srv.URL+"/api/v1"
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLoadsAndMergesFolders(t *testing.T) {
	_, srv, f := newFakeAPI(t)
	ctx := context.Background()
	c := clientFor(t, srv, f.Token, Options{})
	values, err := c.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 || values["DATABASE_URL"] != f.Expected["/:DATABASE_URL"] || values["UNICODE"] != f.Expected["/:UNICODE"] {
		t.Fatalf("values %v", values)
	}
	all, err := clientFor(t, srv, f.Token, Options{Recursive: true}).Load(ctx)
	if err != nil || all["API_ONLY"] != "only in /api" {
		t.Fatalf("recursive %v %v", all, err)
	}
	if c.Environment() != "production" || c.Project() != "shop" || c.Version() != 3 {
		t.Fatalf("environment %q project %q version %d", c.Environment(), c.Project(), c.Version())
	}
}

func TestInjectEnvLeavesWhatIsSetWhenAsked(t *testing.T) {
	_, srv, f := newFakeAPI(t)
	c := clientFor(t, srv, f.Token, Options{})
	if _, err := c.InjectEnv(true); err == nil {
		t.Fatal("InjectEnv before Load must refuse")
	}
	if _, err := c.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DATABASE_URL", "keep")
	t.Setenv("UNICODE", "")
	os.Unsetenv("UNICODE")
	set, err := c.InjectEnv(false)
	if err != nil || len(set) != 1 || set[0] != "UNICODE" || os.Getenv("DATABASE_URL") != "keep" || os.Getenv("UNICODE") != f.Expected["/:UNICODE"] {
		t.Fatalf("set %v err %v", set, err)
	}
}

func TestRefreshIsA304UntilSomethingMoves(t *testing.T) {
	api, srv, f := newFakeAPI(t)
	c := clientFor(t, srv, f.Token, Options{})
	ctx := context.Background()
	if _, err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	changed, err := c.Refresh(ctx)
	if err != nil || changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	if api.answers != 2 {
		t.Fatalf("answers %d", api.answers)
	}
}

func TestFailsSoftWhileUnreachableButNeverThroughARefusal(t *testing.T) {
	api, srv, f := newFakeAPI(t)
	ctx := context.Background()
	c := clientFor(t, srv, f.Token, Options{FailSoft: time.Minute})
	if _, err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api.down = true
	if changed, err := c.Refresh(ctx); err != nil || changed || !c.Stale() {
		t.Fatalf("changed %v err %v stale %v", changed, err, c.Stale())
	}
	if v, _ := c.Get("UNICODE"); v != f.Expected["/:UNICODE"] {
		t.Fatalf("stale copy %q", v)
	}
	if err := c.Set(ctx, map[string]string{"X": "1"}, "/", ""); err == nil {
		t.Fatal("nothing may be saved while Dbrij cannot be reached")
	}
	cold := clientFor(t, srv, f.Token, Options{})
	if _, err := cold.Load(ctx); err == nil {
		t.Fatal("with no good copy yet, unreachable is an error")
	}
	api.down = false
	tok, _ := ParseToken(f.Token)
	wrong := clientFor(t, srv, f.Token, Options{FailSoft: time.Minute})
	if _, err := wrong.Load(ctx); err != nil {
		t.Fatal(err)
	}
	wrong.token = &Token{Kind: "token", CredentialHex: tok.CredentialHex, authSecret: strings.Repeat("b", 39), keySecret: tok.keySecret}
	api.bundle["environment"].(map[string]any)["version"] = 99.0
	_, err := wrong.Refresh(ctx)
	var e *Error
	if !errors.As(err, &e) || e.Status != 401 || !strings.Contains(e.Message, "not valid") {
		t.Fatalf("a refusal must never fail soft: %v", err)
	}
}

func TestNoFailSoftTurnsItOffAndZeroMeansAnHour(t *testing.T) {
	api, srv, f := newFakeAPI(t)
	ctx := context.Background()
	if c := clientFor(t, srv, f.Token, Options{}); c.failSoft != time.Hour {
		t.Fatalf("zero must mean one hour, got %v", c.failSoft)
	}
	c := clientFor(t, srv, f.Token, Options{FailSoft: NoFailSoft})
	if _, err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api.down = true
	if _, err := c.Refresh(ctx); err == nil {
		t.Fatal("with NoFailSoft, unreachable is an error at once")
	}
}

func TestSavesSealedValuesAndRetriesOnceWhenAnotherSaveLanded(t *testing.T) {
	api, srv, f := newFakeAPI(t)
	ctx := context.Background()
	c := clientFor(t, srv, f.Token, Options{})
	if _, err := c.Load(ctx); err != nil {
		t.Fatal(err)
	}
	api.env()["version"] = float64(api.version() + 1) // a save elsewhere
	if err := c.Set(ctx, map[string]string{"GENERATED": "from go"}, "/", "job"); err != nil {
		t.Fatal(err)
	}
	if v, _ := c.Get("GENERATED"); v != "from go" {
		t.Fatalf("saved value %q", v)
	}
	if strings.Contains(string(api.saved), "from go") {
		t.Fatal("a value must be sealed before it leaves")
	}
	if err := c.Delete(ctx, []string{"GENERATED"}, "/", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("GENERATED"); ok {
		t.Fatal("deleted value still there")
	}
	if err := c.Set(ctx, map[string]string{"X": "1"}, "/nope", ""); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Fatalf("unknown folder: %v", err)
	}
}

func TestWatchHearsAChangeFromTheStream(t *testing.T) {
	_, srv, f := newFakeAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher := clientFor(t, srv, f.Token, Options{})
	if _, err := watcher.Load(ctx); err != nil {
		t.Fatal(err)
	}
	got := make(chan map[string]string, 1)
	watcher.Watch(ctx, func(v map[string]string) { got <- v }, nil)
	time.Sleep(200 * time.Millisecond) // let the stream open
	writer := clientFor(t, srv, f.Token, Options{})
	if err := writer.Set(ctx, map[string]string{"FROM_WATCH": "yes"}, "/", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-got:
		if v["FROM_WATCH"] != "yes" {
			t.Fatalf("watch values %v", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watch never heard the change")
	}
}

func TestALoginKeyLogsInWithItsPlatformIdentity(t *testing.T) {
	api, srv, f := newFakeAPI(t)
	tok, _ := ParseToken(f.Token)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte("k.8.s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("DBRIJ_SECRETS_KUBERNETES_TOKEN_FILE", file)
	c := clientFor(t, srv, formatKey(tok.CredentialHex, tok.keySecret), Options{})
	values, err := c.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if values["DATABASE_URL"] != f.Expected["/:DATABASE_URL"] || len(api.logins) != 1 || api.logins[0]["credential"] != tok.CredentialHex {
		t.Fatalf("values %v logins %v", values, api.logins)
	}
	// The access token is kept until it is near its end: no second login.
	if _, err := c.Refresh(context.Background()); err != nil || len(api.logins) != 1 {
		t.Fatalf("logins %d err %v", len(api.logins), err)
	}
	if err := os.WriteFile(file, []byte("someone.else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := clientFor(t, srv, formatKey(tok.CredentialHex, tok.keySecret), Options{})
	if _, err := other.Load(context.Background()); err == nil || !strings.Contains(err.Error(), "Only shop/api") {
		t.Fatalf("the wrong identity must be refused: %v", err)
	}
}

func TestNewSaysWhatIsMissing(t *testing.T) {
	t.Setenv("DBRIJ_SECRETS_TOKEN", "")
	t.Setenv("DBRIJ_SECRETS_KEY", "")
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "give a machine token") {
		t.Fatalf("no token: %v", err)
	}
	if _, err := New(Options{Token: "dbs_short"}); err == nil {
		t.Fatal("a short token must be refused before anything is sent")
	}
}
