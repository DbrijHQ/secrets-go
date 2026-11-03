// Package dbrijsecrets loads an environment's secrets from Dbrij Secrets with a machine
// token and opens them in this process.
//
//	secrets, err := dbrijsecrets.New(dbrijsecrets.Options{Environment: "production"})
//	if err != nil { ... }
//	if _, err := secrets.Load(ctx); err != nil { ... }
//	databaseURL, _ := secrets.Get("DATABASE_URL")
//
// Dbrij sends only ciphertext and keys wrapped to this machine; the token's key half, which
// never leaves the machine, opens them. Refresh asks with the last ETag, so an unchanged
// environment costs one small request. If Dbrij cannot be reached, the last good copy keeps
// being served for Options.FailSoft (a refusal never fails soft).
package dbrijsecrets

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBaseURL is the API address used when neither Options.BaseURL nor DBRIJ_API_URL is set.
	DefaultBaseURL  = "https://api.dbrij.com/api/v1"
	defaultAudience = "https://secrets.dbrij.com"
	// Version is this SDK's version.
	Version = "0.1.0"
	// NoFailSoft, as Options.FailSoft, turns failing soft off: a Load or Refresh that cannot
	// reach Dbrij returns the error at once. (Zero means one hour, because an Options left
	// empty has to mean the default. Node's failSoftMs: 0 and Python's fail_soft_seconds=0
	// turn it off; in Go, use NoFailSoft or any negative duration.)
	NoFailSoft time.Duration = -1
)

// Error is what every call returns when Dbrij refuses or cannot be reached.
type Error struct {
	Message string
	// Status is the HTTP status, or 0 when Dbrij could not be reached.
	Status int
	// Code is Dbrij's error code, such as environment_changed, when it gave one.
	Code string
}

func (e *Error) Error() string { return e.Message }

func errorf(status int, format string, args ...any) *Error {
	return &Error{Message: fmt.Sprintf(format, args...), Status: status}
}

// Options configure a Client. Every field is optional.
type Options struct {
	// Token is a machine token (dbs_...) or login key (dbsk_...). Defaults to
	// DBRIJ_SECRETS_TOKEN, then DBRIJ_SECRETS_KEY.
	Token string
	// Environment is the environment's short name. Defaults to DBRIJ_SECRETS_ENV, or the
	// only environment the machine reads.
	Environment string
	// Paths are folders to merge in order, a later one winning. Defaults to ["/"].
	Paths []string
	// Recursive includes the folders inside each path.
	Recursive bool
	// BaseURL defaults to DBRIJ_API_URL, then DefaultBaseURL.
	BaseURL string
	// FailSoft is how long the last good copy is served while Dbrij cannot be reached.
	// Zero means one hour; NoFailSoft (or any negative value) turns it off. This differs
	// from Node, where failSoftMs: 0 turns it off.
	FailSoft time.Duration
	// Timeout is per request. Zero means ten seconds.
	Timeout time.Duration
	// GitHubAudience is the audience asked for in GitHub Actions. Defaults to https://secrets.dbrij.com.
	GitHubAudience string
	// HTTPClient sends every request. Defaults to a client with no overall timeout (each
	// request carries its own, and the watch stream stays open).
	HTTPClient *http.Client
}

type bundleEnvironment struct {
	ID         string `json:"id"`
	Slug       string `json:"slug"`
	Name       string `json:"name"`
	Version    int    `json:"version"`
	KeyVersion int    `json:"keyVersion"`
	Protected  bool   `json:"protected"`
}

type bundleItem struct {
	ID          string  `json:"id"`
	FolderID    *string `json:"folderId"`
	FolderPath  string  `json:"folderPath"`
	Key         string  `json:"key"`
	Type        string  `json:"type"`
	OwnerUserID *string `json:"ownerUserId"`
	Version     int     `json:"version"`
	KeyVersion  int     `json:"keyVersion"`
	Ciphertext  string  `json:"ciphertext"`
	IV          string  `json:"iv"`
	// B5: a template's references; the folder an imported value counts for and its rank;
	// set when the secret is sent only to fill a template.
	Refs         []SecretsRef `json:"refs"`
	ImportedInto string       `json:"importedInto"`
	ImportRank   int          `json:"importRank"`
	ViaReference bool         `json:"viaReference"`
}

type wrapView struct {
	KeyVersion int    `json:"keyVersion"`
	Wrapped    string `json:"wrapped"`
}

type bundle struct {
	Project struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"project"`
	Environment bundleEnvironment `json:"environment"`
	Access      string            `json:"access"`
	Holder      struct {
		Kind                string `json:"kind"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
		KeySalt             string `json:"keySalt"`
	} `json:"holder"`
	Wraps   []wrapView `json:"wraps"`
	Folders []struct {
		ID   string `json:"id"`
		Path string `json:"path"`
	} `json:"folders"`
	Items []bundleItem `json:"items"`
	// B5: other environments a template here is built from, as far as the reader may read them.
	Referenced []struct {
		Environment struct {
			ID         string `json:"id"`
			Slug       string `json:"slug"`
			Name       string `json:"name"`
			KeyVersion int    `json:"keyVersion"`
		} `json:"environment"`
		Wraps []wrapView   `json:"wraps"`
		Items []bundleItem `json:"items"`
	} `json:"referenced"`
	ETag string `json:"etag"`
}

// Client holds one environment's secrets, opened in this process. It is safe for use by
// several goroutines.
type Client struct {
	token          *Token
	environment    string
	paths          []string
	recursive      bool
	base           string
	failSoft       time.Duration
	timeout        time.Duration
	githubAudience string
	http           *http.Client
	proofs         proofContext

	mu          sync.Mutex
	privateKey  *rsa.PrivateKey
	accessToken string
	accessUntil time.Time
	bundle      *bundle
	values      map[string]string
	goodAt      time.Time
	stale       bool
	problems    []string
	collisions  []string
}

// New reads the token and options. It makes no request.
func New(opts Options) (*Client, error) {
	raw := opts.Token
	if raw == "" {
		raw = os.Getenv("DBRIJ_SECRETS_TOKEN")
	}
	if raw == "" {
		raw = os.Getenv("DBRIJ_SECRETS_KEY")
	}
	if raw == "" {
		return nil, errorf(0, "give a machine token: Options.Token, or DBRIJ_SECRETS_TOKEN")
	}
	token, err := ParseToken(raw)
	if err != nil {
		return nil, &Error{Message: err.Error()}
	}
	c := &Client{
		token:          token,
		environment:    opts.Environment,
		paths:          opts.Paths,
		recursive:      opts.Recursive,
		base:           opts.BaseURL,
		failSoft:       opts.FailSoft,
		timeout:        opts.Timeout,
		githubAudience: opts.GitHubAudience,
		http:           opts.HTTPClient,
	}
	if c.environment == "" {
		c.environment = os.Getenv("DBRIJ_SECRETS_ENV")
	}
	if len(c.paths) == 0 {
		c.paths = []string{"/"}
	}
	if c.base == "" {
		c.base = os.Getenv("DBRIJ_API_URL")
	}
	if c.base == "" {
		c.base = DefaultBaseURL
	}
	c.base = strings.TrimRight(c.base, "/")
	if c.failSoft == 0 {
		c.failSoft = time.Hour
	}
	if c.timeout == 0 {
		c.timeout = 10 * time.Second
	}
	if c.githubAudience == "" {
		c.githubAudience = defaultAudience
	}
	if c.http == nil {
		c.http = &http.Client{}
	}
	c.proofs = defaultProofContext(&http.Client{Timeout: c.timeout})
	return c, nil
}

// ── Reading ─────────────────────────────────────────────────────────────────────

// Load fetches and opens the environment, and returns its values.
func (c *Client) Load(ctx context.Context) (map[string]string, error) {
	if _, err := c.Refresh(ctx); err != nil {
		return nil, err
	}
	return c.All(), nil
}

// Refresh asks for the latest. It reports whether the values changed.
func (c *Client) Refresh(ctx context.Context) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refreshLocked(ctx)
}

func (c *Client) refreshLocked(ctx context.Context) (bool, error) {
	status, b, err := c.fetchBundle(ctx)
	if err != nil {
		var e *Error
		unreachable := !errors.As(err, &e) || e.Status == 0 || e.Status >= 500 || e.Status == 429
		if c.values != nil && unreachable && c.failSoft > 0 && time.Since(c.goodAt) < c.failSoft {
			c.stale = true
			return false, nil
		}
		return false, err
	}
	c.goodAt = time.Now()
	c.stale = false
	if status == http.StatusNotModified && c.values != nil {
		return false, nil
	}
	if b == nil {
		return false, errorf(status, "Dbrij answered without the environment")
	}
	values, err := c.open(b)
	if err != nil {
		return false, err
	}
	changed := !sameValues(c.values, values)
	c.bundle = b
	c.environment = b.Environment.Slug
	c.values = values
	return changed, nil
}

// Get gives one value. The second result is false when the name is not there, or before Load.
func (c *Client) Get(name string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.values[name]
	return v, ok
}

// All gives a copy of every value; nil before Load.
func (c *Client) All() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.values == nil {
		return nil
	}
	out := make(map[string]string, len(c.values))
	for k, v := range c.values {
		out[k] = v
	}
	return out
}

// InjectEnv puts the values into this process's environment and returns the names set.
// With override false, a name already set is left alone.
func (c *Client) InjectEnv(override bool) ([]string, error) {
	values := c.All()
	if values == nil {
		return nil, errorf(0, "call Load first")
	}
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	done := []string{}
	for _, k := range names {
		if _, set := os.LookupEnv(k); set && !override {
			continue
		}
		if err := os.Setenv(k, values[k]); err != nil {
			return done, err
		}
		done = append(done, k)
	}
	return done, nil
}

// Stale reports whether the values are the last good copy, served while Dbrij cannot be reached.
func (c *Client) Stale() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stale
}

// Problems lists values that did not open, with what to do about each.
func (c *Client) Problems() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.problems...)
}

// Collisions lists names given by more than one folder (the later path, then the deeper folder, wins).
func (c *Client) Collisions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.collisions...)
}

// Environment is the environment's short name, once loaded.
func (c *Client) Environment() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.environment
}

// Version is the environment's version the values come from, once loaded; 0 before.
func (c *Client) Version() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bundle == nil {
		return 0
	}
	return c.bundle.Environment.Version
}

// Project is the short name of the project the machine reads, once loaded.
func (c *Client) Project() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.bundle == nil {
		return ""
	}
	return c.bundle.Project.Slug
}

// Watch calls onChange whenever the environment's values change, from a stream of its
// version (a few seconds after a save). It reconnects on its own until ctx is done, or
// until Dbrij refuses the machine (onError hears why). onError may be nil.
func (c *Client) Watch(ctx context.Context, onChange func(map[string]string), onError func(error)) {
	go func() {
		delay := time.Second
		for ctx.Err() == nil {
			err := c.stream(ctx, func(version int) {
				delay = time.Second
				c.mu.Lock()
				current := c.bundle != nil && version <= c.bundle.Environment.Version
				c.mu.Unlock()
				if current {
					return
				}
				changed, err := c.Refresh(ctx)
				if err != nil {
					if onError != nil {
						onError(err)
					}
					return
				}
				if changed {
					onChange(c.All())
				}
			})
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if onError != nil {
					onError(err)
				}
				var e *Error
				if errors.As(err, &e) && (e.Status == 401 || e.Status == 403 || e.Status == 404) {
					return
				}
				delay = min(delay*2, time.Minute)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
}

// ── Writing ─────────────────────────────────────────────────────────────────────

// Set saves values into a folder ("/" for the top), for a machine with write access. They
// are sealed here first. If the environment changed meanwhile, it reloads and tries once more.
func (c *Client) Set(ctx context.Context, values map[string]string, path, message string) error {
	names := make([]string, 0, len(values))
	for k := range values {
		names = append(names, k)
	}
	sort.Strings(names)
	return c.write(ctx, message, func(b *bundle, envKey []byte) ([]map[string]any, error) {
		folderID, err := folderOf(b, path)
		if err != nil {
			return nil, err
		}
		ops := []map[string]any{}
		for _, key := range names {
			expected := 0
			if existing := existingItem(b, folderID, key); existing != nil {
				expected = existing.Version
			}
			ciphertext, iv, err := sealValue(envKey, secretsAAD(b.Environment.ID, folderID, key, nil), values[key], "")
			if err != nil {
				return nil, err
			}
			ops = append(ops, map[string]any{"op": "set", "folderId": folderID, "key": key, "type": "shared", "expectedVersion": expected, "keyVersion": b.Environment.KeyVersion, "ciphertext": ciphertext, "iv": iv})
		}
		return ops, nil
	})
}

// Delete removes names from a folder, for a machine with write access.
func (c *Client) Delete(ctx context.Context, names []string, path, message string) error {
	return c.write(ctx, message, func(b *bundle, _ []byte) ([]map[string]any, error) {
		folderID, err := folderOf(b, path)
		if err != nil {
			return nil, err
		}
		ops := []map[string]any{}
		for _, key := range names {
			existing := existingItem(b, folderID, key)
			if existing == nil {
				return nil, errorf(404, "%s is not in %s", key, cleanPath(path))
			}
			ops = append(ops, map[string]any{"op": "delete", "itemId": existing.ID, "expectedVersion": existing.Version})
		}
		return ops, nil
	})
}

func (c *Client) write(ctx context.Context, message string, makeOps func(*bundle, []byte) ([]map[string]any, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := c.refreshLocked(ctx); err != nil {
			return err
		}
		if c.stale {
			return errorf(0, "Dbrij Secrets cannot be reached, so nothing was saved")
		}
		b := c.bundle
		if b.Access == "reader" {
			return errorf(403, "this machine reads %s but cannot change it", b.Environment.Name)
		}
		var wrapped string
		for _, w := range b.Wraps {
			if w.KeyVersion == b.Environment.KeyVersion {
				wrapped = w.Wrapped
			}
		}
		if wrapped == "" {
			return errorf(403, "this machine does not hold the current %s key", b.Environment.Name)
		}
		envKey, err := unwrapEnvironmentKey(wrapped, c.privateKey)
		if err != nil {
			return errorf(0, "the %s key did not open on this machine", b.Environment.Name)
		}
		ops, err := makeOps(b, envKey)
		if err != nil {
			return err
		}
		if len(ops) == 0 {
			return nil
		}
		idem := make([]byte, 18)
		if _, err := rand.Read(idem); err != nil {
			return err
		}
		body := map[string]any{"ops": ops, "idempotencyKey": base64.RawURLEncoding.EncodeToString(idem), "source": "api"}
		if message != "" {
			body["message"] = message
		}
		_, _, err = c.request(ctx, "POST", "/secrets/machine/changes?env="+url.QueryEscape(b.Environment.Slug), body, map[string]string{"If-Match": fmt.Sprintf(`"v%d"`, b.Environment.Version)}, true)
		if err == nil {
			_, err = c.refreshLocked(ctx)
			return err
		}
		var e *Error
		if attempt == 0 && errors.As(err, &e) && e.Status == 409 {
			continue
		}
		return err
	}
	return nil
}

func cleanPath(path string) string {
	p := strings.TrimRight(path, "/")
	if p == "" {
		return "/"
	}
	return p
}

func folderOf(b *bundle, path string) (*string, error) {
	p := cleanPath(path)
	if p == "/" {
		return nil, nil
	}
	for _, f := range b.Folders {
		if f.Path == p {
			id := f.ID
			return &id, nil
		}
	}
	return nil, errorf(404, "%s is not a folder in %s. Create it in Dbrij first", p, b.Environment.Name)
}

func existingItem(b *bundle, folderID *string, key string) *bundleItem {
	for i := range b.Items {
		it := &b.Items[i]
		if it.Type == "shared" && it.Key == key && sameFolder(it.FolderID, folderID) {
			return it
		}
	}
	return nil
}

func sameFolder(a, b *string) bool {
	if a == nil || *a == "" {
		return b == nil || *b == ""
	}
	return b != nil && *a == *b
}

func sameValues(a, b map[string]string) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// ── Opening ─────────────────────────────────────────────────────────────────────

func depth(path string) int {
	if path == "/" {
		return 0
	}
	return strings.Count(path, "/")
}

type openedItem struct {
	bundleItem
	value       string
	environment string
}

// openItems opens one environment's items with its wrapped keys; what does not open is a problem, in words.
func (c *Client) openItems(envID, envName string, wraps []wrapView, items []bundleItem, slug string) []openedItem {
	keys := map[int][]byte{}
	tried := map[int]bool{}
	var out []openedItem
	for _, item := range items {
		if item.Ciphertext == "" || item.IV == "" {
			continue
		}
		if !tried[item.KeyVersion] {
			tried[item.KeyVersion] = true
			for _, w := range wraps {
				if w.KeyVersion == item.KeyVersion {
					if k, err := unwrapEnvironmentKey(w.Wrapped, c.privateKey); err == nil {
						keys[item.KeyVersion] = k
					}
				}
			}
		}
		envKey := keys[item.KeyVersion]
		if envKey == nil {
			c.problems = append(c.problems, fmt.Sprintf("%s was saved under a key this machine does not hold. Ask a project admin to replace the %s key", item.Key, envName))
			continue
		}
		var owner *string
		if item.Type == "personal" {
			owner = item.OwnerUserID
		}
		payload, ok := openValue(envKey, secretsAAD(envID, item.FolderID, item.Key, owner), item.Ciphertext, item.IV)
		if !ok {
			c.problems = append(c.problems, fmt.Sprintf("%s did not open: it does not belong where it is stored", item.Key))
			continue
		}
		out = append(out, openedItem{bundleItem: item, value: payload.V, environment: slug})
	}
	return out
}

func (c *Client) open(b *bundle) (map[string]string, error) {
	if b.Holder.Kind != "machine" {
		return nil, errorf(0, "this is not a machine bundle")
	}
	if c.privateKey == nil {
		key, err := openMachinePrivateKey(c.token.keySecret, b.Holder.KeySalt, b.Holder.EncryptedPrivateKey)
		if err != nil {
			return nil, &Error{Message: err.Error()}
		}
		c.privateKey = key
	}
	c.problems = nil
	own := b.Environment.Slug
	opened := c.openItems(b.Environment.ID, b.Environment.Name, b.Wraps, b.Items, own)
	var referenced []openedItem
	for _, r := range b.Referenced {
		referenced = append(referenced, c.openItems(r.Environment.ID, r.Environment.Name, r.Wraps, r.Items, r.Environment.Slug)...)
	}

	// A later path wins, then a deeper folder: the same order as the Node SDK and the CLI.
	// What a folder imports counts for that folder, below everything that is its own.
	at := func(o openedItem) string {
		if o.ImportedInto != "" {
			return o.ImportedInto
		}
		return o.FolderPath
	}
	rank := func(o openedItem) int {
		best := -1
		for i, p := range c.paths {
			if at(o) == p || p == "/" || strings.HasPrefix(at(o), p+"/") {
				best = i
			}
		}
		return best
	}
	ownValue := func(o openedItem) int {
		if o.ImportedInto != "" {
			return 0
		}
		return 1
	}
	personal := func(o openedItem) int {
		if o.Type == "personal" {
			return 1
		}
		return 0
	}
	var mine []openedItem
	for _, o := range opened {
		if !o.ViaReference {
			mine = append(mine, o)
		}
	}
	sort.SliceStable(mine, func(i, j int) bool {
		a, b := mine[i], mine[j]
		for _, d := range []int{rank(a) - rank(b), ownValue(a) - ownValue(b), a.ImportRank - b.ImportRank, depth(at(a)) - depth(at(b)), personal(a) - personal(b)} {
			if d != 0 {
				return d < 0
			}
		}
		return false
	})
	winners := map[string]openedItem{}
	order := []string{}
	seen := map[string]string{}
	collisions := map[string]bool{}
	for _, o := range mine {
		before, had := winners[o.Key]
		if place, set := seen[o.Key]; set && !(o.Type == "personal" && place == o.FolderPath) && o.ImportedInto == "" && !(had && before.ImportedInto != "") {
			collisions[o.Key] = true
		}
		if !had {
			order = append(order, o.Key)
		}
		winners[o.Key] = o
		seen[o.Key] = o.FolderPath
	}
	c.collisions = c.collisions[:0]
	for k := range collisions {
		c.collisions = append(c.collisions, k)
	}
	sort.Strings(c.collisions)

	// Templates are filled in here, from the secrets the bundle carried (a person's own value first).
	place := map[string]openedItem{}
	for _, o := range append(append([]openedItem{}, opened...), referenced...) {
		id := refID(o.environment, o.FolderPath, o.Key)
		if prev, ok := place[id]; !ok || (prev.Type != "personal" && o.Type == "personal") {
			place[id] = o
		}
	}
	var fill func(o openedItem, env string, trail []string) (string, string)
	fill = func(o openedItem, env string, trail []string) (string, string) {
		if len(o.Refs) == 0 {
			return o.value, ""
		}
		here := refID(env, o.FolderPath, o.Key)
		for _, t := range trail {
			if t == here {
				return "", o.Key + " is built from itself, through its references"
			}
		}
		if len(trail) > maxRefDepth {
			return "", fmt.Sprintf("%s leads through more than %d references", o.Key, maxRefDepth)
		}
		return fillTemplate(o.value, o.FolderPath, func(refEnv, path, key string) (string, string) {
			envOf := refEnv
			if envOf == "" {
				envOf = env
			}
			target, ok := place[refID(envOf, path, key)]
			labelEnv := envOf
			if envOf == own {
				labelEnv = ""
			}
			if !ok {
				if envOf == own {
					return "", refLabel(labelEnv, path, key) + " is not there"
				}
				return "", refLabel(labelEnv, path, key) + " is not there, or this reader may not read " + envOf
			}
			return fill(target, envOf, append(append([]string{}, trail...), here))
		})
	}
	values := map[string]string{}
	for _, key := range order {
		value, problem := fill(winners[key], own, nil)
		if problem != "" {
			c.problems = append(c.problems, key+" could not be filled in: "+problem)
			continue
		}
		values[key] = value
	}
	return values, nil
}

// ── Talking to Dbrij ────────────────────────────────────────────────────────────

func (c *Client) query() string {
	q := url.Values{}
	if c.environment != "" {
		q.Set("env", c.environment)
	}
	for _, p := range c.paths {
		q.Add("path", p)
	}
	if c.recursive {
		q.Set("recursive", "true")
	}
	return q.Encode()
}

func (c *Client) fetchBundle(ctx context.Context) (int, *bundle, error) {
	headers := map[string]string{}
	if c.bundle != nil && c.bundle.ETag != "" {
		headers["If-None-Match"] = c.bundle.ETag
	}
	status, data, err := c.request(ctx, "GET", "/secrets/machine/bundle?"+c.query(), nil, headers, true)
	if err != nil || status == http.StatusNotModified {
		return status, nil, err
	}
	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return status, nil, errorf(status, "Dbrij's answer did not read: %v", err)
	}
	return status, &b, nil
}

func (c *Client) bearer(ctx context.Context) (string, error) {
	if c.token.Kind == "token" {
		return c.token.Bearer()
	}
	if c.accessToken != "" && time.Until(c.accessUntil) > time.Minute {
		return c.accessToken, nil
	}
	requestURL, requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL == "" || requestToken == "" {
		// Outside GitHub Actions: Dbrij says which platform the key logs in with, and its proof goes instead.
		return c.federatedLogin(ctx)
	}
	sep := "?"
	if strings.Contains(requestURL, "?") {
		sep = "&"
	}
	status, text, err := c.proofs.open(ctx, "GET", requestURL+sep+"audience="+url.QueryEscape(c.githubAudience), map[string]string{"Authorization": "Bearer " + requestToken}, "")
	if err != nil || status != 200 {
		return "", errorf(status, "GitHub Actions did not give an OIDC token (%d)", status)
	}
	var oidc struct {
		Value string `json:"value"`
	}
	if json.Unmarshal([]byte(text), &oidc) != nil || oidc.Value == "" {
		return "", errorf(0, "GitHub Actions answered without an OIDC token")
	}
	return c.login(ctx, "/secrets/machine/login/github", map[string]any{"credential": c.token.CredentialHex, "token": oidc.Value})
}

func (c *Client) federatedLogin(ctx context.Context) (string, error) {
	_, data, err := c.request(ctx, "GET", "/secrets/machine/login/hint?credential="+c.token.CredentialHex, nil, nil, false)
	if err != nil {
		return "", err
	}
	var hint struct {
		Kind     string `json:"kind"`
		Audience string `json:"audience"`
	}
	if err := json.Unmarshal(data, &hint); err != nil {
		return "", errorf(0, "Dbrij's answer did not read: %v", err)
	}
	if hint.Kind == "github" {
		return "", errorf(0, "this key logs in from GitHub Actions. Give the job permission id-token: write")
	}
	p, err := platformProof(ctx, hint.Kind, hint.Audience, c.proofs)
	if err != nil {
		return "", &Error{Message: err.Error()}
	}
	body := map[string]any{"credential": c.token.CredentialHex}
	if p.AWS != nil {
		body["aws"] = p.AWS
	} else {
		body["token"] = p.Token
	}
	return c.login(ctx, "/secrets/machine/login/federated", body)
}

func (c *Client) login(ctx context.Context, path string, body map[string]any) (string, error) {
	_, data, err := c.request(ctx, "POST", path, body, nil, false)
	if err != nil {
		return "", err
	}
	var login struct {
		AccessToken string    `json:"accessToken"`
		ExpiresAt   time.Time `json:"expiresAt"`
	}
	if err := json.Unmarshal(data, &login); err != nil || login.AccessToken == "" {
		return "", errorf(0, "Dbrij answered the login without an access token")
	}
	c.accessToken, c.accessUntil = login.AccessToken, login.ExpiresAt
	return login.AccessToken, nil
}

// request sends one call and unwraps Dbrij's { success, data } envelope.
func (c *Client) request(ctx context.Context, method, path string, body any, headers map[string]string, auth bool) (int, json.RawMessage, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dbrij-secrets-go/"+Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if auth {
		bearer, err := c.bearer(ctx)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errorf(0, "could not reach Dbrij Secrets: %v", err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
	if err != nil {
		return 0, nil, errorf(0, "could not reach Dbrij Secrets: %v", err)
	}
	if res.StatusCode == http.StatusNotModified {
		return res.StatusCode, nil, nil
	}
	if res.StatusCode >= 400 {
		var e struct {
			Message any    `json:"message"`
			Code    string `json:"code"`
		}
		_ = json.Unmarshal(raw, &e)
		message := fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
		switch m := e.Message.(type) {
		case string:
			message = m
		case []any:
			parts := make([]string, len(m))
			for i, p := range m {
				parts[i] = fmt.Sprint(p)
			}
			message = strings.Join(parts, "; ")
		}
		return res.StatusCode, nil, &Error{Message: message, Status: res.StatusCode, Code: e.Code}
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) == nil && envelope.Data != nil {
		return res.StatusCode, envelope.Data, nil
	}
	return res.StatusCode, raw, nil
}

// stream follows the environment's version stream (server sent events) until it ends.
func (c *Client) stream(ctx context.Context, onVersion func(int)) error {
	c.mu.Lock()
	bearer, err := c.bearer(ctx)
	q := c.query()
	c.mu.Unlock()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.base+"/secrets/machine/watch?"+q, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", "dbrij-secrets-go/"+Version)
	res, err := c.http.Do(req)
	if err != nil {
		return errorf(0, "could not reach Dbrij Secrets: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		var e struct {
			Message string `json:"message"`
		}
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
		}
		return &Error{Message: e.Message, Status: res.StatusCode}
	}
	scanner := bufio.NewScanner(res.Body)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case line == "":
			if event == "version" && data != "" {
				var v struct {
					Version int `json:"version"`
				}
				if json.Unmarshal([]byte(data), &v) == nil {
					onVersion(v.Version)
				}
			}
			if event == "end" {
				reason := "reconnect"
				var r struct {
					Reason string `json:"reason"`
				}
				if data != "" && json.Unmarshal([]byte(data), &r) == nil && r.Reason != "" {
					reason = r.Reason
				}
				if reason != "reconnect" {
					return &Error{Message: reason, Status: 401}
				}
				return nil
			}
			event, data = "", ""
		}
	}
	return scanner.Err()
}
