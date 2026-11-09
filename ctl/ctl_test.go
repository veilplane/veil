// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package ctl

import (
	"bytes"
	"context"
	"encoding/json"
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

// fakeAPI is a small stand-in for the management API: one person, one organization.
type fakeAPI struct {
	mu       sync.Mutex
	orgs     []map[string]any
	clusters []map[string]any
	features map[string]any
	calls    []string
	token    string // a valid API token
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	f := &fakeAPI{
		orgs:     []map[string]any{{"slug": "acme", "name": "Acme", "plan": "free", "admin": true}},
		clusters: []map[string]any{{"id": "k7f3m2x9q1ab", "name": "web", "region": "eu", "revision": 7, "sizeBytes": 1500000, "quotaBytes": 4 << 30, "features": map[string]any{"proxy": true, "mesh": false}}},
		token:    "vpt_good",
	}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	problem := func(status int, detail string) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "detail": detail})
	}
	switch r.URL.Path {
	case "/api/v1/auth/link":
		w.WriteHeader(http.StatusAccepted)
		return
	case "/api/v1/auth/link/verify":
		var b struct{ Token string }
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Token != "tok123" {
			problem(403, "this link is invalid, used or expired; ask for a new one")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-veilplane", Value: "sess-abc", Path: "/", HttpOnly: true})
		reply(200, map[string]any{"userId": "u1", "email": "julian@example.com", "newAccount": false})
		return
	}
	authed := r.Header.Get("Cookie") == "__Host-veilplane=sess-abc" || r.Header.Get("Authorization") == "Bearer "+f.token
	if !authed {
		w.WriteHeader(http.StatusUnauthorized) // no body, like the backend for a bad token
		return
	}
	switch {
	case r.URL.Path == "/api/v1/me/orgs":
		reply(200, f.orgs)
	case r.URL.Path == "/api/v1/me/invitations":
		reply(200, []any{})
	case r.URL.Path == "/api/v1/orgs/acme" && r.Method == "GET":
		reply(200, map[string]any{"slug": "acme", "name": "Acme", "plan": "free", "status": "active", "admin": true})
	case r.URL.Path == "/api/v1/orgs/acme/clusters" && r.Method == "GET":
		reply(200, f.clusters)
	case r.URL.Path == "/api/v1/orgs/acme/clusters" && r.Method == "POST":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		reply(201, map[string]any{"id": "newid", "name": b["name"], "region": b["region"]})
	case r.URL.Path == "/api/v1/orgs/acme/clusters/k7f3m2x9q1ab" && r.Method == "GET":
		reply(200, f.clusters[0])
	case r.URL.Path == "/api/v1/orgs/acme/clusters/k7f3m2x9q1ab" && r.Method == "DELETE":
		reply(200, f.clusters[0])
	case strings.HasPrefix(r.URL.Path, "/api/v1/orgs/acme/clusters/") && r.Method == "GET" && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/api/v1/orgs/acme/clusters/"), "/"):
		problem(404, "no such cluster")
	case r.URL.Path == "/api/v1/orgs/acme/clusters/k7f3m2x9q1ab/features":
		_ = json.NewDecoder(r.Body).Decode(&f.features)
		c := f.clusters[0]
		c["features"] = f.features
		reply(200, c)
	case r.URL.Path == "/api/v1/orgs/acme/clusters/k7f3m2x9q1ab/devices":
		reply(200, []any{map[string]any{"node": "cp-1", "role": "control-plane", "firstSeen": "2026-01-01T00:00:00Z",
			"agent": map[string]any{"reportedAt": time.Now().UTC().Format(time.RFC3339), "status": map[string]any{
				"version": "v1.0.0", "state": "running", "backend": map[string]any{"connected": true},
				"features": map[string]any{
					"proxy": map[string]any{"wanted": true, "allowed": true, "state": "running", "revision": 42},
					"mesh": map[string]any{"wanted": true, "allowed": true, "state": "running",
						"mesh": map[string]any{"warnings": []string{"Tailscale runs here and drops packets"}}}}}}}})
	case r.URL.Path == "/api/v1/orgs/acme/clusters/k7f3m2x9q1ab/join-codes":
		reply(201, map[string]any{"code": "vp1.eu.abc", "expiresAt": "2030-01-01T00:00:00Z"})
	default:
		problem(404, "not here: "+r.URL.Path)
	}
}

// run runs veilctl with its own configuration file against the fake API.
func run(t *testing.T, cfg, api string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	t.Setenv("VEILCTL_CONFIG", cfg)
	t.Setenv("VEILCTL_API", api)
	for _, v := range []string{"VEILCTL_TOKEN", "VEILCTL_ORG", "VEILCTL_CONTEXT"} {
		t.Setenv(v, "")
	}
	var out, errb bytes.Buffer
	code = Run(context.Background(), args, "test", Env{In: strings.NewReader(""), Out: &out, Err: &errb})
	return out.String(), errb.String(), code
}

func signIn(t *testing.T, cfg, api string) {
	t.Helper()
	if _, errs, code := run(t, cfg, api, "login", "--email", "julian@example.com", "--link", "https://app.veilplane.com/auth/link?token=tok123"); code != 0 {
		t.Fatalf("login: %d %s", code, errs)
	}
}

func TestLoginKeepsTheSessionPrivately(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "veilctl", "config.json")
	_, errs, code := run(t, cfg, srv.URL, "login", "--email", "julian@example.com", "--link", "https://app.veilplane.com/auth/link?token=tok123")
	if code != 0 || !strings.Contains(errs, "Signed in as julian@example.com") || !strings.Contains(errs, "Organization: acme") {
		t.Fatalf("login: %d\n%s", code, errs)
	}
	st, err := os.Stat(cfg)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", st, err)
	}
	raw, _ := os.ReadFile(cfg)
	var c Config
	_ = json.Unmarshal(raw, &c)
	if cx := c.Contexts["default"]; cx == nil || cx.Session != "__Host-veilplane=sess-abc" || cx.Org != "acme" {
		t.Fatalf("saved: %s", raw)
	}
}

// Asked on the terminal: the address, then the link, both typed in one go (pasted).
func TestLoginAsksOnTheTerminal(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("VEILCTL_CONFIG", cfg)
	t.Setenv("VEILCTL_API", srv.URL)
	t.Setenv("VEILCTL_TOKEN", "")
	var out, errb bytes.Buffer
	in := strings.NewReader("julian@example.com\nhttps://app.veilplane.com/auth/link?token=tok123\n")
	code := Run(context.Background(), []string{"login"}, "test", Env{In: in, Out: &out, Err: &errb, TTY: true})
	if code != 0 || !strings.Contains(errb.String(), "E-mail address:") || !strings.Contains(errb.String(), "Link:") ||
		!strings.Contains(errb.String(), "Signed in as julian@example.com") {
		t.Fatalf("%d\n%s", code, errb.String())
	}
	// and a confirmation typed wrong cancels
	out.Reset()
	errb.Reset()
	code = Run(context.Background(), []string{"clusters", "delete", "web"}, "test", Env{In: strings.NewReader("wbe\n"), Out: &out, Err: &errb, TTY: true})
	if code != 1 || !strings.Contains(errb.String(), "canceled") {
		t.Fatalf("%d %s", code, errb.String())
	}
}

func TestLoginWithAUsedLink(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	_, errs, code := run(t, cfg, srv.URL, "login", "--email", "julian@example.com", "--link", "https://x/auth/link?token=old")
	if code != 1 || !strings.Contains(errs, "used or expired") {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestClustersTableAndJSON(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	out, errs, code := run(t, cfg, srv.URL, "clusters")
	if code != 0 || !strings.Contains(out, "k7f3m2x9q1ab") || !strings.Contains(out, "1.5 MB / 4 GiB") || strings.Contains(out, "\x1b[") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	out, _, code = run(t, cfg, srv.URL, "clusters", "--json")
	var list []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &list) != nil || list[0]["id"] != "k7f3m2x9q1ab" {
		t.Fatalf("json: %d %s", code, out)
	}
}

func TestClusterByNameAndTypo(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	if out, errs, code := run(t, cfg, srv.URL, "clusters", "show", "web"); code != 0 || !strings.Contains(out, "k7f3m2x9q1ab") {
		t.Fatalf("by name: %d %s %s", code, out, errs)
	}
	if _, errs, code := run(t, cfg, srv.URL, "clusters", "show", "wbe"); code != 1 || !strings.Contains(errs, "did you mean web") {
		t.Fatalf("typo: %d %s", code, errs)
	}
}

// The nodes: what their agents run, and what gets in the way of their mesh.
func TestDevicesShowAgentsAndMeshWarnings(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	out, errs, code := run(t, cfg, srv.URL, "clusters", "devices", "web")
	if code != 0 || !strings.Contains(out, "running @42") || !strings.Contains(out, "cp-1 mesh: Tailscale runs here") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
	out, _, _ = run(t, cfg, srv.URL, "clusters", "devices", "web", "cp-1")
	if !strings.Contains(out, "! Tailscale runs here") || !strings.Contains(out, "revision 42") {
		t.Fatalf("%s", out)
	}
}

func TestFeaturesChangeOnlyWhatIsGiven(t *testing.T) {
	f, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	if _, errs, code := run(t, cfg, srv.URL, "clusters", "features", "web", "--mesh", "on"); code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	if f.features["mesh"] != true || f.features["proxy"] != true {
		t.Fatalf("sent %v", f.features)
	}
	if _, errs, code := run(t, cfg, srv.URL, "clusters", "features", "web", "--mesh", "maybe"); code != 2 || !strings.Contains(errs, "on or off") {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestJoinCodeAloneOnStdout(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	out, errs, code := run(t, cfg, srv.URL, "join-code", "web")
	if code != 0 || out != "vp1.eu.abc\n" || !strings.Contains(errs, InstallCommand+"vp1.eu.abc") {
		t.Fatalf("%d %q %s", code, out, errs)
	}
}

func TestDeletingNeedsConfirmation(t *testing.T) {
	f, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	if _, errs, code := run(t, cfg, srv.URL, "clusters", "delete", "web"); code != 1 || !strings.Contains(errs, "--yes") {
		t.Fatalf("without --yes: %d %s", code, errs)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "DELETE") {
			t.Fatalf("deleted without confirmation: %v", f.calls)
		}
	}
	if _, errs, code := run(t, cfg, srv.URL, "clusters", "delete", "web", "-y"); code != 0 {
		t.Fatalf("with -y: %d %s", code, errs)
	}
}

func TestAPITokenFromTheEnvironment(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("VEILCTL_CONFIG", cfg)
	t.Setenv("VEILCTL_API", srv.URL)
	t.Setenv("VEILCTL_ORG", "acme")
	t.Setenv("VEILCTL_TOKEN", "vpt_good")
	var out, errb bytes.Buffer
	if code := Run(context.Background(), []string{"clusters"}, "test", Env{In: strings.NewReader(""), Out: &out, Err: &errb}); code != 0 || !strings.Contains(out.String(), "web") {
		t.Fatalf("%d %s %s", code, out.String(), errb.String())
	}
	t.Setenv("VEILCTL_TOKEN", "vpt_deleted")
	out.Reset()
	errb.Reset()
	if code := Run(context.Background(), []string{"clusters"}, "test", Env{In: strings.NewReader(""), Out: &out, Err: &errb}); code != 1 || !strings.Contains(errb.String(), "API token is not valid") {
		t.Fatalf("%d %s", code, errb.String())
	}
}

func TestUsageErrors(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"clustr"}, `did you mean "clusters"`},
		{[]string{"clusters", "creat", "x"}, `did you mean "create"`},
		{[]string{"clusters", "create"}, "needs NAME"},
		{[]string{"clusters", "create", "a", "--regoin", "eu"}, "did you mean --region"},
		{[]string{"clusters", "list", "extra"}, "takes no arguments"},
		{[]string{"clusters", "create", "a", "--region"}, "needs a value"},
	} {
		_, errs, code := run(t, cfg, "http://127.0.0.1:1", tc.args...)
		if code != 2 || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: %d %s", tc.args, code, errs)
		}
	}
}

func TestHelpAndDefaults(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.json")
	out, _, code := run(t, cfg, "http://127.0.0.1:1", "--help")
	if code != 0 || !strings.Contains(out, "Get started") || !strings.Contains(out, "join-code") {
		t.Fatalf("%d %s", code, out)
	}
	out, _, _ = run(t, cfg, "http://127.0.0.1:1", "clusters", "create", "-h")
	if !strings.Contains(out, "--region REGION") || !strings.Contains(out, "Examples") {
		t.Fatalf("%s", out)
	}
	// "veilctl clusters" runs "clusters list": not signed in here
	if _, errs, code := run(t, cfg, "http://127.0.0.1:1", "clusters"); code != 1 || !strings.Contains(errs, "veilctl login") {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestParseFlagsAnywhere(t *testing.T) {
	root := tree()
	root.link()
	cmd, args, flags, err := parse(root, globalFlags, []string{"--org", "acme", "clusters", "create", "web", "-r", "eu", "--json", "--", "--odd"})
	if err != nil || cmd.path() != "veilctl clusters create" || flags["org"] != "acme" || flags["region"] != "eu" || flags["json"] != "true" ||
		len(args) != 2 || args[0] != "web" || args[1] != "--odd" {
		t.Fatalf("%v %v %v %v", cmd.path(), args, flags, err)
	}
	if _, _, flags, err = parse(root, globalFlags, []string{"clusters", "--yes=false"}); err != nil || flags["yes"] != "false" {
		t.Fatalf("%v %v", flags, err)
	}
}

func TestCompletion(t *testing.T) {
	_, srv := newFakeAPI(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	signIn(t, cfg, srv.URL)
	for _, tc := range []struct {
		words []string
		want  string
	}{
		{[]string{"clu"}, "clusters\n"},
		{[]string{"clusters", "show", ""}, "k7f3m2x9q1ab\n"},
		{[]string{"clusters", "features", "web", "--mesh", ""}, "off\non\n"},
		{[]string{"--org", ""}, "acme\n"},
		{[]string{"clusters", "create", "x", "--reg"}, "--region\n"},
	} {
		out, _, code := run(t, cfg, srv.URL, append([]string{"__complete"}, tc.words...)...)
		if code != 0 || out != tc.want {
			t.Errorf("%v: %q, want %q", tc.words, out, tc.want)
		}
	}
	for _, sh := range []string{"bash", "zsh", "fish"} {
		if out, _, code := run(t, cfg, srv.URL, "completion", sh); code != 0 || !strings.Contains(out, "__complete") {
			t.Errorf("%s: %d %s", sh, code, out)
		}
	}
}

func TestValues(t *testing.T) {
	for in, want := range map[string]string{
		"https://app.veilplane.com/auth/link?token=abc_D-9": "abc_D-9",
		"<https://app.veilplane.com/auth/link?token=xyz>":   "xyz",
		"abc123": "abc123",
	} {
		if got, err := linkToken(in); err != nil || got != want {
			t.Errorf("linkToken(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := linkToken("https://app.veilplane.com/somewhere"); err == nil {
		t.Error("a link without token was taken")
	}
	if got := invitationToken("https://app.veilplane.com/invite/tok?x=1"); got != "tok" {
		t.Errorf("invitationToken: %q", got)
	}
	for in, want := range map[string]int{"90": 90, "90d": 90, "2w": 14, "6m": 180, "1y": 365} {
		if got, err := parseDays(in); err != nil || got != want {
			t.Errorf("parseDays(%q) = %d, %v", in, got, err)
		}
	}
	for in, want := range map[int64]string{999: "999 B", 1024: "1 KiB", 64000000: "64 MB", 4 << 30: "4 GiB", 1500000: "1.5 MB", 123456789: "123.5 MB"} {
		if got := size(in); got != want {
			t.Errorf("size(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestNoColorsWhenPiped(t *testing.T) {
	var b bytes.Buffer
	table(&b, style{}, []string{"A", "B"}, [][]string{{"x", "y"}})
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal(b.String())
	}
	b.Reset()
	table(&b, style{on: true}, []string{"NODE", "STATE"}, [][]string{{"cp-1", style{on: true}.state("running")}, {"cp-22", "off"}})
	lines := strings.Split(strings.TrimSpace(ansi.ReplaceAllString(b.String(), "")), "\n")
	if len(lines) != 3 || strings.Index(lines[1], "running") != strings.Index(lines[2], "off") {
		t.Fatalf("columns do not line up with colors:\n%s", strings.Join(lines, "\n"))
	}
	_ = io.Discard
}
