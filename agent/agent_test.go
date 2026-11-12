// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/veilplane/veil/mesh"
)

// fakeBackend is the agent API as far as these tests need it.
type fakeBackend struct {
	t       *testing.T
	mu      sync.Mutex
	devices map[string]ed25519.PublicKey // node -> key
	revoked map[string]bool
	proxy   bool
	mesh    bool
	secrets map[string]string // code -> server secret
	kinds   map[string]string // code -> bootstrap, invite, worker
	changed chan struct{}
	status  map[string]json.RawMessage
	api     string // named in the join answer: the region's agent API
}

func newFake(t *testing.T) (*fakeBackend, *httptest.Server) {
	f := &fakeBackend{t: t, devices: map[string]ed25519.PublicKey{}, revoked: map[string]bool{}, proxy: true,
		secrets: map[string]string{}, kinds: map[string]string{"vp1.first": "bootstrap"}, changed: make(chan struct{}),
		status: map[string]json.RawMessage{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeBackend) set(fn func()) {
	f.mu.Lock()
	fn()
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
}

func writeProblem(w http.ResponseWriter, code int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"detail": detail})
}

func (f *fakeBackend) serve(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	str := func(k string) string { s, _ := body[k].(string); return s }
	caller := func() string {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		node, ok := strings.CutPrefix(tok, "vt1.")
		f.mu.Lock()
		defer f.mu.Unlock()
		if !ok || f.devices[node] == nil {
			return ""
		}
		if f.revoked[node] {
			return "-"
		}
		return node
	}
	switch r.URL.Path {
	case "/agent/v1/join":
		code, node := str("code"), str("node")
		key, _ := base64.StdEncoding.DecodeString(str("publicKey"))
		sig, _ := base64.StdEncoding.DecodeString(str("signature"))
		if len(key) != 32 || !ed25519.Verify(key, []byte("veilplane join v1\n"+code+"\n"+node), sig) {
			writeProblem(w, 400, "bad signature")
			return
		}
		f.mu.Lock()
		kind := f.kinds[code]
		delete(f.kinds, code)
		if kind != "" {
			f.devices[node], f.revoked[node] = key, false
		}
		secret := f.secrets[code]
		f.mu.Unlock()
		if kind == "" {
			writeProblem(w, 403, "invalid, used or expired join code")
			return
		}
		role, master := "control-plane", map[string]string{"bootstrap": "create", "invite": "receive", "worker": "none"}[kind]
		if kind == "worker" {
			role = "worker"
		}
		json.NewEncoder(w).Encode(map[string]string{"cluster": "c1", "node": node, "role": role, "masterKey": master, "inviteSecret": secret,
			"api": f.api})
	case "/agent/v1/token":
		node, nonce := str("node"), str("nonce")
		tm := int64(body["time"].(float64))
		sig, _ := base64.StdEncoding.DecodeString(str("signature"))
		f.mu.Lock()
		key, revoked := f.devices[node], f.revoked[node]
		f.mu.Unlock()
		msg := "veilplane token v1\n" + str("cluster") + "\n" + node + "\n" + strconv.FormatInt(tm, 10) + "\n" + nonce
		if key == nil || revoked || !ed25519.Verify(key, []byte(msg), sig) {
			writeProblem(w, 403, "device unknown or revoked")
			return
		}
		exp := time.Now().Add(15 * time.Minute).Truncate(time.Second)
		json.NewEncoder(w).Encode(map[string]any{"token": "vt1." + node, "expiresAt": exp,
			"attestation": base64.StdEncoding.EncodeToString(ed25519.Sign(testAttestationKey, attestationMessage(str("cluster"), node, nonce, exp)))})
	case "/agent/v1/config":
		node := caller()
		if node == "" || node == "-" {
			writeProblem(w, 403, "refused")
			return
		}
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		deadline := time.After(time.Duration(wait) * time.Second)
		for {
			f.mu.Lock()
			role := "control-plane"
			if bytes.HasPrefix([]byte(node), []byte("w")) {
				role = "worker"
			}
			cfg := map[string]any{"cluster": "c1", "node": node, "role": role,
				"backend":  map[string]any{"grpc": "127.0.0.1:1", "tls": false},
				"features": map[string]any{"proxy": map[string]any{"enabled": f.proxy && role == "control-plane"}, "mesh": map[string]any{"enabled": f.mesh, "prefix": "10.200.0.0/16"}}}
			raw, _ := json.Marshal(cfg)
			etag := fmt.Sprintf(`"%x"`, len(raw)*7+boolInt(f.proxy)*3+boolInt(f.mesh)+boolInt(f.revoked[node])*11)
			changed, revoked := f.changed, f.revoked[node]
			f.mu.Unlock()
			if revoked {
				writeProblem(w, 403, "revoked")
				return
			}
			if etag != r.Header.Get("If-None-Match") {
				w.Header().Set("ETag", etag)
				w.Write(raw)
				return
			}
			select {
			case <-changed:
			case <-r.Context().Done():
				return
			case <-deadline:
				w.Header().Set("ETag", etag)
				w.WriteHeader(304)
				return
			}
		}
	case "/agent/v1/status":
		node := caller()
		raw, _ := json.Marshal(body)
		f.mu.Lock()
		f.status[node] = raw
		f.mu.Unlock()
		w.WriteHeader(204)
	case "/agent/v1/invites":
		node := caller()
		if node == "" || node == "-" || strings.HasPrefix(node, "w") {
			writeProblem(w, 403, "only control plane nodes")
			return
		}
		code := fmt.Sprintf("vp1.inv%d", time.Now().UnixNano())
		answer := map[string]any{"code": code, "expiresAt": time.Now().Add(time.Hour)}
		f.mu.Lock()
		if str("role") == "worker" {
			f.kinds[code] = "worker"
			answer["address"], answer["prefix"] = "10.200.0.2", "10.200.0.0/16"
		} else {
			f.kinds[code], f.secrets[code] = "invite", str("serverSecret")
		}
		f.mu.Unlock()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(answer)
	case "/agent/v1/leave":
		node := caller()
		f.set(func() { f.revoked[node] = true })
		w.WriteHeader(204)
	default:
		writeProblem(w, 404, "no such endpoint")
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// node: an agent in its own directories, running until the test ends.
type node struct {
	t      *testing.T
	paths  Paths
	cancel context.CancelFunc
	done   chan error
}

func startNode(t *testing.T, api string, cfg map[string]any) *node {
	dir := t.TempDir()
	n := &node{t: t, paths: Paths{Config: filepath.Join(dir, "etc"), State: filepath.Join(dir, "var")}, done: make(chan error, 1)}
	os.MkdirAll(n.paths.Config, 0o755)
	cfg["api"] = api
	n.writeConfig(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	go func() { n.done <- Run(ctx, n.paths, "test") }()
	t.Cleanup(n.stop)
	return n
}

func (n *node) writeConfig(cfg map[string]any) {
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(n.paths.ConfigFile(), raw, 0o644); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) stop() {
	if n.cancel != nil {
		n.cancel()
		<-n.done
		n.cancel = nil
	}
}

// wait until the status file satisfies ok.
func (n *node) wait(what string, ok func(*Status) bool) *Status {
	n.t.Helper()
	var s *Status
	for i := 0; i < 150; i++ {
		var err error
		if s, err = ReadStatus(n.paths); err == nil && ok(s) {
			return s
		}
		time.Sleep(100 * time.Millisecond)
	}
	raw, _ := json.MarshalIndent(s, "", "  ")
	n.t.Fatalf("%s: status is\n%s", what, raw)
	return nil
}

func TestJoinCreatesMasterKeyAndRunsWhatIsWanted(t *testing.T) {
	f, srv := newFake(t)
	n := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first",
		"proxy": map[string]any{"listen": "127.0.0.1:0", "opsListen": "off"}})
	s := n.wait("joined, proxy wanted", func(s *Status) bool {
		return s.State == "running" && s.Features["proxy"].Wanted && s.Features["proxy"].State != "off"
	})
	if s.Cluster != "c1" || s.Node != "cp1" || s.Role != "control-plane" || s.PID != os.Getpid() {
		t.Fatalf("identity in the status: %+v", s)
	}
	if st, err := os.Stat(n.paths.state(masterKey)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("master key: %v", err)
	}
	if st, _ := os.Stat(n.paths.state(deviceKey)); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatal("device key")
	}
	if s.Features["mesh"].State != "off" {
		t.Fatalf("mesh is not wanted: %+v", s.Features["mesh"])
	}
	// the backend switches the proxy off: it stops within the long poll, not after it
	start := time.Now()
	f.set(func() { f.proxy = false })
	n.wait("proxy off", func(s *Status) bool { return !s.Features["proxy"].Wanted && s.Features["proxy"].State == "off" })
	if time.Since(start) > 5*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	// the status reached the backend
	time.Sleep(6 * time.Second)
	f.mu.Lock()
	reported := string(f.status["cp1"])
	f.mu.Unlock()
	if !strings.Contains(reported, `"node":"cp1"`) {
		t.Errorf("status report: %s", reported)
	}
}

// A join code of another region: the instance the agent asks redirects it, the region's answer
// names its agent API, and the agent talks to the region from then on.
func TestJoinFollowsTheClustersRegion(t *testing.T) {
	f, region := newFake(t)
	f.set(func() { f.api = region.URL })
	var redirected, other atomic.Int32
	home := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/agent/v1/join" {
			redirected.Add(1)
			http.Redirect(w, r, region.URL+"/agent/v1/join", http.StatusTemporaryRedirect)
			return
		}
		other.Add(1)
		writeProblem(w, 404, "not here")
	}))
	t.Cleanup(home.Close)
	n := startNode(t, home.URL, map[string]any{"node": "cp1", "join": "vp1.first", "allow": []string{}})
	s := n.wait("running in the region", func(s *Status) bool { return s.State == "running" })
	if s.API != region.URL {
		t.Fatalf("status API %q, want the region's %q", s.API, region.URL)
	}
	var id Identity
	if raw, err := os.ReadFile(n.paths.state(identityFile)); err != nil || json.Unmarshal(raw, &id) != nil || id.API != region.URL {
		t.Fatalf("identity.json: %+v %v", id, err)
	}
	if redirected.Load() != 1 || other.Load() != 0 {
		t.Fatalf("the home instance got %d joins and %d other requests", redirected.Load(), other.Load())
	}
}

func TestAllowlistRefusesWhatTheBackendWants(t *testing.T) {
	f, srv := newFake(t)
	f.set(func() { f.mesh = true })
	n := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first", "allow": []string{}})
	s := n.wait("refused", func(s *Status) bool {
		return s.Features["proxy"].State == "refused" && s.Features["mesh"].State == "refused"
	})
	if s.Features["mesh"].Allowed || !s.Features["mesh"].Wanted {
		t.Fatalf("%+v", s.Features["mesh"])
	}
	// allowing it in agent.json takes effect without a restart
	n.writeConfig(map[string]any{"api": srv.URL, "node": "cp1", "join": "vp1.first", "allow": []string{"proxy"},
		"proxy": map[string]any{"listen": "127.0.0.1:0", "opsListen": "off"}})
	n.wait("proxy allowed", func(s *Status) bool {
		return s.Features["proxy"].Allowed && s.Features["proxy"].State != "refused" && s.Features["mesh"].State == "refused"
	})
}

func TestBadJoinIsReportedAndRetriedWhenTheConfigChanges(t *testing.T) {
	_, srv := newFake(t)
	n := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.wrong"})
	n.wait("join refused", func(s *Status) bool {
		return s.State == "joining" && strings.Contains(s.Error, "invalid, used or expired")
	})
	n.writeConfig(map[string]any{"api": srv.URL, "node": "cp1", "join": "vp1.first", "allow": []string{}})
	n.wait("joined", func(s *Status) bool { return s.State == "running" && s.Node == "cp1" })
	n2 := startNode(t, srv.URL, map[string]any{"node": "cp9"})
	n2.wait("nothing to join with", func(s *Status) bool { return strings.Contains(s.Error, `set "join"`) })
}

func TestInviteGivesTheMasterKeyToTheNextNodeOnly(t *testing.T) {
	_, srv := newFake(t)
	cp1 := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first", "allow": []string{}})
	cp1.wait("joined", func(s *Status) bool { return s.State == "running" })
	inv, err := CreateInvite(context.Background(), cp1.paths, "test", InviteOptions{Node: "cp2"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Role != "control-plane" || inv.Box == "" || inv.FileSecret == "" || strings.Contains(fmt.Sprint(inv), "serverSecret") {
		t.Fatalf("invite: %+v", inv)
	}
	file := filepath.Join(t.TempDir(), "cp2.invite")
	if err := WriteInvite(inv, file); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
		t.Fatal("invite file mode")
	}
	if WriteInvite(inv, file) == nil {
		t.Fatal("overwrote an invite file")
	}
	cp2 := startNode(t, srv.URL, map[string]any{"join": file, "allow": []string{}})
	cp2.wait("cp2 joined", func(s *Status) bool { return s.State == "running" && s.Node == "cp2" })
	k1, _ := os.ReadFile(cp1.paths.state(masterKey))
	k2, _ := os.ReadFile(cp2.paths.state(masterKey))
	if len(k1) == 0 || string(k1) != string(k2) {
		t.Fatal("cp2 has not the cluster's master key")
	}
	// the file alone is useless: the backend's half is gone
	cp3 := startNode(t, srv.URL, map[string]any{"join": file, "allow": []string{}})
	cp3.wait("second use refused", func(s *Status) bool { return strings.Contains(s.Error, "join") })
	if _, err := os.Stat(cp3.paths.state(masterKey)); err == nil {
		t.Fatal("a master key without the backend's half")
	}
}

func TestWorkerInviteHasNoMasterKey(t *testing.T) {
	_, srv := newFake(t)
	cp1 := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first", "allow": []string{}})
	cp1.wait("joined", func(s *Status) bool { return s.State == "running" })
	if _, err := CreateInvite(context.Background(), cp1.paths, "test", InviteOptions{Worker: true}); err == nil {
		t.Fatal("a worker invite without a name")
	}
	inv, err := CreateInvite(context.Background(), cp1.paths, "test", InviteOptions{Node: "w1", Worker: true})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Box != "" || inv.FileSecret != "" || inv.Certificate == "" || inv.Address != "10.200.0.2" {
		t.Fatalf("worker invite: %+v", inv)
	}
	root, _ := base64.StdEncoding.DecodeString(inv.MeshKey)
	c, err := mesh.VerifyCert(root, inv.Certificate)
	if err != nil || c.Role != "worker" || c.Node != "w1" {
		t.Fatalf("certificate: %v %+v", err, c)
	}
	file := filepath.Join(t.TempDir(), "w1.invite")
	WriteInvite(inv, file)
	w := startNode(t, srv.URL, map[string]any{"join": file, "allow": []string{}})
	s := w.wait("worker joined", func(s *Status) bool { return s.State == "running" && s.Role == "worker" })
	if s.Features["proxy"].Wanted {
		t.Fatal("a worker never runs the etcd proxy")
	}
	if _, err := os.Stat(w.paths.state(masterKey)); err == nil {
		t.Fatal("a worker got the master key")
	}
	if _, err := CreateInvite(context.Background(), w.paths, "test", InviteOptions{Node: "w2", Worker: true}); err == nil {
		t.Fatal("a worker invited")
	}
}

func TestRevokedNodeStopsAndJoinsAgainWithANewJoin(t *testing.T) {
	f, srv := newFake(t)
	n := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first",
		"proxy": map[string]any{"listen": "127.0.0.1:0", "opsListen": "off"}})
	n.wait("running", func(s *Status) bool { return s.Features["proxy"].State != "off" })
	if err := Leave(context.Background(), n.paths, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(n.paths.state(leftMarker)); err != nil {
		t.Fatalf("no marker after leaving: %v", err)
	}
	n.wait("revoked", func(s *Status) bool { return s.State == "revoked" && s.Features["proxy"].State == "off" })
	f.set(func() { f.kinds["vp1.again"] = "bootstrap" })
	os.Remove(n.paths.state(masterKey)) // a new first node creates a new key
	n.writeConfig(map[string]any{"api": srv.URL, "node": "cp1", "join": "vp1.again",
		"proxy": map[string]any{"listen": "127.0.0.1:0", "opsListen": "off"}})
	n.wait("joined again", func(s *Status) bool { return s.State == "running" && s.Features["proxy"].State != "off" })
	if _, err := os.Stat(n.paths.state(leftMarker)); err == nil {
		t.Fatal("the marker survived joining again")
	}
}

func TestSecondAgentOnTheSameStateIsRefused(t *testing.T) {
	_, srv := newFake(t)
	n := startNode(t, srv.URL, map[string]any{"node": "cp1", "join": "vp1.first", "allow": []string{}})
	n.wait("running", func(s *Status) bool { return s.State == "running" })
	if err := Run(context.Background(), n.paths, "test"); err == nil || !strings.Contains(err.Error(), "another veil agent") {
		t.Fatalf("second agent: %v", err)
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := Paths{Config: dir, State: dir}
	os.WriteFile(p.ConfigFile(), []byte(`{"join":"vp1.x","alow":["proxy"]}`), 0o644)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("a typo must not silently allow everything")
	}
	os.WriteFile(p.ConfigFile(), []byte(`{"allow":["proxy","ssh"]}`), 0o644)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("unknown feature")
	}
	os.WriteFile(p.ConfigFile(), []byte(`{"proxy":{"history":"20m"}}`), 0o644)
	c, err := LoadConfig(p)
	if err != nil || time.Duration(c.Proxy.History) != 20*time.Minute || !c.allowed("mesh") {
		t.Fatalf("%v %+v", err, c)
	}
}

func TestInviteSealOpen(t *testing.T) {
	master := NewMasterKey()
	fs, box, server, err := inviteSeal(master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := inviteOpen(fs, box, server)
	if err != nil || string(got) != string(master) {
		t.Fatal("round trip")
	}
	_, _, other, _ := inviteSeal(master)
	if _, err := inviteOpen(fs, box, other); err == nil {
		t.Fatal("opened with the wrong half")
	}
}

// Without the rights to read the status (it is root's), veil status says so instead of
// suggesting that the agent is not running.
func TestStatusWithoutRights(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	p := Paths{Config: t.TempDir(), State: t.TempDir()}
	if err := os.WriteFile(p.Lock(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.State, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p.State, 0o700) })
	if _, err := ReadStatus(p); err == nil || !strings.Contains(err.Error(), "sudo veil status") {
		t.Fatalf("ReadStatus: %v", err)
	}
}

// The metrics address serves the agent, its features and the mesh with every peer, in
// Prometheus' text format; "off" closes it.
func TestMetrics(t *testing.T) {
	a := &Agent{cfg: &Config{Metrics: MetricsConfig{Listen: "127.0.0.1:0"}}, running: map[string]*feature{}}
	a.status = Status{Version: "v1.2.3", State: "running", Cluster: "home", Node: "fedora", Role: "control-plane",
		Features: map[string]*FeatureStatus{"proxy": {Wanted: true, Allowed: true, State: "running"},
			"mesh": {Wanted: true, Allowed: true, State: "running", Mesh: &mesh.Status{Interface: "veil0", Address: "10.200.0.1",
				Mode: "kernel", Backend: true, Repairs: 2, Warnings: []string{"x"}, Peers: []mesh.PeerStatus{
					{Node: "rocky-1", State: "connected", Path: "lan", RTT: 0.0012, Probes: 10, Answers: 9, RxBytes: 1000, TxBytes: 2000,
						Handshake: time.Unix(1700000000, 0)},
					{Node: "worker-2", State: "blocked"}}}}}}
	a.status.Backend.Connected = true
	a.ensureMetrics()
	t.Cleanup(a.stopMetrics)
	resp, err := http.Get("http://" + a.metrics.bound + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	out := string(raw)
	for _, want := range []string{
		`veil_agent_info{version="v1.2.3",node="fedora",cluster="home",role="control-plane"} 1`,
		`veil_agent_state{state="running"} 1`,
		`veil_agent_state{state="error"} 0`,
		`veil_agent_backend_connected 1`,
		`veil_agent_feature_state{feature="mesh",state="running"} 1`,
		`veil_mesh_up 1`,
		`veil_mesh_interface_repairs_total 2`,
		`veil_mesh_peers{state="blocked"} 1`,
		`veil_mesh_peer_up{peer="rocky-1"} 1`,
		`veil_mesh_peer_up{peer="worker-2"} 0`,
		`veil_mesh_peer_path{peer="rocky-1",path="lan"} 1`,
		`veil_mesh_peer_rtt_seconds{peer="rocky-1"} 0.0012`,
		`veil_mesh_peer_receive_bytes_total{peer="rocky-1"} 1000`,
		`veil_mesh_peer_last_handshake_timestamp_seconds{peer="rocky-1"} 1.7e+09`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	// each metric's HELP and TYPE exactly once
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "# TYPE ") && strings.Count(out, l+"\n") != 1 {
			t.Errorf("twice: %s", l)
		}
	}
	if resp.Header.Get("Content-Type") == "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Errorf("content type %q", resp.Header.Get("Content-Type"))
	}
	if os.Getenv("VEIL_METRICS_OUT") != "" {
		os.WriteFile(os.Getenv("VEIL_METRICS_OUT"), raw, 0o644)
	}

	addr := a.metrics.bound
	a.cfg.Metrics.Listen = "off"
	a.ensureMetrics()
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Fatal("still served after off")
	}
}

// The tests run like a development build: fake backends on 127.0.0.1, a CA of their own, and an
// attestation key of their own that the fake backends sign tokens with.
var testAttestationKey = func() ed25519.PrivateKey {
	pub, priv, _ := ed25519.GenerateKey(nil)
	devMode = true
	attestationKeys = []string{base64.StdEncoding.EncodeToString(pub)}
	return priv
}()

// A release build talks to Veilplane's backend only: https on a Veilplane name, the system's
// CAs, every redirect too, gRPC with TLS on a Veilplane name, and tokens with Veilplane's
// signature over the agent's nonce.
func TestOnlyVeilplanesBackend(t *testing.T) {
	devMode = false
	t.Cleanup(func() { devMode = true })

	for _, ok := range []string{"https://api.veilplane.com", "https://eu-api.veilplane.com", "https://API.VEILPLANE.COM:443"} {
		if _, err := newAPI(ok, "", "test"); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://api.veilplane.com", "https://api.example.com", "https://veilplane.com.evil.net",
		"https://evilveilplane.com", "https://127.0.0.1:8443"} {
		if _, err := newAPI(bad, "", "test"); err == nil || !strings.Contains(err.Error(), "Veilplane's backend only") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
	if _, err := newAPI("https://api.veilplane.com", "/etc/veil/ca.pem", "test"); err == nil || !strings.Contains(err.Error(), "development builds only") {
		t.Errorf("apiCa accepted: %v", err)
	}
	for _, g := range []struct {
		addr string
		tls  bool
		ok   bool
	}{{"grpc.veilplane.com:443", true, true}, {"eu-grpc.veilplane.com:443", true, true}, {"grpc.veilplane.com:443", false, false},
		{"grpc.example.com:443", true, false}, {"127.0.0.1:2379", true, false}} {
		if err := checkGRPC(g.addr, g.tls); (err == nil) != g.ok {
			t.Errorf("gRPC %s tls=%v: %v", g.addr, g.tls, err)
		}
	}

	// a redirect away from Veilplane is not followed
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer foreign.Close()
	a, _ := newAPI("https://api.veilplane.com", "", "test")
	req, _ := http.NewRequest("POST", foreign.URL+"/agent/v1/join", nil)
	if err := a.http.CheckRedirect(req, []*http.Request{{}}); err == nil {
		t.Error("a redirect to another host is followed")
	}

	// attestations: Veilplane's key over exactly this token
	exp := time.Unix(1800000000, 0)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(testAttestationKey, attestationMessage("c1", "cp-1", "n0nce", exp)))
	if err := verifyAttestation("c1", "cp-1", "n0nce", exp, sig); err != nil {
		t.Fatalf("a valid attestation: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(nil)
	forged := base64.StdEncoding.EncodeToString(ed25519.Sign(other, attestationMessage("c1", "cp-1", "n0nce", exp)))
	for name, c := range map[string][5]string{
		"none":          {"c1", "cp-1", "n0nce", "", ""},
		"another key":   {"c1", "cp-1", "n0nce", forged, ""},
		"another nonce": {"c1", "cp-1", "replay", sig, ""},
		"another node":  {"c1", "cp-2", "n0nce", sig, ""},
	} {
		if err := verifyAttestation(c[0], c[1], c[2], exp, c[3]); !errors.Is(err, errNotVeilplane) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := verifyAttestation("c1", "cp-1", "n0nce", exp.Add(time.Hour), sig); !errors.Is(err, errNotVeilplane) {
		t.Errorf("another expiry: %v", err)
	}
	saved := attestationKeys
	attestationKeys = nil
	if err := verifyAttestation("c1", "cp-1", "n0nce", exp, sig); err == nil || !strings.Contains(err.Error(), "no Veilplane attestation key") {
		t.Errorf("without keys: %v", err)
	}
	attestationKeys = saved
}

// A backend that answers tokens without (or with a forged) attestation gets no further than that.
func TestTokenWithoutAttestationIsRefused(t *testing.T) {
	_, other, _ := ed25519.GenerateKey(nil)
	for name, attest := range map[string]func(cluster, node, nonce string, exp time.Time) string{
		"without": func(string, string, string, time.Time) string { return "" },
		"forged": func(c, n, nonce string, exp time.Time) string {
			return base64.StdEncoding.EncodeToString(ed25519.Sign(other, attestationMessage(c, n, nonce, exp)))
		},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			exp := time.Now().Add(time.Minute).Truncate(time.Second)
			json.NewEncoder(w).Encode(map[string]any{"token": "vt1.x", "expiresAt": exp,
				"attestation": attest(b["cluster"].(string), b["node"].(string), b["nonce"].(string), exp)})
		}))
		a, err := newAPI(srv.URL, "", "test")
		if err != nil {
			t.Fatal(err)
		}
		_, key, _ := ed25519.GenerateKey(nil)
		if _, err := a.token(context.Background(), "c1", "cp-1", key); !errors.Is(err, errNotVeilplane) {
			t.Errorf("%s attestation: %v", name, err)
		}
		srv.Close()
	}
}
