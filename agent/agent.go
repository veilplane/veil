// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Package agent is the veil agent: it runs in the background on every node of a cluster and
// runs what the backend wants there (the etcd proxy, the mesh), as far as the node allows it.
//
// It is configured only declaratively:
//
//	<config>/agent.json   written by people or veilctl, only read here (see Config)
//	<state>/              the agent's own files: identity, keys, checkpoints
//	<state>/veil.lock     what the agent actually runs, rewritten on every change (see Status)
//
// The loop:
//
//  1. Not enrolled yet: join with the code or invite file named in agent.json.
//  2. Get an access token (signed with the device key) and keep it fresh. It is the identity on
//     every agent API request and on the etcd proxy's gRPC calls (etcd is the only gRPC API);
//     nothing depends on TLS client certificates, so a proxy that ends TLS can sit in front
//     of the backend.
//  3. Ask the backend what to run (long polling: the answer comes as soon as it changes).
//  4. Run it: start or stop the etcd proxy and the mesh, unless agent.json's allowlist refuses.
//  5. Write the status file, and report the status to the backend.
//
// The backend can switch features on and off, nothing more: it never gets the master key and
// cannot make the agent run commands, change its keys or skip a check.
package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/veilplane/veil/mesh"
	"github.com/veilplane/veil/proxy"
	"google.golang.org/grpc"
)

const (
	configWait   = 50 * time.Second // long polling, short enough for proxies on the way
	reportEvery  = 30 * time.Second
	lockEvery    = 30 * time.Second // the status file is rewritten at least this often (a heartbeat)
	tick         = time.Second
	retryJoin    = 30 * time.Second
	retryFeature = 5 * time.Second
)

// Status is the status file (veil.lock), and what the agent reports to the backend.
type Status struct {
	Version string    `json:"version"`
	PID     int       `json:"pid"`
	Updated time.Time `json:"updated"`
	// State: starting, joining, running, revoked or error.
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
	Cluster string `json:"cluster,omitempty"`
	Node    string `json:"node,omitempty"`
	Role    string `json:"role,omitempty"`
	API     string `json:"api,omitempty"`
	Backend struct {
		Connected    bool      `json:"connected"`
		GRPC         string    `json:"grpc,omitempty"`
		LastContact  time.Time `json:"lastContact,omitzero"`
		TokenExpires time.Time `json:"tokenExpires,omitzero"`
		ConfigETag   string    `json:"configEtag,omitempty"`
	} `json:"backend"`
	Features map[string]*FeatureStatus `json:"features"`
}

// FeatureStatus: wanted by the backend, allowed by agent.json, and what runs.
type FeatureStatus struct {
	Wanted  bool `json:"wanted"`
	Allowed bool `json:"allowed"`
	// State: off, refused (wanted, not allowed), starting, running or error.
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// proxy
	Listen   string `json:"listen,omitempty"`
	Revision int64  `json:"revision,omitempty"`
	// mesh
	Mesh *mesh.Status `json:"mesh,omitempty"`
}

// Agent is one running agent.
type Agent struct {
	paths   Paths
	version string

	mu     sync.Mutex
	status Status

	cfg      *Config
	cfgStamp string // agent.json's modification time and size
	id       *Identity
	key      ed25519.PrivateKey
	api      *api
	tok      *tokens
	remote   *RemoteConfig
	etag     string
	conn     *grpc.ClientConn
	connKey  string
	running  map[string]*feature
	lastJoin time.Time
	joinTry  string // agent.json's stamp at the last join attempt
}

// feature is a running proxy or mesh.
type feature struct {
	key    string // what it was started with; a change restarts it
	cancel context.CancelFunc
	done   chan struct{}
}

// Run is "veil agent": it runs until ctx ends.
func Run(ctx context.Context, paths Paths, version string) error {
	if err := os.MkdirAll(paths.State, 0o700); err != nil {
		return err
	}
	unlock, err := lockState(paths.State)
	if err != nil {
		return err
	}
	defer unlock()
	proxy.Version = version
	a := &Agent{paths: paths, version: version, running: map[string]*feature{}}
	a.status = Status{Version: version, PID: os.Getpid(), State: "starting", Features: map[string]*FeatureStatus{}}
	for _, f := range features {
		a.status.Features[f] = &FeatureStatus{State: "off"}
	}
	defer a.stopAll()
	return a.loop(ctx)
}

// lockState makes sure only one agent uses the state directory.
func lockState(dir string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another veil agent uses %s", dir)
	}
	return func() { f.Close() }, nil
}

type remoteEvent struct {
	cfg  *RemoteConfig
	etag string
	err  error
}

func (a *Agent) loop(ctx context.Context) error {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	events := make(chan remoteEvent, 1)
	var pollCancel context.CancelFunc
	stopPolling := func() {
		if pollCancel != nil {
			pollCancel()
			pollCancel = nil
		}
	}
	defer stopPolling()
	var lastLock, lastReport time.Time
	var lastWritten, lastReported []byte
	for {
		// local configuration: read again when the file changed
		if stamp := fileStamp(a.paths.ConfigFile()); a.cfg == nil || stamp != a.cfgStamp {
			cfg, err := LoadConfig(a.paths)
			if err != nil {
				a.setError("config", err)
			} else {
				if a.cfg != nil {
					log.Printf("agent.json changed")
				}
				a.cfg, a.cfgStamp = cfg, stamp
			}
		}
		if a.cfg != nil {
			// enrolled? (and not revoked)
			if a.id == nil {
				stopPolling()
				a.enroll(ctx)
			}
			if a.id != nil && a.tok != nil {
				if a.tok.isRevoked() && a.cfg.Join != "" && joinHash(a.cfg.Join) != a.id.Join {
					log.Printf("revoked, and agent.json has a new join: joining again")
					stopPolling()
					a.forget()
				} else if pollCancel == nil {
					pctx, cancel := context.WithCancel(ctx)
					pollCancel = cancel
					go a.poll(pctx, events)
				}
			}
			a.reconcile(ctx)
		}

		now := time.Now()
		raw := a.snapshot()
		if !bytesEqual(raw, lastWritten) || now.Sub(lastLock) > lockEvery {
			a.writeLock()
			lastWritten, lastLock = raw, now
		}
		if a.tok != nil && !a.tok.isRevoked() && (!bytesEqual(raw, lastReported) && now.Sub(lastReport) > 5*time.Second || now.Sub(lastReport) > reportEvery) {
			lastReport, lastReported = now, raw
			go a.report(ctx)
		}

		select {
		case <-ctx.Done():
			a.mu.Lock()
			a.status.State = "stopped"
			a.mu.Unlock()
			a.stopAll()
			a.writeLock()
			return nil
		case ev := <-events:
			a.remoteChanged(ev)
		case <-ticker.C:
		}
	}
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

func fileStamp(name string) string {
	st, err := os.Stat(name)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d %d", st.ModTime().UnixNano(), st.Size())
}

// snapshot: the status without the time stamp, to notice changes.
func (a *Agent) snapshot() []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.status
	s.Updated = time.Time{}
	s.Backend.LastContact = time.Time{}
	raw, _ := json.Marshal(s)
	return raw
}

func (a *Agent) writeLock() {
	a.mu.Lock()
	a.status.Updated = time.Now().UTC()
	if a.tok != nil {
		a.status.Backend.TokenExpires = a.tok.expires()
	}
	s := a.status
	raw, err := json.MarshalIndent(s, "", "  ")
	a.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(a.paths.Lock(), append(raw, '\n'), 0o644)
	}
	if err != nil {
		log.Printf("status file: %v", err)
	}
}

func (a *Agent) report(ctx context.Context) {
	a.mu.Lock()
	raw, _ := json.Marshal(a.status)
	api, tok := a.api, a.tok
	a.mu.Unlock()
	if api == nil || tok == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	t, err := tok.get(rctx)
	if err == nil {
		_, err = api.do(rctx, "PUT", "/agent/v1/status", t, json.RawMessage(raw), nil, nil)
	}
	if err != nil && ctx.Err() == nil {
		log.Printf("status report: %v", err)
	}
}

func (a *Agent) setError(what string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	msg := what + ": " + err.Error()
	if a.status.Error != msg {
		log.Print(msg)
	}
	a.status.State, a.status.Error = "error", msg
}

// ---------------------------------------------------------------- enrollment

// enroll loads the identity, or joins with agent.json's join.
func (a *Agent) enroll(ctx context.Context) {
	id, err := loadIdentity(a.paths)
	if err != nil {
		a.setError("identity", err)
		return
	}
	if id == nil {
		if a.cfg.Join == "" {
			a.mu.Lock()
			a.status.State, a.status.Error = "joining", `not enrolled: set "join" in `+a.paths.ConfigFile()+` to a join code or invite file`
			a.mu.Unlock()
			return
		}
		if time.Since(a.lastJoin) < retryJoin && a.cfgStamp == a.joinTry {
			return // a failed join is tried again after a while, or at once when agent.json changes
		}
		a.lastJoin, a.joinTry = time.Now(), a.cfgStamp
		a.mu.Lock()
		a.status.State, a.status.Error = "joining", ""
		a.mu.Unlock()
		if id, err = a.join(ctx); err != nil {
			a.setError("join", err)
			a.mu.Lock()
			a.status.State = "joining"
			a.mu.Unlock()
			return
		}
	}
	key, err := loadDeviceKey(a.paths)
	if err != nil {
		a.setError("device key", err)
		return
	}
	caFile := a.cfg.APICA
	if caFile == "" {
		if _, err := os.Stat(a.paths.state(apiCAFile)); err == nil {
			caFile = a.paths.state(apiCAFile)
		}
	}
	api, err := newAPI(cmpOr(a.cfg.API, id.API), caFile, a.version)
	if err != nil {
		a.setError("api", err)
		return
	}
	a.mu.Lock()
	a.id, a.key, a.api = id, key, api
	a.tok = &tokens{api: api, cluster: id.Cluster, node: id.Node, key: key}
	a.status.State, a.status.Error = "running", ""
	a.status.Cluster, a.status.Node, a.status.Role, a.status.API = id.Cluster, id.Node, id.Role, api.base
	a.mu.Unlock()
	log.Printf("node %s of cluster %s (%s)", id.Node, id.Cluster, id.Role)
}

// forget the identity of a revoked node, to join again.
func (a *Agent) forget() {
	a.stopAll()
	if a.conn != nil {
		a.conn.Close()
		a.conn, a.connKey = nil, ""
	}
	for _, f := range []string{identityFile, deviceKey, wgKey, meshFile, proxyState, apiCAFile} {
		os.Remove(a.paths.state(f))
	}
	a.mu.Lock()
	a.id, a.tok, a.api, a.remote, a.etag = nil, nil, nil, nil, ""
	a.mu.Unlock()
	a.lastJoin = time.Time{}
}

func hostname() string {
	h, _ := os.Hostname()
	out := []rune{}
	for _, r := range h {
		switch {
		case r == '.':
			return string(out)
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+'a'-'A')
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "node"
	}
	return string(out)
}

// join redeems agent.json's join: a code (the first node of a cluster) or an invite file.
func (a *Agent) join(ctx context.Context) (*Identity, error) {
	var inv *Invite
	code := a.cfg.Join
	if !isCode(code) {
		file := code
		if !filepath.IsAbs(file) {
			file = filepath.Join(a.paths.Config, file)
		}
		var err error
		if inv, err = loadInvite(file); err != nil {
			return nil, err
		}
		code = inv.Code
	}
	apiURL := DefaultAPI
	node := hostname()
	if inv != nil {
		apiURL = inv.API
		if inv.Node != "" {
			node = inv.Node
		}
	}
	apiURL, node = cmpOr(a.cfg.API, apiURL), cmpOr(a.cfg.Node, node)
	if inv != nil && inv.Node != "" && node != inv.Node {
		return nil, fmt.Errorf("the invite is for node %s, agent.json says %s", inv.Node, node)
	}
	caFile := a.cfg.APICA
	if caFile == "" && inv != nil && inv.APICA != "" {
		caFile = a.paths.state(apiCAFile)
		if err := writeFileAtomic(caFile, []byte(inv.APICA), 0o644); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(a.paths.state(masterKey)); err == nil && (inv == nil || inv.Role != "control-plane") {
		return nil, fmt.Errorf("%s exists already: a new cluster would get a new master key; move it away first", a.paths.state(masterKey))
	}
	api, err := newAPI(apiURL, caFile, a.version)
	if err != nil {
		return nil, err
	}
	key := newDeviceKey()
	jctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	log.Printf("joining as %s at %s", node, apiURL)
	j, err := api.join(jctx, code, node, key)
	if err != nil {
		return nil, err
	}
	// enrolled: from here on, a failure has to unenroll again
	if err := a.setUp(j, inv); err != nil {
		if tok, terr := api.token(jctx, j.Cluster, j.Node, key); terr == nil {
			api.do(jctx, "POST", "/agent/v1/leave", tok.Token, nil, nil, nil)
		}
		for _, f := range []string{masterKey, wgKey, meshFile, proxyState} {
			if f != masterKey || j.MasterKey != "receive" || inv == nil {
				os.Remove(a.paths.state(f))
			}
		}
		return nil, err
	}
	if err := writeFileAtomic(a.paths.state(deviceKey), encodeDeviceKey(key), 0o600); err != nil {
		return nil, err
	}
	id := &Identity{API: apiURL, Cluster: j.Cluster, Node: j.Node, Role: j.Role, JoinedAt: time.Now().UTC(), Join: joinHash(a.cfg.Join)}
	if err := writeJSON(a.paths.state(identityFile), id, 0o600); err != nil {
		return nil, err
	}
	log.Printf("joined cluster %s as %s (%s)", j.Cluster, j.Node, j.Role)
	return id, nil
}

func isCode(s string) bool { return len(s) > 4 && s[:4] == "vp1." }

// setUp writes the keys the join answer asks for.
func (a *Agent) setUp(j *joined, inv *Invite) error {
	switch j.MasterKey {
	case "create":
		if inv != nil {
			return errors.New("the backend treats this invite as the first node of the cluster")
		}
		log.Printf("first node of the cluster: creating the master key")
		return writeFileAtomic(a.paths.state(masterKey), encodeMasterKey(NewMasterKey()), 0o600)
	case "receive":
		if inv == nil || inv.Role != "control-plane" {
			return errors.New("this cluster already has nodes: join with an invite file from one of them (veil invite)")
		}
		if j.InviteSecret == "" {
			return errors.New("the backend did not hand out its half of the invite key")
		}
		master, err := inviteOpen(inv.FileSecret, inv.Box, j.InviteSecret)
		if err != nil {
			return err
		}
		if old, err := LoadMasterKey(a.paths.state(masterKey)); err == nil && string(old) != string(master) {
			return fmt.Errorf("%s holds another cluster's master key; move it away first", a.paths.state(masterKey))
		}
		if err := writeFileAtomic(a.paths.state(masterKey), encodeMasterKey(master), 0o600); err != nil {
			return err
		}
		if inv.State != "" { // the inviting node's checkpoints: the backend must not be older
			return writeFileAtomic(a.paths.state(proxyState), []byte(inv.State), 0o600)
		}
		return nil
	case "none":
		if inv == nil || inv.Role != "worker" {
			return errors.New("the backend enrolled this node as a worker, but this is no worker invite")
		}
		pub, err := wireGuardPublic(inv.WireGuardKey)
		if err != nil {
			return fmt.Errorf("invite: WireGuard key: %v", err)
		}
		root, err := base64.StdEncoding.DecodeString(inv.MeshKey)
		if err != nil || len(root) != ed25519.PublicKeySize {
			return errors.New("invite: meshKey is not an Ed25519 public key")
		}
		c, err := mesh.VerifyCert(root, inv.Certificate)
		if err != nil || c.Node != j.Node || c.Cluster != j.Cluster || base64.StdEncoding.EncodeToString(c.WireGuard[:]) != pub {
			return errors.New("invite: the mesh certificate does not belong to this node and key")
		}
		if err := writeFileAtomic(a.paths.state(wgKey), []byte(inv.WireGuardKey+"\n"), 0o600); err != nil {
			return err
		}
		return writeJSON(a.paths.state(meshFile), meshState{Address: inv.Address, Prefix: inv.Prefix, Certificate: inv.Certificate,
			MeshKey: inv.MeshKey, WireGuardKey: pub}, 0o600)
	}
	return fmt.Errorf("unexpected join answer (masterKey %q)", j.MasterKey)
}

// ---------------------------------------------------------------- the backend's config

// poll asks for the config again and again; each answer (or failure) goes to events.
func (a *Agent) poll(ctx context.Context, events chan<- remoteEvent) {
	etag := ""
	backoff := time.Second
	for ctx.Err() == nil {
		t, err := a.tok.get(ctx)
		var cfg *RemoteConfig
		var tag string
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, configWait+30*time.Second)
			cfg, tag, err = a.api.config(cctx, t, etag, configWait)
			cancel()
			if statusOf(err) == 401 {
				a.tok.forget() // e.g. the backend's token key changed
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			backoff = time.Second
			if cfg == nil {
				events <- remoteEvent{etag: etag} // unchanged: a sign of life
				continue
			}
			etag = tag
		}
		select {
		case events <- remoteEvent{cfg: cfg, etag: tag, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff = min(backoff*2, 15*time.Second)
		}
	}
}

func (a *Agent) remoteChanged(ev remoteEvent) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ev.err != nil {
		a.status.Backend.Connected = false
		if statusOf(ev.err) == 403 || (a.tok != nil && a.tok.isRevoked()) {
			if a.status.State != "revoked" {
				log.Printf("this node was revoked (or its cluster deleted): stopping everything")
			}
			a.tok.setRevoked()
			a.status.State, a.status.Error = "revoked", "the backend refuses this node: it was revoked, or its cluster deleted; "+
				`set a new "join" in agent.json to join again`
			a.remote = nil
			return
		}
		msg := "backend: " + ev.err.Error()
		if a.status.Error != msg {
			log.Print(msg)
		}
		a.status.Error = msg
		return
	}
	a.status.Backend.Connected, a.status.Backend.LastContact = true, time.Now().UTC()
	if a.status.State == "revoked" || a.status.Error != "" && a.status.State == "running" {
		a.status.Error = ""
	}
	a.status.State = "running"
	if ev.cfg != nil {
		if a.remote == nil || !reflect.DeepEqual(*a.remote, *ev.cfg) {
			log.Printf("config from the backend: proxy %v, mesh %v", ev.cfg.Features.Proxy.Enabled, ev.cfg.Features.Mesh.Enabled)
		}
		a.remote, a.etag = ev.cfg, ev.etag
		a.status.Backend.ConfigETag, a.status.Backend.GRPC = ev.etag, ev.cfg.Backend.GRPC
	}
}

// ---------------------------------------------------------------- features

// reconcile starts and stops features to match the backend's config and agent.json.
func (a *Agent) reconcile(ctx context.Context) {
	a.mu.Lock()
	remote, revoked := a.remote, a.tok != nil && a.tok.isRevoked()
	a.mu.Unlock()
	if revoked {
		remote = nil
	}
	if remote != nil {
		key := fmt.Sprintf("%s %v", remote.Backend.GRPC, remote.Backend.TLS)
		if a.conn == nil || key != a.connKey {
			if a.conn != nil {
				a.stopAll()
				a.conn.Close()
			}
			a.tok.secure = remote.Backend.TLS
			conn, err := dial(remote.Backend.GRPC, remote.Backend.TLS, a.api.roots, a.tok)
			if err != nil {
				a.setError("grpc", err)
				return
			}
			a.conn, a.connKey = conn, key
		}
	}
	for _, name := range features {
		wanted := remote != nil && remote.wants(name)
		allowed := a.cfg.allowed(name)
		a.mu.Lock()
		fs := a.status.Features[name]
		fs.Wanted, fs.Allowed = wanted, allowed
		a.mu.Unlock()
		var key string
		if wanted && allowed {
			key = a.featureKey(name, remote)
		}
		running := a.running[name]
		if running != nil && running.key != key {
			log.Printf("%s: stopping", name)
			a.stop(name)
			running = nil
		}
		switch {
		case key == "":
			a.mu.Lock()
			if wanted && !allowed {
				fs.State, fs.Error = "refused", "agent.json does not allow it"
			} else if fs.State != "off" {
				*fs = FeatureStatus{State: "off", Wanted: wanted, Allowed: allowed}
			}
			a.mu.Unlock()
		case running == nil:
			log.Printf("%s: starting", name)
			fctx, cancel := context.WithCancel(ctx)
			f := &feature{key: key, cancel: cancel, done: make(chan struct{})}
			a.running[name] = f
			a.mu.Lock()
			fs.State, fs.Error = "starting", ""
			a.mu.Unlock()
			go func() {
				defer close(f.done)
				if name == "proxy" {
					a.runProxy(fctx, fs)
				} else {
					a.runMesh(fctx, fs, remote)
				}
			}()
		}
	}
}

// featureKey: everything a feature is started with; when it changes, it is restarted.
func (a *Agent) featureKey(name string, remote *RemoteConfig) string {
	var v any
	if name == "proxy" {
		v = a.cfg.Proxy
	} else {
		v = []any{a.cfg.Mesh, remote.Features.Mesh.Prefix}
	}
	raw, _ := json.Marshal(v)
	if name == "proxy" {
		return fmt.Sprintf("%p %s", a.conn, raw) // the proxy uses the gRPC connection
	}
	return string(raw)
}

func (a *Agent) stop(name string) {
	f := a.running[name]
	if f == nil {
		return
	}
	f.cancel()
	select {
	case <-f.done:
	case <-time.After(15 * time.Second):
		log.Printf("%s: did not stop within 15 s", name)
	}
	delete(a.running, name)
	a.mu.Lock()
	fs := a.status.Features[name]
	*fs = FeatureStatus{State: "off", Wanted: fs.Wanted, Allowed: fs.Allowed}
	a.mu.Unlock()
}

func (a *Agent) stopAll() {
	for _, name := range features {
		a.stop(name)
	}
}

func (a *Agent) setFeature(fs *FeatureStatus, state string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fs.State, fs.Error = state, ""
	if err != nil {
		fs.Error = err.Error()
	}
}

// sleep: false when ctx ended.
func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// runProxy runs the etcd proxy until ctx ends, starting it again after failures.
func (a *Agent) runProxy(ctx context.Context, fs *FeatureStatus) {
	c := a.cfg.Proxy
	listen := cmpOr(c.Listen, "127.0.0.1:2379")
	ops := cmpOr(c.OpsListen, "127.0.0.1:9390")
	if ops == "off" {
		ops = ""
	}
	a.mu.Lock()
	fs.Listen = listen
	a.mu.Unlock()
	for ctx.Err() == nil {
		master, err := LoadMasterKey(a.paths.state(masterKey))
		if err != nil {
			a.setFeature(fs, "error", fmt.Errorf("no master key: %v (only control plane nodes run the etcd proxy)", err))
			if !sleep(ctx, retryFeature) {
				return
			}
			continue
		}
		p, err := proxy.Start(ctx, a.conn, proxy.Options{Listen: listen, OpsListen: ops, StateFile: a.paths.state(proxyState),
			Node: a.id.Node, Master: master, History: time.Duration(c.History), Verbose: c.Verbose, TrustBackend: c.TrustBackend})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.setFeature(fs, "error", err)
			log.Printf("proxy: %v", err)
			if !sleep(ctx, retryFeature) {
				return
			}
			continue
		}
		log.Printf("proxy: serving etcd on %s", p.Addr())
		for ctx.Err() == nil {
			a.mu.Lock()
			fs.Revision = p.Revision()
			switch {
			case p.Err() != nil:
				fs.State, fs.Error = "error", p.Err().Error()
			case p.Ready():
				fs.State, fs.Error = "running", ""
			default:
				fs.State = "starting"
			}
			a.mu.Unlock()
			sleep(ctx, tick)
		}
		p.Shutdown()
		return
	}
}

// runMesh joins the mesh (control plane nodes sign their own certificate) and runs it.
func (a *Agent) runMesh(ctx context.Context, fs *FeatureStatus, remote *RemoteConfig) {
	for ctx.Err() == nil {
		st, priv, err := a.meshSetUp(ctx, remote)
		if err == nil {
			c := a.cfg.Mesh
			a.setFeature(fs, "starting", nil)
			err = mesh.Run(ctx, mesh.Config{Cluster: a.id.Cluster, Node: a.id.Node, Interface: c.Interface, ListenPort: st.Port,
				MTU: c.MTU, Mode: c.Mode, PrivateKey: priv, Certificate: st.Certificate, MeshKey: st.MeshKey, Prefix: st.Prefix,
				Backend: &meshBackend{api: a.api, tok: a.tok}, OnStatus: func(s mesh.Status) {
					a.mu.Lock()
					defer a.mu.Unlock()
					fs.Mesh = &s
					if s.Backend {
						fs.State, fs.Error = "running", ""
					} else if fs.State == "running" {
						fs.State = "starting"
					}
				}})
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			a.setFeature(fs, "error", err)
			log.Printf("mesh: %v", err)
		}
		if !sleep(ctx, retryFeature) {
			return
		}
	}
}

// meshSetUp: a worker has everything from its invite; a control plane node gets its address
// from the backend and signs its own certificate with the cluster's mesh key.
func (a *Agent) meshSetUp(ctx context.Context, remote *RemoteConfig) (*meshState, string, error) {
	var st meshState
	if raw, err := os.ReadFile(a.paths.state(meshFile)); err == nil {
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, "", fmt.Errorf("%s: %v", meshFile, err)
		}
	}
	privRaw, err := os.ReadFile(a.paths.state(wgKey))
	priv := string(privRaw)
	if a.id.Role == "worker" {
		if err != nil || st.Certificate == "" {
			return nil, "", errors.New("this worker has no mesh certificate (it comes with the invite file)")
		}
	} else {
		master, err2 := LoadMasterKey(a.paths.state(masterKey))
		if err2 != nil {
			return nil, "", fmt.Errorf("no master key: %v", err2)
		}
		if err != nil {
			var pub string
			priv, pub = wireGuardKeys()
			if err := writeFileAtomic(a.paths.state(wgKey), []byte(priv+"\n"), 0o600); err != nil {
				return nil, "", err
			}
			st.WireGuardKey = pub
		}
		pub, err := wireGuardPublic(priv)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %v", wgKey, err)
		}
		t, err := a.tok.get(ctx)
		if err != nil {
			return nil, "", err
		}
		var addr struct{ Address, Prefix string }
		actx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err = a.api.do(actx, "POST", "/agent/v1/mesh/address", t, map[string]string{"wireguardKey": pub}, &addr, nil)
		cancel()
		if err != nil {
			return nil, "", fmt.Errorf("mesh address: %v", err)
		}
		k, err := mesh.MeshKey(master, a.id.Cluster)
		if err != nil {
			return nil, "", err
		}
		ip, err := netip.ParseAddr(addr.Address)
		if err != nil {
			return nil, "", fmt.Errorf("mesh address %q: %v", addr.Address, err)
		}
		if st.Address != addr.Address || st.WireGuardKey != pub || st.Certificate == "" {
			c := mesh.Cert{Cluster: a.id.Cluster, Node: a.id.Node, Role: "control-plane", Address: ip}
			wg, _ := base64.StdEncoding.DecodeString(pub)
			copy(c.WireGuard[:], wg)
			if st.Certificate, err = mesh.Issue(k, c); err != nil {
				return nil, "", err
			}
		}
		st.Address, st.Prefix, st.WireGuardKey = addr.Address, addr.Prefix, pub
		st.MeshKey = base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
	}
	if remote.Features.Mesh.Prefix != "" && st.Prefix != remote.Features.Mesh.Prefix {
		log.Printf("mesh: the backend's prefix is %s, this node's certificate is for %s", remote.Features.Mesh.Prefix, st.Prefix)
	}
	if p := a.cfg.Mesh.Port; p != 0 {
		st.Port = p
	} else if st.Port == 0 {
		st.Port = 51820 + int(time.Now().UnixNano()%1000) // two nodes behind one NAT should not share a port
	}
	if err := writeJSON(a.paths.state(meshFile), st, 0o600); err != nil {
		return nil, "", err
	}
	return &st, priv, nil
}
