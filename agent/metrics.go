// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/veilplane/veil/mesh"
)

// The agent's metrics, for Prometheus (and Grafana on top): one address per node with everything
// it does, on every node (workers too): the agent and its backend connection, the features, the
// etcd proxy (the same series as on the proxy's ops address) and the mesh with every peer.
// Text format, written by hand: no client library, no dependency.

const defaultMetricsListen = "127.0.0.1:9391"

// The states the agent and its features can be in: each gets a series, 1 for the current one.
var (
	agentStates   = []string{"starting", "joining", "running", "revoked", "error", "stopped"}
	featureStates = []string{"off", "refused", "starting", "running", "error"}
	peerStates    = []string{"connected", "blocked", "trying", "unreachable", "refused"}
)

// metricsServer is the running metrics address.
type metricsServer struct {
	addr  string // as configured
	bound string // where it listens (with port 0: the port it got)
	srv   *http.Server
}

// ensureMetrics starts, moves or stops the metrics address as agent.json says (metrics.listen,
// default 127.0.0.1:9391, "off": none).
func (a *Agent) ensureMetrics() {
	want := defaultMetricsListen
	if a.cfg != nil && a.cfg.Metrics.Listen != "" {
		want = a.cfg.Metrics.Listen
	}
	if want == "off" {
		want = ""
	}
	if a.metrics != nil && a.metrics.addr == want {
		return
	}
	a.stopMetrics()
	if want == "" {
		return
	}
	ln, err := net.Listen("tcp", want)
	if err != nil {
		log.Printf("metrics: %v", err)
		a.metrics = &metricsServer{addr: want} // do not try again until agent.json changes it
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		a.writeMetrics(w)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	a.metrics = &metricsServer{addr: want, bound: ln.Addr().String(), srv: srv}
	log.Printf("metrics on http://%s/metrics", ln.Addr())
}

func (a *Agent) stopMetrics() {
	if a.metrics != nil && a.metrics.srv != nil {
		a.metrics.srv.Close()
	}
	a.metrics = nil
}

// prom writes Prometheus' text format: each metric's HELP and TYPE once, before its first sample.
type prom struct {
	w    io.Writer
	seen map[string]bool
}

func (p *prom) sample(name, typ, help string, value float64, labels ...string) {
	if !p.seen[name] {
		p.seen[name] = true
		fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	var l []string
	for i := 0; i+1 < len(labels); i += 2 {
		l = append(l, fmt.Sprintf("%s=%q", labels[i], labels[i+1]))
	}
	set := ""
	if len(l) > 0 {
		set = "{" + strings.Join(l, ",") + "}"
	}
	fmt.Fprintf(p.w, "%s%s %v\n", name, set, value)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func unixOrZero(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.Unix())
}

// writeMetrics writes everything the agent knows, from its status (the same as veil status
// shows and the backend gets), plus the proxy's own series.
func (a *Agent) writeMetrics(w io.Writer) {
	a.mu.Lock()
	st := a.status
	features := map[string]FeatureStatus{}
	for n, f := range a.status.Features {
		c := *f
		if f.Mesh != nil {
			m := *f.Mesh
			m.Peers = append([]mesh.PeerStatus(nil), f.Mesh.Peers...)
			c.Mesh = &m
		}
		features[n] = c
	}
	px := a.proxy
	a.mu.Unlock()

	p := &prom{w: w, seen: map[string]bool{}}
	p.sample("veil_agent_info", "gauge", "The agent: its version, node, cluster and role (always 1).", 1,
		"version", st.Version, "node", st.Node, "cluster", st.Cluster, "role", st.Role)
	for _, s := range agentStates {
		p.sample("veil_agent_state", "gauge", "The agent's state: 1 for the current one.", b2f(st.State == s), "state", s)
	}
	p.sample("veil_agent_backend_connected", "gauge", "Whether the agent reaches the backend.", b2f(st.Backend.Connected))
	p.sample("veil_agent_backend_last_contact_timestamp_seconds", "gauge", "When the agent last heard from the backend (Unix time).",
		unixOrZero(st.Backend.LastContact))
	p.sample("veil_agent_token_expiry_timestamp_seconds", "gauge", "When the agent's access token expires (it renews it before; Unix time).",
		unixOrZero(st.Backend.TokenExpires))

	names := make([]string, 0, len(features))
	for n := range features {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f := features[n]
		p.sample("veil_agent_feature_wanted", "gauge", "Whether the backend wants the feature on.", b2f(f.Wanted), "feature", n)
		p.sample("veil_agent_feature_allowed", "gauge", "Whether agent.json allows the feature.", b2f(f.Allowed), "feature", n)
	}
	for _, n := range names {
		for _, s := range featureStates {
			p.sample("veil_agent_feature_state", "gauge", "A feature's state: 1 for the current one.", b2f(features[n].State == s),
				"feature", n, "state", s)
		}
	}

	if f, ok := features["mesh"]; ok && f.Mesh != nil {
		writeMeshMetrics(p, f.Mesh, f.State == "running")
	}
	if px != nil {
		px.WriteMetrics(w)
	}
}

func writeMeshMetrics(p *prom, m *mesh.Status, running bool) {
	p.sample("veil_mesh_up", "gauge", "Whether the mesh runs (its interface is up, the backend reachable).", b2f(running))
	p.sample("veil_mesh_info", "gauge", "The mesh on this node: its interface, address and WireGuard mode (always 1).", 1,
		"interface", m.Interface, "address", m.Address, "mode", m.Mode)
	p.sample("veil_mesh_backend_connected", "gauge", "Whether the mesh reaches the backend (new members, address changes).", b2f(m.Backend))
	p.sample("veil_mesh_warnings", "gauge", "What on this machine gets in the way of the mesh (veil status lists it).", float64(len(m.Warnings)))
	p.sample("veil_mesh_interface_repairs_total", "counter",
		"How often the agent had to put its interface back after something else changed it (since the mesh started).", float64(m.Repairs))
	count := map[string]int{}
	for _, peer := range m.Peers {
		count[peer.State]++
	}
	for _, s := range peerStates {
		p.sample("veil_mesh_peers", "gauge", "The peers by state (blocked: a live handshake, but probes get no answer).",
			float64(count[s]), "state", s)
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_up", "gauge", "Whether a peer is reachable over the mesh (connected and answering probes).",
			b2f(peer.State == "connected"), "peer", peer.Node)
	}
	for _, peer := range m.Peers {
		for _, s := range peerStates {
			p.sample("veil_mesh_peer_state", "gauge", "A peer's state: 1 for the current one.", b2f(peer.State == s),
				"peer", peer.Node, "state", s)
		}
	}
	for _, peer := range m.Peers {
		if peer.State == "connected" {
			p.sample("veil_mesh_peer_path", "gauge", "How a connected peer is reached: lan or direct (always 1).", 1,
				"peer", peer.Node, "path", peer.Path)
		}
	}
	for _, peer := range m.Peers {
		if peer.RTT > 0 {
			p.sample("veil_mesh_peer_rtt_seconds", "gauge", "Round trip to a peer over the mesh (the probes', smoothed).", peer.RTT,
				"peer", peer.Node)
		}
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_probes_total", "counter", "Probes sent to a peer.", float64(peer.Probes), "peer", peer.Node)
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_probe_answers_total", "counter", "Answers to probes received from a peer.", float64(peer.Answers),
			"peer", peer.Node)
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_receive_bytes_total", "counter", "Bytes received from a peer (WireGuard).", float64(peer.RxBytes),
			"peer", peer.Node)
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_transmit_bytes_total", "counter", "Bytes sent to a peer (WireGuard).", float64(peer.TxBytes),
			"peer", peer.Node)
	}
	for _, peer := range m.Peers {
		p.sample("veil_mesh_peer_last_handshake_timestamp_seconds", "gauge", "The last WireGuard handshake with a peer (Unix time).",
			unixOrZero(peer.Handshake), "peer", peer.Node)
	}
}
