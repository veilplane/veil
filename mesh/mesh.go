// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Package mesh is the mesh of the veil agent: it keeps this node's WireGuard interface
// connected to every other member of the cluster's mesh.
//
//  1. Register with the backend: the mesh certificate and the node's local addresses.
//  2. Learn the public address: a WireGuard peer is pointed at the backend's reflector for a
//     moment, so WireGuard sends a handshake from its own port; the backend sees where it comes
//     from (behind NAT: the router's address and port) and hands it to the other members.
//  3. Receive the member list (again on every change), check every certificate against the
//     cluster's mesh key, and configure one WireGuard peer per member.
//  4. Find a path to each peer. In the same network (same public address) or towards a node
//     that is reachable directly: try its addresses in turn until a handshake succeeds. A node
//     with a public address does not knock at a node behind NAT; it waits for it, so that the
//     other node's packet opens its own router first.
//     Between two nodes that both sit behind NAT: hole punching. Both send at the same moment,
//     by the backend's clock, so that each packet leaves its own router before the other one
//     arrives there. Many routers (Linux among them) otherwise record the early packet as a
//     connection of their own and give the node a different port when it answers, after which
//     nothing fits. Between attempts both stay silent long enough (35 s) for such records to
//     expire. WireGuard then follows the peer if its address changes.
//  5. Report how each peer is reached (metadata only), and hand the same to the agent's status.
//
// Everything goes through the agent API (Backend): register, the member list by long polling,
// reports, the backend's clock.

package mesh

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config of the mesh, from the agent.
type Config struct {
	Cluster     string
	Node        string
	Interface   string // default veil0
	ListenPort  int    // default 51820
	MTU         int    // default 1420
	Mode        string // auto, kernel or userspace
	PrivateKey  string // WireGuard private key (base64)
	Certificate string // this node's mesh certificate
	MeshKey     string // public half of the cluster's mesh key (base64)
	Prefix      string // the mesh network, e.g. 10.200.0.0/16

	// Backend: the agent API (it carries the access token).
	Backend Backend
	// OnStatus is called with the current state every few seconds.
	OnStatus func(Status)
}

// Run brings the interface up and keeps the mesh connected until ctx ends; then the interface
// is removed again.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Interface == "" {
		cfg.Interface = "veil0"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 51820
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	if cfg.Mode == "" {
		cfg.Mode = "auto"
	}
	a, err := newAgent(&cfg)
	if err != nil {
		return err
	}
	return a.run(ctx)
}

const (
	tryEach       = 6 * time.Second   // time for one address before the next is tried
	retryAfter    = 30 * time.Second  // pause between rounds once every address failed twice
	handshakeLive = 180 * time.Second // WireGuard renews sessions every 2 minutes
	keepaliveTime = 25 * time.Second
	reflectEvery  = 60 * time.Second
	reportEvery   = 15 * time.Second
	punchEvery    = 35 * time.Second // > 30 s, Linux's timeout for unanswered UDP
	punchWindow   = 4500 * time.Millisecond
)

type candidate struct {
	addr netip.AddrPort
	lan  bool // an interface address of a node behind the same public address
}

type peer struct {
	node       string
	cert       Cert
	candidates []candidate
	idx        int
	tried      time.Time
	rounds     int
	state      peerState
	path       string
	endpoint   string
	handshake  time.Time
	refused    string

	// hole punching (both behind NAT): attempts at agreed times, silent in between
	punch     bool
	passive   bool // we have a public address, the peer is behind NAT: it comes to us
	added     time.Time
	options   []netip.AddrPort // the peer's public addresses
	scheduled int64            // number of the attempt scheduled last
	window    time.Time        // end of the running attempt
	attempts  int
}

type agent struct {
	cfg      *Config
	self     Cert
	selfCert string
	meshKey  ed25519.PublicKey
	prefix   netip.Prefix
	wg       *wgInterface
	priv     wgtypes.Key

	mu        sync.Mutex
	peers     map[string]*peer // by node
	observed  netip.AddrPort   // our public address, as the reflector saw it
	reflector netip.AddrPort
	reflKey   wgtypes.Key
	reflSince time.Time
	connected bool
	local     []netip.AddrPort // our interface addresses, as last registered
	offset    time.Duration    // the backend's clock minus ours
	warnings  []string         // conflicts with the machine (conflicts), checked every warnEvery
	warnedAt  time.Time
}

// warnEvery: how often the machine is checked for conflicts with the mesh (Tailscale may start
// later, another interface may come up).
const warnEvery = 30 * time.Second

func newAgent(cfg *Config) (*agent, error) {
	a := &agent{cfg: cfg, peers: map[string]*peer{}}
	rk, err := base64.StdEncoding.DecodeString(cfg.MeshKey)
	if err != nil || len(rk) != ed25519.PublicKeySize {
		return nil, errors.New("config: meshKey is not an Ed25519 public key")
	}
	a.meshKey = rk
	if a.self, err = verifyCert(a.meshKey, cfg.Certificate); err != nil {
		return nil, fmt.Errorf("config: own certificate: %v", err)
	}
	if a.self.Cluster != cfg.Cluster || a.self.Node != cfg.Node {
		return nil, errors.New("config: the certificate is for another cluster or node")
	}
	a.selfCert = cfg.Certificate
	if a.prefix, err = netip.ParsePrefix(cfg.Prefix); err != nil || !a.prefix.Contains(a.self.Address) {
		return nil, fmt.Errorf("config: prefix %q does not contain this node's address %s", cfg.Prefix, a.self.Address)
	}
	if a.priv, err = wgtypes.ParseKey(strings.TrimSpace(cfg.PrivateKey)); err != nil {
		return nil, fmt.Errorf("config: WireGuard private key: %v", err)
	}
	if pub := a.priv.PublicKey(); pub != wgtypes.Key(a.self.WireGuard) {
		return nil, errors.New("config: the WireGuard key does not match the certificate")
	}
	return a, nil
}

func (a *agent) run(ctx context.Context) error {
	var err error
	a.wg, err = openInterface(a.cfg.Interface, a.cfg.Mode, a.cfg.MTU, netip.PrefixFrom(a.self.Address, a.prefix.Bits()))
	if err != nil {
		return err
	}
	defer a.wg.Close()
	port := a.cfg.ListenPort
	if err := a.wg.configure(wgtypes.Config{PrivateKey: &a.priv, ListenPort: &port, ReplacePeers: true}); err != nil {
		return err
	}
	log.Printf("%s up (%s), %s in %s, mesh of cluster %s", a.cfg.Interface, a.wg.mode, a.self.Address, a.prefix, a.cfg.Cluster)
	a.mu.Lock()
	a.checkConflicts()
	a.mu.Unlock()

	if a.cfg.Backend == nil {
		return errors.New("no connection to the backend")
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		a.setConnected(false)
		a.writeStatus()
		if ctx.Err() != nil {
			break
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		log.Printf("mesh: backend: %v; again in %v", err, backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
	return nil
}

func (a *agent) setConnected(v bool) {
	a.mu.Lock()
	a.connected = v
	a.mu.Unlock()
}

// session: registration and the member list (long polling), until something fails.
func (a *agent) session(ctx context.Context) error {
	b := a.cfg.Backend
	sctx, stop := context.WithCancel(ctx)
	defer stop()

	if err := a.register(sctx); err != nil {
		return err
	}
	lists := make(chan *PeerList, 4)
	failed := make(chan error, 1)
	go func() {
		etag := ""
		for {
			l, tag, err := b.Peers(sctx, etag)
			if err != nil {
				failed <- err
				return
			}
			if l == nil {
				continue // unchanged
			}
			etag = tag
			select {
			case lists <- l:
			case <-sctx.Done():
				return
			}
		}
	}()
	a.setConnected(true)
	log.Printf("mesh: connected to the backend")

	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	lastReport, lastRegister := time.Time{}, time.Now()
	a.reflect()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-failed:
			return err
		case l := <-lists:
			a.apply(l)
		case <-tick.C:
			now := time.Now()
			if now.Sub(lastRegister) > reflectEvery {
				// addresses change (DHCP, roaming); the NAT mapping too
				if err := a.register(sctx); err != nil {
					return err
				}
				lastRegister = now
				a.reflect()
			}
			a.maintain(now)
			if now.Sub(lastReport) > reportEvery {
				lastReport = now
				rctx, c := context.WithTimeout(sctx, 10*time.Second)
				err := b.Report(rctx, a.report())
				c()
				if err != nil {
					return err
				}
			}
			a.writeStatus()
		}
	}
}

func (a *agent) register(ctx context.Context) error {
	local := localEndpoints(a.cfg.Interface, a.cfg.ListenPort)
	var addrs []string
	for _, e := range local {
		addrs = append(addrs, e.String())
	}
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	r, err := a.cfg.Backend.Register(rctx, a.selfCert, addrs)
	if err != nil {
		return err
	}
	offset, synced := a.clock(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.local = local
	if synced {
		if d := (offset - a.offset).Abs(); d > 50*time.Millisecond {
			log.Printf("clock: %v off the backend's", offset.Round(time.Millisecond))
		}
		a.offset = offset
	}
	a.reflector = netip.AddrPort{}
	if r.Reflector != "" && len(r.ReflectorKey) == 32 {
		if ua, err := net.ResolveUDPAddr("udp", r.Reflector); err == nil {
			a.reflector = ua.AddrPort()
			if a.reflector.Addr().Is4In6() {
				a.reflector = netip.AddrPortFrom(a.reflector.Addr().Unmap(), a.reflector.Port())
			}
			copy(a.reflKey[:], r.ReflectorKey)
		} else {
			log.Printf("reflector %s: %v", r.Reflector, err)
		}
	}
	return nil
}

// clock measures the difference between the backend's clock and ours, like NTP: a few
// samples, the one with the shortest round trip wins (its answer was most likely written in the
// middle of it). Hole punching between two nodes behind NAT needs both to send within a
// fraction of the delay between them.
func (a *agent) clock(ctx context.Context) (time.Duration, bool) {
	best, offset := time.Duration(1<<62), time.Duration(0)
	for i := 0; i < 5; i++ {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		sent := time.Now()
		t, err := a.cfg.Backend.Clock(cctx)
		got := time.Now()
		cancel()
		if err != nil {
			return 0, false
		}
		if rtt := got.Sub(sent); rtt < best {
			best = rtt
			offset = t.Sub(sent.Add(rtt / 2))
		}
	}
	return offset, true
}

// reflect points a peer at the reflector for a moment: WireGuard sends a handshake initiation
// from its port, which tells the backend our public address. The peer is removed again by
// maintain, so it does not keep sending.
func (a *agent) reflect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.reflector.IsValid() {
		return
	}
	err := a.wg.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{
		PublicKey:                   a.reflKey,
		Endpoint:                    udpAddr(a.reflector),
		PersistentKeepaliveInterval: keepalive(keepaliveTime), // turning it on sends at once
		ReplaceAllowedIPs:           true,
	}}})
	if err != nil {
		log.Printf("reflector peer: %v", err)
		return
	}
	a.reflSince = time.Now()
}

// localEndpoints: this node's addresses with the WireGuard port, without loopback, link-local,
// the mesh itself and the usual container and Kubernetes interfaces.
func localEndpoints(meshIf string, port int) []netip.AddrPort {
	var out []netip.AddrPort
	ifs, _ := net.Interfaces()
	skip := []string{"lo", "docker", "veth", "cni", "flannel", "cali", "kube", "lxc", "virbr", "br-", "vxlan", "tun", "wg", "tailscale", "veil"}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Name == meshIf {
			continue
		}
		bad := false
		for _, p := range skip {
			if strings.HasPrefix(i.Name, p) {
				bad = true
			}
		}
		if bad {
			continue
		}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			pfx, err := netip.ParsePrefix(ad.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr()
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || (ip.Is6() && !ip.IsGlobalUnicast()) {
				continue
			}
			out = append(out, netip.AddrPortFrom(ip, uint16(port)))
			if len(out) == 8 {
				return out
			}
		}
	}
	return out
}

// apply takes a new member list from the backend.
func (a *agent) apply(l *PeerList) {
	a.mu.Lock()
	defer a.mu.Unlock()
	type entry struct {
		node     string
		cert     Cert
		local    []netip.AddrPort
		observed netip.AddrPort
		refused  string
	}
	var entries []entry
	seenAddr := map[netip.Addr]string{a.self.Address: a.self.Node}
	seenKey := map[[32]byte]string{a.self.WireGuard: a.self.Node}
	for _, p := range l.Peers {
		e := entry{node: p.Node}
		for _, ep := range p.Endpoints {
			ap, err := netip.ParseAddrPort(ep.Address)
			if err != nil {
				continue
			}
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if ep.Kind == Observed {
				e.observed = ap
			} else {
				e.local = append(e.local, ap)
			}
		}
		if p.Node == a.self.Node {
			a.observed = e.observed
			continue
		}
		c, err := verifyCert(a.meshKey, p.Certificate)
		switch {
		case err != nil:
			e.refused = err.Error()
		case c.Cluster != a.cfg.Cluster || c.Node != p.Node:
			e.refused = "certificate for another cluster or node"
		case !a.prefix.Contains(c.Address):
			e.refused = "address outside the mesh network"
		case seenAddr[c.Address] != "":
			e.refused = "address already used by " + seenAddr[c.Address]
		case seenKey[c.WireGuard] != "":
			e.refused = "WireGuard key already used by " + seenKey[c.WireGuard]
		default:
			seenAddr[c.Address], seenKey[c.WireGuard] = p.Node, p.Node
		}
		e.cert = c
		entries = append(entries, e)
	}

	var cfg []wgtypes.PeerConfig
	keep := map[string]bool{}
	for _, e := range entries {
		keep[e.node] = true
		old := a.peers[e.node]
		if e.refused != "" {
			if old == nil || old.refused != e.refused {
				log.Printf("refused peer %s: %s", e.node, e.refused)
			}
			if old != nil && old.refused == "" {
				cfg = append(cfg, wgtypes.PeerConfig{PublicKey: wgtypes.Key(old.cert.WireGuard), Remove: true})
			}
			a.peers[e.node] = &peer{node: e.node, refused: e.refused, state: stateRefused}
			continue
		}
		// Towards a node behind NAT nothing goes to its public address unless both send at the
		// agreed moment (hole punching), or we are known to have a public address ourselves.
		// An early packet would make its router (and ours) pick other ports for good.
		cands := a.candidates(e.local, e.observed)
		peerNAT := e.observed.IsValid() && !hasAddr(e.local, e.observed.Addr())
		known := a.observed.IsValid()
		sameNAT := known && e.observed.IsValid() && e.observed.Addr() == a.observed.Addr()
		punch := peerNAT && !sameNAT && (!known || a.behindNAT())
		passive := peerNAT && !sameNAT && known && !a.behindNAT()
		var options []netip.AddrPort
		if punch || passive {
			var rest []candidate
			for _, c := range cands {
				if c.addr.Addr() == e.observed.Addr() {
					if known && punch {
						options = append(options, c.addr)
					}
				} else {
					rest = append(rest, c)
				}
			}
			cands = rest
		} else if sameNAT {
			var lan []candidate
			for _, c := range cands {
				if c.lan {
					lan = append(lan, c)
				}
			}
			cands = lan
		}
		p := old
		if p == nil || p.refused != "" || p.cert.WireGuard != e.cert.WireGuard || p.cert.Address != e.cert.Address {
			if p != nil && p.refused == "" {
				cfg = append(cfg, wgtypes.PeerConfig{PublicKey: wgtypes.Key(p.cert.WireGuard), Remove: true})
			}
			p = &peer{node: e.node, cert: e.cert, state: stateTrying, punch: punch, passive: passive, added: time.Now()}
			a.peers[e.node] = p
			pc := wgtypes.PeerConfig{PublicKey: wgtypes.Key(e.cert.WireGuard), ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{hostRoute(e.cert.Address)}}
			if len(cands) > 0 && !punch {
				pc.Endpoint = udpAddr(cands[0].addr)
				pc.PersistentKeepaliveInterval = keepalive(keepaliveTime)
				p.tried = time.Now()
			}
			cfg = append(cfg, pc)
			mode := "trying its addresses"
			if punch {
				mode = "hole punching (both behind NAT)"
			} else if passive {
				mode = "behind NAT, waiting for it to reach us"
			}
			log.Printf("peer %s (%s, %s): %s", e.node, e.cert.Role, e.cert.Address, mode)
		} else if p.state != stateConnected && (p.punch != punch || p.passive != passive ||
			(!punch && !sameCandidates(p.candidates, cands)) || (punch && !sameAddrs(p.options, options))) {
			// behind symmetric NAT the reflector sees a new port every time: not a new chance
			if (punch || passive) && !p.punch && !p.passive {
				a.silence(p)
			}
			p.punch, p.passive, p.attempts, p.window, p.added = punch, passive, 0, time.Time{}, time.Now()
			p.idx, p.rounds, p.tried = -1, 0, time.Time{} // new addresses: start over at once
		}
		p.candidates, p.options = cands, options
	}
	for node, p := range a.peers {
		if !keep[node] {
			if p.refused == "" {
				cfg = append(cfg, wgtypes.PeerConfig{PublicKey: wgtypes.Key(p.cert.WireGuard), Remove: true})
				log.Printf("peer %s left the mesh", node)
			}
			delete(a.peers, node)
		}
	}
	if len(cfg) > 0 {
		if err := a.wg.configure(wgtypes.Config{Peers: cfg}); err != nil {
			log.Printf("configure peers: %v", err)
		}
	}
	for _, p := range a.peers {
		if p.refused == "" && p.state != stateConnected && !p.punch && !p.passive {
			a.poke(p)
		}
	}
}

// sameAddrs: the same IP addresses, whatever the ports.
func sameAddrs(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Addr() != b[i].Addr() {
			return false
		}
	}
	return true
}

func hasAddr(list []netip.AddrPort, a netip.Addr) bool {
	for _, l := range list {
		if l.Addr() == a {
			return true
		}
	}
	return false
}

// behindNAT: the backend saw us at an address that is none of our own.
func (a *agent) behindNAT() bool {
	return a.observed.IsValid() && !hasAddr(a.local, a.observed.Addr())
}

// silence takes the peer's address away, so WireGuard stops sending to it (and stops renewing
// the records in the routers on the way); it still answers if the peer gets through.
func (a *agent) silence(p *peer) {
	key := wgtypes.Key(p.cert.WireGuard)
	if err := a.wg.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}}); err != nil {
		log.Printf("configure peer %s: %v", p.node, err)
	}
	if err := a.wg.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{hostRoute(p.cert.Address)}}}}); err != nil {
		log.Printf("configure peer %s: %v", p.node, err)
	}
}

// punchPhase spreads the attempts of different pairs over the period; both sides of a pair
// compute the same value.
func punchPhase(x, y string) time.Duration {
	if x > y {
		x, y = y, x
	}
	h := uint32(2166136261)
	for _, c := range []byte(x + "\x00" + y) {
		h = (h ^ uint32(c)) * 16777619
	}
	return time.Duration(h%uint32(punchEvery/time.Millisecond)) * time.Millisecond
}

// schedulePunch arranges the next attempt for a peer behind NAT, at the time both sides agree on.
func (a *agent) schedulePunch(p *peer, now time.Time) {
	if len(p.options) == 0 || !p.window.IsZero() {
		return
	}
	phase := punchPhase(a.self.Node, p.node)
	server := now.Add(a.offset).UnixMilli() - phase.Milliseconds()
	period := punchEvery.Milliseconds()
	k := server/period + 1
	wait := time.Duration(k*period-server) * time.Millisecond
	if wait > 3*time.Second || p.scheduled == k {
		return
	}
	p.scheduled = k
	node := p.node
	time.AfterFunc(wait, func() { a.punchAttempt(node, k) })
}

// punchAttempt: point WireGuard at the peer's public address and switch the keepalive on, which
// sends a handshake at once. The peer does the same towards us at this moment.
func (a *agent) punchAttempt(node string, k int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.peers[node]
	if p == nil || !p.punch || p.state == stateConnected || len(p.options) == 0 {
		return
	}
	target := p.options[int(k)%len(p.options)]
	// A fresh peer: WireGuard sends at most one handshake every 5 s, and counts attempts that
	// failed for want of an address too (traffic to the peer while it was silent), which could
	// hold back exactly this one.
	key := wgtypes.Key(p.cert.WireGuard)
	a.wg.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}})
	err := a.wg.configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Endpoint: udpAddr(target),
		PersistentKeepaliveInterval: keepalive(keepaliveTime), ReplaceAllowedIPs: true,
		AllowedIPs: []net.IPNet{hostRoute(p.cert.Address)}}}})
	if err != nil {
		log.Printf("configure peer %s: %v", node, err)
		return
	}
	p.window, p.endpoint = time.Now().Add(punchWindow), target.String()
	p.attempts++
	if p.attempts <= 2*len(p.options) {
		log.Printf("hole punching towards %s at %s (attempt %d)", node, target, p.attempts)
	}
}

// candidates orders a peer's addresses: behind the same public address its interface
// addresses come first (routers rarely send traffic back into their own network), otherwise
// its public address. Its other interface addresses are tried as well: they may be reachable
// directly (public IPs, a private network between data centres, IPv6).
func (a *agent) candidates(local []netip.AddrPort, observed netip.AddrPort) []candidate {
	sameNAT := observed.IsValid() && a.observed.IsValid() && observed.Addr() == a.observed.Addr()
	var out []candidate
	add := func(ap netip.AddrPort, lan bool) {
		for _, c := range out {
			if c.addr == ap {
				return
			}
		}
		out = append(out, candidate{addr: ap, lan: lan})
	}
	if sameNAT {
		for _, l := range local {
			if l.Addr().Is4() {
				add(l, true)
			}
		}
	}
	if observed.IsValid() {
		add(observed, false)
		// The reflector saw the port the router chose towards the backend. Many routers (Linux
		// among them) choose per destination and keep the node's own port where they can, so
		// the public address with the node's WireGuard port is worth a try too.
		for _, l := range local {
			if l.Port() != observed.Port() {
				add(netip.AddrPortFrom(observed.Addr(), l.Port()), false)
			}
		}
	}
	for _, l := range local {
		add(l, sameNAT && l.Addr().Is4())
	}
	return out
}

func sameCandidates(a, b []candidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// poke sends one packet through the tunnel to the peer: WireGuard starts a handshake at once
// instead of at the next keepalive.
func (a *agent) poke(p *peer) {
	if a.wg.client == nil {
		return // tests
	}
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: p.cert.Address.AsSlice(), Port: 9})
	if err != nil {
		return
	}
	c.Write([]byte{0})
	c.Close()
}

// maintain checks the handshakes and moves on to the next address where none happened.
func (a *agent) maintain(now time.Time) {
	dev, err := a.wg.device()
	if err != nil {
		log.Printf("read %s: %v", a.cfg.Interface, err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	byKey := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range dev.Peers {
		byKey[p.PublicKey] = p
	}
	var cfg []wgtypes.PeerConfig
	if !a.reflSince.IsZero() && now.Sub(a.reflSince) > 4*time.Second {
		cfg = append(cfg, wgtypes.PeerConfig{PublicKey: a.reflKey, Remove: true})
		a.reflSince = time.Time{}
	}
	for _, p := range a.peers {
		if p.refused != "" {
			continue
		}
		w, ok := byKey[wgtypes.Key(p.cert.WireGuard)]
		if ok {
			p.handshake = w.LastHandshakeTime
		}
		if ok && !w.LastHandshakeTime.IsZero() && now.Sub(w.LastHandshakeTime) < handshakeLive {
			if p.state != stateConnected {
				log.Printf("peer %s connected via %v", p.node, w.Endpoint)
			}
			p.state, p.rounds = stateConnected, 0
			if w.Endpoint != nil {
				ep := w.Endpoint.AddrPort()
				ep = netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port())
				p.endpoint, p.path = ep.String(), "direct"
				for _, c := range p.candidates {
					if c.addr == ep && c.lan {
						p.path = "lan"
					}
				}
			}
			continue
		}
		if p.state == stateConnected {
			log.Printf("peer %s lost (no handshake for %v)", p.node, handshakeLive)
			p.state, p.idx, p.rounds, p.tried = stateTrying, -1, 0, time.Time{}
			p.attempts, p.window = 0, time.Time{}
			p.added = now
			if p.punch || p.passive {
				a.silence(p)
			}
		}
		if p.passive {
			if now.Sub(p.added) > 2*time.Minute {
				if p.state != stateUnreachable {
					log.Printf("peer %s unreachable: it is behind NAT and has not reached us", p.node)
				}
				p.state = stateUnreachable
			}
			continue
		}
		if p.punch {
			if !p.window.IsZero() && now.After(p.window) {
				a.silence(p) // no handshake: quiet until the next agreed moment
				p.window = time.Time{}
			}
			if p.attempts >= 2*max(1, len(p.options)) {
				if p.state != stateUnreachable {
					log.Printf("peer %s unreachable: hole punching failed %d times (symmetric NAT on both sides, or UDP blocked)",
						p.node, p.attempts)
				}
				p.state = stateUnreachable
			}
			a.schedulePunch(p, now)
			continue
		}
		if len(p.candidates) == 0 {
			p.state = stateUnreachable
			continue
		}
		wait := tryEach
		if p.rounds >= 2 {
			wait = retryAfter
		}
		if now.Sub(p.tried) < wait {
			continue
		}
		p.idx++
		if p.idx >= len(p.candidates) {
			p.idx = 0
			p.rounds++
		}
		if p.rounds >= 2 {
			if p.state != stateUnreachable {
				log.Printf("peer %s unreachable: no handshake on any of its %d addresses", p.node, len(p.candidates))
			}
			p.state = stateUnreachable
		} else {
			p.state = stateTrying
		}
		p.tried = now
		p.endpoint = p.candidates[p.idx].addr.String()
		cfg = append(cfg, wgtypes.PeerConfig{PublicKey: wgtypes.Key(p.cert.WireGuard), UpdateOnly: true,
			Endpoint: udpAddr(p.candidates[p.idx].addr)})
		defer a.poke(p)
	}
	if len(cfg) > 0 {
		if err := a.wg.configure(wgtypes.Config{Peers: cfg}); err != nil {
			log.Printf("configure peers: %v", err)
		}
	}
}

func (a *agent) report() []PeerReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := []PeerReport{}
	for _, p := range a.sortedPeers() {
		s := PeerReport{Node: p.node, State: p.state.name()}
		if p.state == stateConnected {
			s.Path, s.Endpoint = p.path, p.endpoint
		}
		if !p.handshake.IsZero() {
			s.LastHandshake = p.handshake.Unix()
		}
		r = append(r, s)
	}
	return r
}

func (a *agent) sortedPeers() []*peer {
	out := make([]*peer, 0, len(a.peers))
	for _, p := range a.peers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].node < out[j].node })
	return out
}

// Status is what the mesh reports to the agent (and the agent to its status file).
type Status struct {
	Node      string       `json:"node"`
	Address   string       `json:"address"`
	Interface string       `json:"interface"`
	Mode      string       `json:"mode"`
	Backend   bool         `json:"backend"`
	Public    string       `json:"public,omitempty"`
	Updated   time.Time    `json:"updated"`
	Peers     []PeerStatus `json:"peers"`
	// Warnings: what on this machine gets in the way of the mesh (an overlapping network, Tailscale)
	Warnings []string `json:"warnings,omitempty"`
}

type PeerStatus struct {
	Node      string    `json:"node"`
	Role      string    `json:"role,omitempty"`
	Address   string    `json:"address,omitempty"`
	State     string    `json:"state"`
	Path      string    `json:"path,omitempty"`
	Endpoint  string    `json:"endpoint,omitempty"`
	Handshake time.Time `json:"handshake,omitzero"`
	Refused   string    `json:"refused,omitempty"`
}

// checkConflicts looks for what gets in the way of the mesh on this machine and logs what is
// new. a.mu held.
func (a *agent) checkConflicts() {
	w := conflicts(a.prefix, a.cfg.Interface, hostNets())
	for _, m := range w {
		if !slices.Contains(a.warnings, m) {
			log.Printf("mesh: %s", m)
		}
	}
	a.warnings, a.warnedAt = w, time.Now()
}

func (a *agent) writeStatus() {
	if a.cfg.OnStatus == nil {
		return
	}
	a.mu.Lock()
	mode := ""
	if a.wg != nil {
		mode = a.wg.mode
	}
	s := Status{Node: a.self.Node, Address: a.self.Address.String(), Interface: a.cfg.Interface, Mode: mode,
		Backend: a.connected, Updated: time.Now().UTC()}
	if a.observed.IsValid() {
		s.Public = a.observed.String()
	}
	if time.Since(a.warnedAt) > warnEvery {
		a.checkConflicts()
	}
	s.Warnings = a.warnings
	for _, p := range a.sortedPeers() {
		ps := PeerStatus{Node: p.node, State: strings.ToLower(p.state.String()), Refused: p.refused, Handshake: p.handshake}
		if p.refused == "" {
			ps.Role, ps.Address = p.cert.Role, p.cert.Address.String()
		}
		if p.state == stateConnected {
			ps.Path, ps.Endpoint = p.path, p.endpoint
		}
		s.Peers = append(s.Peers, ps)
	}
	a.mu.Unlock()
	a.cfg.OnStatus(s)
}
