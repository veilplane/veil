// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Package proxy is the etcd proxy of the veil agent (Veilplane): an end-to-end encrypting,
// verifying etcd v3 gRPC proxy.
//
// It runs on the customer's side next to kube-apiserver. The API server talks
// plain etcd v3 gRPC to this proxy. The proxy encrypts every key and value
// before it reaches the hosted, untrusted etcd-compatible backend, and it
// verifies everything the backend says before believing it.
//
// Confidentiality
//   - Keys: every path segment is padded and encrypted deterministically with
//     AES-256-SIV (RFC 5297, Google Tink), bound to its plaintext parent path.
//     Segment boundaries survive, so prefix scans work on the backend, and all
//     instances sharing the master key produce identical ciphertext keys.
//   - Values: padded, then AES-256-GCM with a random nonce; the plaintext key
//     is bound as additional data.
//   - Lengths: Padmé padding, min 32 bytes per segment and 128 per value.
//
// Integrity and freshness (see replica.go)
//   - Every value names its predecessor revision; deletes carry a receipt.
//   - Each instance is a verified replica of the whole key space: it applies
//     the backend's change stream only after checking every change, and answers
//     reads and watches from that replica.
//   - A keyed digest of the full state is checkpointed to disk and compared
//     between instances, which catches rollbacks and forks (different
//     histories shown to different instances).
//
// PROTOTYPE, not audited.
package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/bits"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tink-crypto/tink-go/v2/daead/subtle"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------------- main

type config struct {
	listen, upstream      string
	stateFile             string
	node                  string        // name in checkpoint records (default: from the device certificate)
	checkpointEvery       time.Duration // tests only (default: a minute)
	silentAfter           time.Duration // tests only (default: five minutes)
	master                []byte
	history               time.Duration
	verbose, trustBackend bool

	// conn: the connection to the backend, shared with the rest of the agent (it carries the
	// access token). Without it (tests), upstream is dialed without TLS.
	conn *grpc.ClientConn

	opsListen string // /healthz, /readyz, /metrics
}

// Version is set by the agent (its build version), for veil_build_info.
var Version = "dev"

// Options of the etcd proxy, from the agent's configuration.
type Options struct {
	Listen       string        // where kube-apiserver connects, e.g. 127.0.0.1:2379
	OpsListen    string        // /healthz, /readyz, /metrics (empty: off)
	StateFile    string        // verified checkpoints
	Node         string        // name of this instance in checkpoint records
	Master       []byte        // the cluster's master key
	History      time.Duration // verified history to keep (default ten minutes)
	Verbose      bool          // log every request with its plaintext key
	TrustBackend bool          // accept the backend state without verification (recovery only)
}

// Proxy is a running etcd proxy.
type Proxy = proxy

// Start connects through conn (the agent's connection to the backend), verifies and loads the
// replica and serves on o.Listen. It retries while the backend is unreachable; everything
// stops when ctx is canceled or Shutdown is called. conn stays open.
func Start(ctx context.Context, conn *grpc.ClientConn, o Options) (*Proxy, error) {
	return start(ctx, config{listen: o.Listen, opsListen: o.OpsListen, stateFile: o.StateFile, node: o.Node, master: o.Master,
		history: cmp.Or(o.History, 10*time.Minute), verbose: o.Verbose, trustBackend: o.TrustBackend, conn: conn})
}

// Addr is the address the proxy serves etcd on.
func (p *proxy) Addr() string { return p.addr }

// Ready: the replica is verified and the proxy serves.
func (p *proxy) Ready() bool {
	_, ok := p.rep.checkpoint()
	return ok && p.serving.Load() && p.rep.err() == nil
}

// Err is why the replica stopped (data loss detected), or nil.
func (p *proxy) Err() error { return p.rep.err() }

// Revision is the newest verified revision.
func (p *proxy) Revision() int64 { return p.rep.current() }

// Shutdown stops serving and persists a final checkpoint.
func (p *proxy) Shutdown() { p.shutdown() }

// WriteMetrics writes the proxy's metrics in Prometheus' text format (the ops address's /metrics,
// and the agent's metrics address).
func (p *proxy) WriteMetrics(w io.Writer) {
	failed := 0
	if p.rep.err() != nil {
		failed = 1
	}
	p.rep.mu.RLock()
	rev, base, keys := p.rep.rev, p.rep.base, len(p.rep.order)
	p.rep.mu.RUnlock()
	fmt.Fprintf(w, "# TYPE veil_build_info gauge\nveil_build_info{version=%q} 1\n", Version)
	fmt.Fprintf(w, "# TYPE veil_replica_failed gauge\nveil_replica_failed %d\n", failed)
	fmt.Fprintf(w, "# TYPE veil_replica_revision gauge\nveil_replica_revision %d\n", rev)
	fmt.Fprintf(w, "# TYPE veil_replica_base_revision gauge\nveil_replica_base_revision %d\n", base)
	fmt.Fprintf(w, "# TYPE veil_replica_tracked_keys gauge\nveil_replica_tracked_keys %d\n", keys)
	fmt.Fprintf(w, "# TYPE veil_backend_floor_revision gauge\nveil_backend_floor_revision %d\n", p.fresh.floor())
	fmt.Fprintf(w, "# TYPE veil_watch_streams gauge\nveil_watch_streams %d\n", p.metrics.watches.Load())
	ages := p.rep.peerAges(time.Now())
	peers := make([]string, 0, len(ages))
	silent := 0
	for n, a := range ages {
		peers = append(peers, n)
		if a > p.silentAfter {
			silent++
		}
	}
	sort.Strings(peers)
	fmt.Fprintf(w, "# TYPE veil_peers_silent gauge\nveil_peers_silent %d\n", silent)
	fmt.Fprintf(w, "# TYPE veil_peer_checkpoint_age_seconds gauge\n")
	for _, n := range peers {
		fmt.Fprintf(w, "veil_peer_checkpoint_age_seconds{node=%q} %.0f\n", n, ages[n].Seconds())
	}
	p.metrics.mu.Lock()
	keysSorted := make([]string, 0, len(p.metrics.requests))
	for k := range p.metrics.requests {
		keysSorted = append(keysSorted, k)
	}
	sort.Strings(keysSorted)
	fmt.Fprintf(w, "# TYPE veil_grpc_requests_total counter\n")
	for _, k := range keysSorted {
		method, code, _ := strings.Cut(k, " ")
		fmt.Fprintf(w, "veil_grpc_requests_total{method=%q,code=%q} %d\n", method, code, p.metrics.requests[k].Load())
	}
	p.metrics.mu.Unlock()
}

// Target turns a backend address list into a gRPC target. Several backend instances can be given as
// one DNS name with several addresses ("backend.veilplane.com:443", resolved again whenever a
// connection fails) or as a list ("10.0.0.1:2379,10.0.0.2:2379"). firstHost is the default
// server name expected in the backend certificate.
func Target(upstream string) (target string, opt grpc.DialOption, firstHost string) {
	addrs := splitList(upstream)
	if len(addrs) == 0 {
		addrs = []string{upstream}
	}
	firstHost = addrs[0]
	if h, _, err := net.SplitHostPort(addrs[0]); err == nil {
		firstHost = h
	}
	if len(addrs) == 1 {
		return "dns:///" + addrs[0], grpc.EmptyDialOption{}, firstHost
	}
	r := manual.NewBuilderWithScheme("veil-backends")
	state := resolver.State{}
	for _, a := range addrs {
		state.Addresses = append(state.Addresses, resolver.Address{Addr: a})
	}
	r.InitialState(state)
	return r.Scheme() + ":///backend", grpc.WithResolvers(r), firstHost
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// DialOptions are the gRPC options for the connection to the backend, without credentials.
func DialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		// spread calls over all backend instances; a failed instance drops out until it is back
		grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`),
		// detect dead backend connections (the watch stream is long-lived)
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		// reconnect quickly after a backend restart (gRPC's default backoff grows to 2 minutes,
		// longer than the API server's leader election tolerates)
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: backoff.Config{BaseDelay: 250 * time.Millisecond,
			Multiplier: 1.6, Jitter: 0.2, MaxDelay: 3 * time.Second}, MinConnectTimeout: 5 * time.Second}),
		// a snapshot load (Range over the whole key space) can be far larger than the 4 MB default
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxBackendMessage)),
	}
}

// start connects to the backend, verifies and loads the replica and serves.
// Everything stops when ctx is canceled.
func start(ctx context.Context, cfg config) (*proxy, error) {
	if len(cfg.master) != 32 {
		return nil, errors.New("the master key must be 32 bytes")
	}
	s, err := newSealer(cfg.master)
	if err != nil {
		return nil, err
	}
	conn := cfg.conn
	if conn == nil {
		target, resolverOpt, _ := Target(cfg.upstream)
		conn, err = grpc.Dial(target, append(DialOptions(), grpc.WithTransportCredentials(insecure.NewCredentials()), resolverOpt)...)
		if err != nil {
			return nil, err
		}
	}
	p := &proxy{
		s:       s,
		kv:      pb.NewKVClient(conn),
		watch:   pb.NewWatchClient(conn),
		lease:   pb.NewLeaseClient(conn),
		maint:   pb.NewMaintenanceClient(conn),
		rep:     newReplica(s, cfg.history),
		verbose: cfg.verbose,
		metrics: &metrics{},
	}
	p.fresh = newFreshness(cfg.stateFile, p.rep)
	p.node = cfg.node
	if p.node == "" {
		p.node, _ = os.Hostname()
	}
	p.rep.self = p.node
	p.checkpointEvery = cmp.Or(cfg.checkpointEvery, defaultCheckpointEvery)
	p.silentAfter = cmp.Or(cfg.silentAfter, defaultSilentAfter)
	if cfg.conn == nil {
		p.closers = append(p.closers, conn.Close)
	}
	if cfg.opsListen != "" {
		ln, err := net.Listen("tcp", cfg.opsListen)
		if err != nil {
			return nil, err
		}
		p.opsAddr = ln.Addr().String()
		ops := &http.Server{Handler: opsHandler(p)}
		go ops.Serve(ln)
		p.closers = append(p.closers, ops.Close)
	}
	for {
		err := p.verifyAndLoad(ctx, cfg.trustBackend)
		if err == nil {
			break
		}
		if c := status.Code(err); c != codes.Unavailable && c != codes.DeadlineExceeded {
			p.closeAll()
			return nil, err
		}
		slog.Warn("backend not reachable yet, retrying", "error", status.Convert(err).Message())
		select {
		case <-ctx.Done():
			p.closeAll()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if p.rep.err() == nil {
		p.fresh.persist() // at once: an invite written now carries this state
		go p.rep.follow(ctx, p)
	}
	go p.checkpointLoop(ctx)

	lis, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		p.closeAll()
		return nil, err
	}
	p.addr = lis.Addr().String()
	p.self = "http://" + p.addr
	p.srv = grpc.NewServer(grpc.MaxRecvMsgSize(16<<20), grpc.MaxSendMsgSize(maxBackendMessage),
		grpc.UnaryInterceptor(p.metrics.unary), grpc.StreamInterceptor(p.metrics.stream))
	pb.RegisterKVServer(p.srv, p)
	pb.RegisterWatchServer(p.srv, p)
	pb.RegisterLeaseServer(p.srv, p)
	pb.RegisterMaintenanceServer(p.srv, maintenance{proxy: p})
	pb.RegisterClusterServer(p.srv, cluster{proxy: p})
	go p.srv.Serve(lis)
	p.serving.Store(true)
	go func() { <-ctx.Done(); p.shutdown() }()
	return p, nil
}

// shutdown stops serving (waiting briefly for running requests), persists a
// final checkpoint and releases the backend connection. Safe to call twice.
func (p *proxy) shutdown() {
	p.stopOnce.Do(func() {
		if p.srv != nil {
			done := make(chan struct{})
			go func() { p.srv.GracefulStop(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second): // watches never end on their own
				p.srv.Stop()
			}
		}
		p.fresh.persist()
		p.closeAll()
	})
}

func (p *proxy) closeAll() {
	for i := len(p.closers) - 1; i >= 0; i-- {
		p.closers[i]()
	}
	p.closers = nil
}

// ---------------------------------------------------------------- operations

// metrics counts gRPC requests per method and status code.
type metrics struct {
	mu       sync.Mutex
	requests map[string]*atomic.Int64 // "method code"
	watches  atomic.Int64
}

func (m *metrics) count(method string, err error) {
	k := method + " " + status.Code(err).String()
	m.mu.Lock()
	if m.requests == nil {
		m.requests = map[string]*atomic.Int64{}
	}
	c := m.requests[k]
	if c == nil {
		c = &atomic.Int64{}
		m.requests[k] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

func (m *metrics) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	resp, err := h(ctx, req)
	m.count(info.FullMethod, err)
	return resp, err
}

func (m *metrics) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if info.FullMethod == "/etcdserverpb.Watch/Watch" {
		m.watches.Add(1)
		defer m.watches.Add(-1)
	}
	err := h(srv, ss)
	m.count(info.FullMethod, err)
	return err
}

// opsHandler serves /healthz (process alive), /readyz (replica verified and
// serving) and /metrics (Prometheus text format). A stopped replica is not
// "unhealthy": restarting would not help, it needs a human. It is "not ready"
// and veil_replica_failed is 1, which is what alerts should fire on.
func opsHandler(p *proxy) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := p.rep.err(); err != nil {
			http.Error(w, "replica stopped: "+status.Convert(err).Message(), http.StatusServiceUnavailable)
			return
		}
		if _, ok := p.rep.checkpoint(); !ok || !p.serving.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	// POST /leave removes this instance's checkpoint record (the agent leaving), so the other
	// instances stop expecting it. Only on the local ops address.
	mux.HandleFunc("/leave", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := p.removeCheckpoint(r.Context()); err != nil {
			http.Error(w, status.Convert(err).Message(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	// GET /state: the current verified checkpoints, in the state file's format, for an invite
	// file written while the proxy runs ("veil invite"). Only on the local ops address.
	mux.HandleFunc("/state", func(w http.ResponseWriter, _ *http.Request) {
		content, ok := p.fresh.current()
		if !ok {
			http.Error(w, "no verified state", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, content)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) { p.WriteMetrics(w) })
	return mux
}

// verifyAndLoad loads the replica from a state the backend can prove: the
// newest checkpoint (own, a peer's, or the last compaction anchor) whose
// digest the backend's snapshot at that revision reproduces. Verification
// failures do not stop the process; the replica refuses to serve instead.
func (p *proxy) verifyAndLoad(ctx context.Context, trustBackend bool) error {
	own, anchor, haveFile, err := p.fresh.loadFile()
	if err != nil {
		return err
	}
	var cands []checkpoint
	for _, c := range []checkpoint{own, anchor} {
		if c.rev > 0 {
			cands = append(cands, c)
			p.fresh.observe(c.rev)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].rev > cands[j].rev })
	for _, c := range cands {
		err := p.rep.load(ctx, p.kv, c.rev)
		msg := status.Convert(err).Message()
		switch {
		case err != nil && strings.Contains(msg, "compacted"):
			log.Printf("checkpoint at revision %d is no longer available on the backend, trying older ones", c.rev)
			continue
		case err != nil && strings.Contains(msg, "future revision"):
			p.rep.fail(dataLoss("backend went back in time (revision %d was already verified, the backend has not reached it)", c.rev))
			return nil
		case err != nil:
			return err
		}
		if cp, _ := p.rep.checkpoint(); cp.digest != c.digest {
			p.rep.fail(dataLoss("backend state at revision %d does not match the verified checkpoint (forged or forked history)", c.rev))
			return nil
		}
		log.Printf("replica verified against checkpoint at revision %d", c.rev)
		return nil
	}
	// No checkpoint at all: only an empty backend (a brand-new cluster) is
	// accepted without -trust-backend. Anything else could be a rolled back or
	// forged state presented to an instance that has nothing to compare with.
	if !haveFile || trustBackend {
		if err := p.rep.load(ctx, p.kv, 0); err != nil {
			return err
		}
		if trustBackend {
			log.Printf("WARNING: trustBackend: accepting the backend state at revision %d without verification", p.rep.current())
			return nil
		}
		if p.rep.size() == 0 {
			log.Printf("first start: the backend is empty (revision %d), nothing to verify", p.rep.current())
			return nil
		}
		p.rep.fail(dataLoss("the backend holds data, but there is no checkpoint to verify it (a new instance needs the state of an existing one, e.g. from an invite); start once with trustBackend (agent.json: proxy.trustBackend) if this is intended"))
		return nil
	}
	// Every checkpoint was compacted away (the instance was off for a while, or it was set up
	// from an older invite). The backend's current state is still accepted if it carries a
	// checkpoint record, written by an instance of this cluster with the master key, that is at
	// least as new as the newest checkpoint known here: then it is not a rolled back state.
	// Forks after that point are found by the records the instances keep writing.
	if err := p.rep.load(ctx, p.kv, 0); err != nil {
		return err
	}
	if newest := p.rep.newestRecord(); newest >= cands[0].rev {
		log.Printf("all checkpoints compacted; backend state verified by a checkpoint record at revision %d (>= %d)", newest, cands[0].rev)
		return nil
	}
	p.rep.fail(dataLoss("no verifiable checkpoint left (the backend compacted past all of them and holds no newer checkpoint record); start once with trustBackend (agent.json: proxy.trustBackend) to accept its state"))
	return nil
}

// ---------------------------------------------------------------- crypto

// maxBackendMessage limits responses from the backend (snapshot loads of the whole key space)
// and to the API server (which pages, but can ask for everything at once).
const maxBackendMessage = 2<<30 - 1

const (
	minSegmentSize = 32  // padded plaintext size of a key segment, at least
	minValueSize   = 128 // padded plaintext size of a value record, at least
	valueVersion   = 3
)

type sealer struct {
	seg       *subtle.AESSIV // key segments: deterministic, AES-256-SIV
	val       cipher.AEAD    // values: AES-256-GCM, random nonce
	digestKey []byte         // keys the state digest
}

func newSealer(master []byte) (*sealer, error) {
	derive := func(info string, n int) []byte {
		k, err := hkdf.Key(sha256.New, master, nil, "veil-proxy v1 "+info, n)
		if err != nil {
			panic(err)
		}
		return k
	}
	s := &sealer{digestKey: derive("state digest", 32)}
	var err error
	if s.seg, err = subtle.NewAESSIV(derive("segment aes-siv", subtle.AESSIVKeySize)); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derive("value aes-gcm", 32))
	if err != nil {
		return nil, err
	}
	if s.val, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return s, nil
}

// padme returns the Padmé size for length l (Nikitin et al., "Reducing
// Metadata Leakage from Encrypted Files and Communication with PURBs", 2019):
// at most ~12% overhead, and only O(log log l) bits of the length remain.
func padme(l int) int {
	if l < 2 {
		return l
	}
	e := bits.Len(uint(l)) - 1 // floor(log2 l)
	s := bits.Len(uint(e))     // floor(log2 e) + 1
	mask := 1<<(e-s) - 1
	return (l + mask) &^ mask
}

// pad appends 0x80 and zero bytes (ISO/IEC 7816-4) up to a Padmé size of at
// least min bytes. It is deterministic, which key segments require.
func pad(b []byte, min int) []byte {
	n := padme(len(b) + 1)
	if n < min {
		n = min
	}
	out := make([]byte, n)
	copy(out, b)
	out[len(b)] = 0x80
	return out
}

func unpad(b []byte) ([]byte, error) {
	for i := len(b) - 1; i >= 0; i-- {
		switch b[i] {
		case 0:
		case 0x80:
			return b[:i], nil
		default:
			return nil, errors.New("bad padding")
		}
	}
	return nil, errors.New("bad padding")
}

func (s *sealer) encSegment(parent, seg string) string {
	ct, err := s.seg.EncryptDeterministically(pad([]byte(seg), minSegmentSize), []byte(parent))
	if err != nil {
		panic(err) // only fails for absurdly large inputs
	}
	return base64.RawURLEncoding.EncodeToString(ct)
}

func (s *sealer) decSegment(parent, enc string) (string, error) {
	// Exactly one spelling per key: Strict() rejects non-zero padding bits, but the decoder
	// still skips '\r' and '\n', so the re-encoding must also match.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != enc {
		return "", errors.New("not an encrypted key segment")
	}
	pt, err := s.seg.DecryptDeterministically(raw, []byte(parent))
	if err != nil {
		return "", errors.New("key segment authentication failed")
	}
	pt, err = unpad(pt)
	if err != nil {
		return "", fmt.Errorf("key segment: %v", err)
	}
	return string(pt), nil
}

// encKey encrypts every "/"-separated segment, keeping the separators.
func (s *sealer) encKey(k string) string {
	segs := strings.Split(k, "/")
	out := make([]string, len(segs))
	for i, seg := range segs {
		if seg != "" {
			out[i] = s.encSegment(strings.Join(segs[:i], "/"), seg)
		}
	}
	return strings.Join(out, "/")
}

func (s *sealer) decKey(ek string) (string, error) {
	segs := strings.Split(ek, "/")
	plain := make([]string, len(segs))
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		pt, err := s.decSegment(strings.Join(plain[:i], "/"), seg)
		if err != nil {
			return "", err
		}
		plain[i] = pt
	}
	return strings.Join(plain, "/"), nil
}

// sealRecord encrypts a value together with its predecessor revision and
// lease. Layout inside the encryption: prev (8) | lease (8) | payload.
func (s *sealer) sealRecord(key string, prev, lease int64, payload []byte) []byte {
	rec := make([]byte, 16+len(payload))
	binary.BigEndian.PutUint64(rec[0:], uint64(prev))
	binary.BigEndian.PutUint64(rec[8:], uint64(lease))
	copy(rec[16:], payload)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	out := append([]byte{valueVersion}, nonce...)
	return s.val.Seal(out, nonce, pad(rec, minValueSize), []byte(key))
}

func (s *sealer) openRecord(key string, ev []byte) (payload []byte, prev, lease int64, err error) {
	if len(ev) < 1+12+16 || ev[0] != valueVersion {
		return nil, 0, 0, errors.New("value is not encrypted with a known format")
	}
	pt, err := s.val.Open(nil, ev[1:13], ev[13:], []byte(key))
	if err != nil {
		return nil, 0, 0, errors.New("value authentication failed")
	}
	if pt, err = unpad(pt); err != nil || len(pt) < 16 {
		return nil, 0, 0, errors.New("malformed value record")
	}
	return pt[16:], int64(binary.BigEndian.Uint64(pt[0:])), int64(binary.BigEndian.Uint64(pt[8:])), nil
}

// A delete receipt lists the deleted keys with the revision each one had.
// Layout: repeated prev (8) | key length (4) | key.
func buildReceipt(m map[string]int64) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b []byte
	for _, k := range keys {
		b = binary.BigEndian.AppendUint64(b, uint64(m[k]))
		b = binary.BigEndian.AppendUint32(b, uint32(len(k)))
		b = append(b, k...)
	}
	return b
}

func parseReceipt(b []byte) (map[string]int64, error) {
	m := map[string]int64{}
	for len(b) > 0 {
		if len(b) < 12 {
			return nil, errors.New("truncated")
		}
		prev, n := int64(binary.BigEndian.Uint64(b)), int(binary.BigEndian.Uint32(b[8:]))
		if len(b) < 12+n {
			return nil, errors.New("truncated")
		}
		m[string(b[12:12+n])] = prev
		b = b[12+n:]
	}
	return m, nil
}

// ---------------------------------------------------------------- key ranges

// prefixEnd mirrors clientv3.GetPrefixRangeEnd.
func prefixEnd(k string) string {
	b := []byte(k)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return "\x00"
}

// keyRange is a classified plaintext [key, end) range: a single key, the
// whole key space, or a prefix scan starting at the prefix itself or at a key
// inside it (pagination continues at lastKey + "\x00").
type keyRange struct {
	single bool
	all    bool
	prefix string
	start  string
}

func parseRange(key, end []byte) (keyRange, error) {
	k, e := string(key), string(end)
	if e == "" {
		return keyRange{single: true, start: k}, nil
	}
	if e == "\x00" && (k == "" || k == "\x00") {
		return keyRange{all: true}, nil
	}
	if last := e[len(e)-1]; last > 0 {
		prefix := e[:len(e)-1] + string([]byte{last - 1})
		if strings.HasPrefix(k, prefix) && !strings.HasSuffix(prefix, "\x00") {
			return keyRange{prefix: prefix, start: k}, nil
		}
	}
	return keyRange{}, status.Errorf(codes.InvalidArgument, "veil: unsupported key range [%q, %q)", k, e)
}

// ---------------------------------------------------------------- freshness and checkpoints

// freshness tracks the highest backend revision seen (the floor) and persists
// verified checkpoints. The other instances learn them from checkpoint records
// (see checkpointLoop).
//
// Rule: a request sent after revision R was seen must be answered with a
// revision >= R. Comparing against the floor taken *before* the request avoids
// false alarms when responses overtake each other.
type freshness struct {
	hwm  atomic.Int64
	file string
	rep  *replica

	mu     sync.Mutex
	last   checkpoint // last persisted own checkpoint
	anchor checkpoint // digest at the last compaction revision we forwarded
	saved  string
}

func newFreshness(file string, rep *replica) *freshness {
	return &freshness{file: file, rep: rep}
}

func (f *freshness) floor() int64 { return f.hwm.Load() }

func (f *freshness) observe(rev int64) {
	for {
		cur := f.hwm.Load()
		if rev <= cur || f.hwm.CompareAndSwap(cur, rev) {
			return
		}
	}
}

func (f *freshness) check(before int64, h *pb.ResponseHeader) error {
	if h == nil {
		return nil
	}
	if h.Revision < before {
		log.Printf("ROLLBACK DETECTED: backend answered with revision %d after revision %d was already seen", h.Revision, before)
		return dataLoss("backend went back in time (revision %d, already seen %d)", h.Revision, before)
	}
	f.observe(h.Revision)
	return nil
}

func formatCheckpoint(c checkpoint) string { return fmt.Sprintf("%d %x", c.rev, c.digest) }

func parseCheckpoint(s string) (checkpoint, error) {
	var c checkpoint
	var d string
	if _, err := fmt.Sscanf(s, "%d %s", &c.rev, &d); err != nil {
		return c, err
	}
	raw, err := hex.DecodeString(d)
	if err != nil || len(raw) != 32 {
		return c, errors.New("bad digest")
	}
	copy(c.digest[:], raw)
	return c, nil
}

// loadFile reads "latest <rev> <digest>" and "anchor <rev> <digest>".
func (f *freshness) loadFile() (latest, anchor checkpoint, exists bool, err error) {
	b, err := os.ReadFile(f.file)
	if os.IsNotExist(err) {
		return latest, anchor, false, nil
	}
	if err != nil {
		return latest, anchor, false, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, rest, _ := strings.Cut(line, " ")
		c, err := parseCheckpoint(rest)
		if err != nil {
			return latest, anchor, true, fmt.Errorf("state file %s: %v", f.file, err)
		}
		switch name {
		case "latest":
			latest = c
		case "anchor":
			anchor = c
		}
	}
	f.mu.Lock()
	f.last, f.anchor = latest, anchor
	f.mu.Unlock()
	return latest, anchor, true, nil
}

func (f *freshness) setAnchor(c checkpoint) {
	f.mu.Lock()
	f.anchor = c
	f.mu.Unlock()
}

// current: the state file's content for the replica's current checkpoint.
func (f *freshness) current() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp, ok := f.rep.checkpoint()
	if !ok {
		return "", false
	}
	return "latest " + formatCheckpoint(cp) + "\nanchor " + formatCheckpoint(f.anchor) + "\n", true
}

func (f *freshness) persist() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cp, ok := f.rep.checkpoint(); ok {
		f.last = cp
	}
	content := "latest " + formatCheckpoint(f.last) + "\nanchor " + formatCheckpoint(f.anchor) + "\n"
	if content == f.saved || f.last.rev == 0 {
		return
	}
	tmp := f.file + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		log.Printf("persist checkpoint: %v", err)
		return
	}
	if err := os.Rename(tmp, f.file); err != nil {
		log.Printf("persist checkpoint: %v", err)
		return
	}
	f.saved = content
}

// ---------------------------------------------------------------- checkpoint records
//
// Every instance writes its latest verified checkpoint to /veil/checkpoint/<node> once a
// minute: "<revision> <digest> <unix time>", encrypted and bound to the key like every value,
// so only holders of the master key can write one. The records travel through the backend
// like all data; no instance accepts connections from the others, so they can sit behind NAT.
//
//   - A record of another instance that names a revision this instance has verified with a
//     different digest proves that the backend shows different histories (fork). The replica
//     checks this for every record it applies (replica.claim).
//   - A backend that forks and hides the other instances' records instead makes them fall
//     silent: an instance whose record is older than five minutes is logged and counted in
//     veil_peers_silent.
//   - After a long downtime, a record newer than the instance's own checkpoint proves that the
//     backend state is not rolled back (verifyAndLoad).

const (
	checkpointPrefix = "/veil/checkpoint/"
)

const (
	defaultCheckpointEvery = time.Minute
	defaultSilentAfter     = 5 * time.Minute
)

func formatRecord(c checkpoint, at time.Time) []byte {
	return []byte(fmt.Sprintf("%d %x %d", c.rev, c.digest, at.Unix()))
}

func parseRecord(b []byte) (checkpoint, time.Time, error) {
	f := strings.Fields(string(b))
	if len(f) != 3 {
		return checkpoint{}, time.Time{}, errors.New("malformed checkpoint record")
	}
	c, err := parseCheckpoint(f[0] + " " + f[1])
	if err != nil {
		return checkpoint{}, time.Time{}, err
	}
	sec, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return checkpoint{}, time.Time{}, err
	}
	return c, time.Unix(sec, 0), nil
}

// checkpointLoop persists the checkpoint every second, writes the checkpoint record every
// minute and reports instances that fell silent.
func (p *proxy) checkpointLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastWrite time.Time
	silent := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			p.fresh.persist()
			if now.Sub(lastWrite) >= p.checkpointEvery && p.rep.err() == nil {
				if err := p.writeCheckpoint(ctx); err != nil {
					log.Printf("checkpoint record: %v", status.Convert(err).Message())
				} else {
					lastWrite = now
				}
			}
			for node, age := range p.rep.peerAges(now) {
				if quiet := age > p.silentAfter; quiet != silent[node] {
					silent[node] = quiet
					if quiet {
						log.Printf("WARNING: instance %q wrote no checkpoint record for %v: it is down, or the backend hides its writes (fork)", node, age.Round(time.Second))
					} else {
						log.Printf("instance %q writes checkpoint records again", node)
					}
				}
			}
		}
	}
}

// writeCheckpoint stores this instance's latest verified checkpoint as its record.
func (p *proxy) writeCheckpoint(ctx context.Context) error {
	cp, ok := p.rep.checkpoint()
	if !ok {
		return nil
	}
	_, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestPut{RequestPut: &pb.PutRequest{
		Key: []byte(checkpointPrefix + p.node), Value: formatRecord(cp, time.Now())}}}}}, true)
	return err
}

// removeCheckpoint deletes this instance's record when it leaves the cluster, so the others
// do not wait for it.
func (p *proxy) removeCheckpoint(ctx context.Context) error {
	_, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestDeleteRange{
		RequestDeleteRange: &pb.DeleteRangeRequest{Key: []byte(checkpointPrefix + p.node)}}}}}, true)
	return err
}

// ---------------------------------------------------------------- gRPC services

type proxy struct {
	// etcd's generated servers must be embedded (forward compatibility): a method etcd adds
	// later answers Unimplemented until the proxy implements it
	pb.UnimplementedKVServer
	pb.UnimplementedWatchServer
	pb.UnimplementedLeaseServer

	s       *sealer
	kv      pb.KVClient
	watch   pb.WatchClient
	lease   pb.LeaseClient
	maint   pb.MaintenanceClient
	rep     *replica
	fresh   *freshness
	verbose bool
	addr    string
	self    string
	node    string // this instance's name in checkpoint records
	opsAddr string

	checkpointEvery, silentAfter time.Duration

	metrics  *metrics
	srv      *grpc.Server
	serving  atomic.Bool
	closers  []func() error
	stopOnce sync.Once
}

func (p *proxy) logf(format string, args ...any) {
	if p.verbose {
		log.Printf(format, args...)
	}
}

type withHeader interface{ GetHeader() *pb.ResponseHeader }

// forward runs one backend call and enforces the freshness rule on its answer.
func forward[R withHeader](p *proxy, call func() (R, error)) (R, error) {
	var zero R
	if err := p.rep.err(); err != nil {
		return zero, err
	}
	before := p.fresh.floor()
	resp, err := call()
	if err != nil {
		return zero, err
	}
	if err := p.fresh.check(before, resp.GetHeader()); err != nil {
		return zero, err
	}
	return resp, nil
}

// readIndex makes a read linearizable: ask the backend for its current
// revision (a cheap count on a key that never exists) and wait until the
// verified replica has caught up to it.
func (p *proxy) readIndex(ctx context.Context) error {
	resp, err := forward(p, func() (*pb.RangeResponse, error) {
		return p.kv.Range(ctx, &pb.RangeRequest{Key: []byte(p.s.encKey(readIndexKey)), CountOnly: true})
	})
	if err != nil {
		return err
	}
	return p.rep.waitFor(ctx, resp.Header.Revision)
}

// KV: reads come from the replica, writes go through txn().

// rangeChunk: how many keys a RangeStream response carries at most.
const rangeChunk = 500

// RangeStream (etcd 3.7) answers like Range, in chunks: the keys in order, header, more and count
// in the last chunk, so that merging all chunks gives Range's answer.
func (p *proxy) RangeStream(r *pb.RangeRequest, out grpc.ServerStreamingServer[pb.RangeStreamResponse]) error {
	resp, err := p.Range(out.Context(), r)
	if err != nil {
		return err
	}
	kvs := resp.Kvs
	for len(kvs) > rangeChunk {
		if err := out.Send(&pb.RangeStreamResponse{RangeResponse: &pb.RangeResponse{Kvs: kvs[:rangeChunk]}}); err != nil {
			return err
		}
		kvs = kvs[rangeChunk:]
	}
	resp.Kvs = kvs
	return out.Send(&pb.RangeStreamResponse{RangeResponse: resp})
}

func (p *proxy) Range(ctx context.Context, r *pb.RangeRequest) (*pb.RangeResponse, error) {
	p.logf("Range %q %q limit=%d rev=%d count=%v", r.Key, r.RangeEnd, r.Limit, r.Revision, r.CountOnly)
	kr, err := parseRange(r.Key, r.RangeEnd)
	if err != nil {
		return nil, err
	}
	switch {
	case r.Revision > 0:
		err = p.rep.waitFor(ctx, r.Revision)
	case !r.Serializable:
		err = p.readIndex(ctx)
	}
	if err != nil {
		return nil, err
	}
	return p.rep.serveRange(r, kr, r.Revision)
}

func (p *proxy) Put(ctx context.Context, r *pb.PutRequest) (*pb.PutResponse, error) {
	p.logf("Put %q (%d bytes)", r.Key, len(r.Value))
	resp, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestPut{RequestPut: r}}}}, false)
	if err != nil {
		return nil, err
	}
	return resp.Responses[0].GetResponsePut(), nil
}

func (p *proxy) DeleteRange(ctx context.Context, r *pb.DeleteRangeRequest) (*pb.DeleteRangeResponse, error) {
	p.logf("DeleteRange %q %q", r.Key, r.RangeEnd)
	resp, err := p.txn(ctx, &pb.TxnRequest{Success: []*pb.RequestOp{{Request: &pb.RequestOp_RequestDeleteRange{RequestDeleteRange: r}}}}, false)
	if err != nil {
		return nil, err
	}
	return resp.Responses[0].GetResponseDeleteRange(), nil
}

func (p *proxy) Txn(ctx context.Context, r *pb.TxnRequest) (*pb.TxnResponse, error) {
	if p.verbose {
		var keys []string
		for _, c := range r.Compare {
			keys = append(keys, string(c.Key))
		}
		p.logf("Txn compare=%q", keys)
	}
	return p.txn(ctx, r, false)
}

// write is one key changed by a transaction's success branch.
type write struct {
	key string
	put *pb.PutRequest // nil for a delete
}

func unsupported(what string) error {
	return status.Errorf(codes.Unimplemented, "veil: %s are not supported", what)
}

// txn executes every write. It pins each written key to the revision it
// replaces (so the value can name its predecessor), adds a delete receipt,
// and then checks the backend's verdict and effects against the replica.
// All results sent back to the client come from the replica.
func (p *proxy) txn(ctx context.Context, r *pb.TxnRequest, internal bool) (*pb.TxnResponse, error) {
	for _, c := range r.Compare {
		if len(c.RangeEnd) > 0 {
			return nil, unsupported("range compares")
		}
		if c.Target == pb.Compare_VALUE {
			return nil, unsupported("value compares")
		}
	}
	var writes []write
	for _, op := range r.Success {
		switch o := op.Request.(type) {
		case *pb.RequestOp_RequestPut:
			if o.RequestPut.IgnoreValue || o.RequestPut.IgnoreLease {
				return nil, unsupported("ignore_value/ignore_lease puts")
			}
			writes = append(writes, write{key: string(o.RequestPut.Key), put: o.RequestPut})
		case *pb.RequestOp_RequestDeleteRange:
			if len(o.RequestDeleteRange.RangeEnd) > 0 {
				return nil, unsupported("range deletes")
			}
			writes = append(writes, write{key: string(o.RequestDeleteRange.Key)})
		case *pb.RequestOp_RequestTxn:
			return nil, unsupported("nested transactions")
		}
	}
	for _, op := range r.Failure {
		if _, ok := op.Request.(*pb.RequestOp_RequestRange); !ok {
			return nil, unsupported("writes in the failure branch")
		}
	}
	for _, w := range writes {
		if strings.HasPrefix(w.key, "/veil/") && !internal {
			return nil, status.Error(codes.PermissionDenied, "veil: /veil/ is reserved")
		}
	}

	for attempt := 0; attempt < 50; attempt++ {
		pins := map[string]int64{}
		for _, c := range r.Compare {
			if c.Target == pb.Compare_MOD && c.Result == pb.Compare_EQUAL {
				pins[string(c.Key)] = c.GetModRevision()
			}
		}
		added := map[string]int64{}
		for _, w := range writes {
			if _, ok := pins[w.key]; !ok {
				v, _ := p.rep.latest(w.key)
				pins[w.key], added[w.key] = v.modRev, v.modRev
			}
		}

		enc := &pb.TxnRequest{}
		encCompare := func(c *pb.Compare) {
			c = proto.Clone(c).(*pb.Compare) // the caller's request stays as it was
			c.Key = []byte(p.s.encKey(string(c.Key)))
			enc.Compare = append(enc.Compare, c)
		}
		for _, c := range r.Compare {
			encCompare(c)
		}
		for k, m := range added {
			encCompare(&pb.Compare{Key: []byte(k), Target: pb.Compare_MOD, Result: pb.Compare_EQUAL,
				TargetUnion: &pb.Compare_ModRevision{ModRevision: m}})
		}
		receipt := map[string]int64{}
		for _, w := range writes {
			ek := []byte(p.s.encKey(w.key))
			if w.put != nil {
				enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestPut{RequestPut: &pb.PutRequest{
					Key: ek, Value: p.s.sealRecord(w.key, pins[w.key], w.put.Lease, w.put.Value), Lease: w.put.Lease}}})
			} else {
				enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestDeleteRange{
					RequestDeleteRange: &pb.DeleteRangeRequest{Key: ek}}})
				if pins[w.key] != 0 {
					receipt[w.key] = pins[w.key]
				}
			}
		}
		if len(receipt) > 0 {
			enc.Success = append(enc.Success, &pb.RequestOp{Request: &pb.RequestOp_RequestPut{RequestPut: &pb.PutRequest{
				Key: []byte(p.s.encKey(receiptKey)), Value: p.s.sealRecord(receiptKey, 0, 0, buildReceipt(receipt))}}})
		}

		resp, err := forward(p, func() (*pb.TxnResponse, error) { return p.kv.Txn(ctx, enc) })
		if err != nil {
			return nil, err
		}
		if err := p.rep.waitFor(ctx, resp.Header.Revision); err != nil {
			return nil, err
		}
		out, retry, err := p.rep.checkTxn(r, writes, added, resp)
		if err != nil {
			p.rep.fail(err)
			return nil, err
		}
		if !retry {
			return out, nil
		}
	}
	return nil, status.Error(codes.Unavailable, "veil: too much write contention")
}

func evalCompare(c *pb.Compare, v version) bool {
	var val, want int64
	switch c.Target {
	case pb.Compare_VERSION:
		val, want = v.ver, c.GetVersion()
	case pb.Compare_CREATE:
		val, want = v.createRev, c.GetCreateRevision()
	case pb.Compare_MOD:
		val, want = v.modRev, c.GetModRevision()
	case pb.Compare_LEASE:
		val, want = v.lease, c.GetLease()
	default:
		return false
	}
	switch c.Result {
	case pb.Compare_EQUAL:
		return val == want
	case pb.Compare_GREATER:
		return val > want
	case pb.Compare_LESS:
		return val < want
	case pb.Compare_NOT_EQUAL:
		return val != want
	}
	return false
}

// checkTxn verifies the backend's answer to a transaction against the
// replica (which has already applied revision H = resp.Header.Revision):
//   - success: the conditions held before H, and every write is in H
//   - failure: the conditions really did not hold at H
//
// A failure caused only by pins the proxy added (its replica was behind)
// asks for a retry. The response is built from the replica.
func (r *replica) checkTxn(req *pb.TxnRequest, writes []write, added map[string]int64, resp *pb.TxnResponse) (*pb.TxnResponse, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	H := resp.Header.Revision
	bumped := false
	if resp.Succeeded && len(writes) > 0 {
		i := sort.Search(len(r.hist), func(i int) bool { return r.hist[i].rev >= H })
		if i < len(r.hist) && r.hist[i].rev == H {
			for _, c := range r.hist[i].changes {
				for _, w := range writes {
					bumped = bumped || c.key == w.key
				}
			}
		}
	}
	at := H
	if bumped {
		at = H - 1
	}
	if at < r.base {
		return nil, false, dataLoss("transaction at revision %d is outside the verified history", H)
	}
	holds := func(c *pb.Compare) bool {
		v, _ := r.atLocked(string(c.Key), at)
		return evalCompare(c, v)
	}
	origOK := true
	for _, c := range req.Compare {
		origOK = origOK && holds(c)
	}
	addedOK := true
	for k, m := range added {
		addedOK = addedOK && holds(&pb.Compare{Key: []byte(k), Target: pb.Compare_MOD, Result: pb.Compare_EQUAL,
			TargetUnion: &pb.Compare_ModRevision{ModRevision: m}})
	}

	if resp.Succeeded {
		if !origOK || !addedOK {
			return nil, false, dataLoss("backend executed a transaction whose condition was false at revision %d", at)
		}
		for _, w := range writes {
			v, ok := r.atLocked(w.key, H)
			before, existed := r.atLocked(w.key, at)
			switch {
			case w.put != nil && (!bumped || !ok || v.modRev != H || v.lease != w.put.Lease || !bytes.Equal(v.value, w.put.Value)):
				return nil, false, dataLoss("backend acknowledged a write to %q that is not in its history at revision %d", w.key, H)
			case w.put == nil && existed && ok:
				return nil, false, dataLoss("backend acknowledged a delete of %q (revision %d) that is not in its history", w.key, before.modRev)
			}
		}
	} else {
		if origOK && addedOK {
			return nil, false, dataLoss("backend rejected a transaction whose condition held at revision %d", at)
		}
		if origOK {
			return nil, true, nil // only our own pins failed: the replica was behind
		}
	}

	out := &pb.TxnResponse{Header: resp.Header, Succeeded: resp.Succeeded}
	ops := req.Failure
	if resp.Succeeded {
		ops = req.Success
	}
	for _, op := range ops {
		switch o := op.Request.(type) {
		case *pb.RequestOp_RequestRange:
			kr, err := parseRange(o.RequestRange.Key, o.RequestRange.RangeEnd)
			if err != nil {
				return nil, false, err
			}
			rr, err := r.serveRangeLocked(o.RequestRange, kr, H)
			if err != nil {
				return nil, false, err
			}
			rr.Header = resp.Header
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponseRange{ResponseRange: rr}})
		case *pb.RequestOp_RequestPut:
			pr := &pb.PutResponse{Header: resp.Header}
			if v, ok := r.atLocked(string(o.RequestPut.Key), at); ok && o.RequestPut.PrevKv {
				pr.PrevKv = v.kv(string(o.RequestPut.Key), false)
			}
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponsePut{ResponsePut: pr}})
		case *pb.RequestOp_RequestDeleteRange:
			dr := &pb.DeleteRangeResponse{Header: resp.Header}
			if v, ok := r.atLocked(string(o.RequestDeleteRange.Key), at); ok {
				dr.Deleted = 1
				if o.RequestDeleteRange.PrevKv {
					dr.PrevKvs = append(dr.PrevKvs, v.kv(string(o.RequestDeleteRange.Key), false))
				}
			}
			out.Responses = append(out.Responses, &pb.ResponseOp{Response: &pb.ResponseOp_ResponseDeleteRange{ResponseDeleteRange: dr}})
		}
	}
	return out, false, nil
}

// Compact first records the verified digest at the compaction revision as
// anchor, so a restart after a long outage can still verify the backend.
func (p *proxy) Compact(ctx context.Context, r *pb.CompactionRequest) (*pb.CompactionResponse, error) {
	p.logf("Compact rev=%d", r.Revision)
	d, ok := p.rep.digestAt(r.Revision)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "veil: will not compact to revision %d, it is outside this instance's verified history", r.Revision)
	}
	p.fresh.setAnchor(checkpoint{rev: r.Revision, digest: d})
	p.fresh.persist()
	return forward(p, func() (*pb.CompactionResponse, error) { return p.kv.Compact(ctx, r) })
}

// upstreamCtx forwards the etcd client's "hasleader" requirement.
func upstreamCtx(ctx context.Context) context.Context {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("hasleader"); len(v) > 0 {
			return metadata.AppendToOutgoingContext(ctx, "hasleader", v[0])
		}
	}
	return ctx
}

// Lease: no keys or values involved, except in TimeToLive.

func (p *proxy) LeaseGrant(ctx context.Context, r *pb.LeaseGrantRequest) (*pb.LeaseGrantResponse, error) {
	return forward(p, func() (*pb.LeaseGrantResponse, error) { return p.lease.LeaseGrant(ctx, r) })
}

func (p *proxy) LeaseRevoke(ctx context.Context, r *pb.LeaseRevokeRequest) (*pb.LeaseRevokeResponse, error) {
	return forward(p, func() (*pb.LeaseRevokeResponse, error) { return p.lease.LeaseRevoke(ctx, r) })
}

func (p *proxy) LeaseTimeToLive(ctx context.Context, r *pb.LeaseTimeToLiveRequest) (*pb.LeaseTimeToLiveResponse, error) {
	resp, err := forward(p, func() (*pb.LeaseTimeToLiveResponse, error) { return p.lease.LeaseTimeToLive(ctx, r) })
	if err != nil {
		return nil, err
	}
	for i, k := range resp.Keys {
		pk, err := p.s.decKey(string(k))
		if err != nil {
			return nil, dataLoss("lease key: %v", err)
		}
		resp.Keys[i] = []byte(pk)
	}
	return resp, nil
}

func (p *proxy) LeaseLeases(ctx context.Context, r *pb.LeaseLeasesRequest) (*pb.LeaseLeasesResponse, error) {
	return forward(p, func() (*pb.LeaseLeasesResponse, error) { return p.lease.LeaseLeases(ctx, r) })
}

func (p *proxy) LeaseKeepAlive(srv pb.Lease_LeaseKeepAliveServer) error {
	ctx, cancel := context.WithCancel(upstreamCtx(srv.Context()))
	defer cancel()
	up, err := p.lease.LeaseKeepAlive(ctx)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	floor := p.fresh.floor()
	go func() {
		for {
			req, err := srv.Recv()
			if err == io.EOF {
				up.CloseSend()
				return
			}
			if err != nil {
				errc <- err
				return
			}
			if err := up.Send(req); err != nil {
				errc <- err
				return
			}
		}
	}()
	go func() {
		for {
			resp, err := up.Recv()
			if err != nil {
				errc <- err
				return
			}
			if err := p.fresh.check(floor, resp.Header); err != nil {
				errc <- err
				return
			}
			floor = max(floor, resp.Header.GetRevision())
			if err := srv.Send(resp); err != nil {
				errc <- err
				return
			}
		}
	}()
	err = <-errc
	if err == io.EOF || status.Code(err) == codes.Canceled {
		return nil
	}
	return err
}

// Maintenance: only Status is needed by kube-apiserver and k3s.

type maintenance struct {
	*proxy
	pb.UnimplementedMaintenanceServer
}

func (m maintenance) Status(ctx context.Context, r *pb.StatusRequest) (*pb.StatusResponse, error) {
	return forward(m.proxy, func() (*pb.StatusResponse, error) { return m.maint.Status(ctx, r) })
}

func (m maintenance) Alarm(ctx context.Context, r *pb.AlarmRequest) (*pb.AlarmResponse, error) {
	return forward(m.proxy, func() (*pb.AlarmResponse, error) { return m.maint.Alarm(ctx, r) })
}

func (maintenance) Defragment(context.Context, *pb.DefragmentRequest) (*pb.DefragmentResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: defragmentation is done by the backend operator")
}

func (maintenance) Hash(context.Context, *pb.HashRequest) (*pb.HashResponse, error) {
	return nil, status.Error(codes.Unimplemented, "veil: not supported")
}

func (maintenance) HashKV(context.Context, *pb.HashKVRequest) (*pb.HashKVResponse, error) {
	return nil, status.Error(codes.Unimplemented, "veil: not supported")
}

func (maintenance) Snapshot(*pb.SnapshotRequest, pb.Maintenance_SnapshotServer) error {
	return status.Error(codes.Unimplemented, "veil: snapshots are taken by the backend operator (ciphertext only)")
}

func (maintenance) MoveLeader(context.Context, *pb.MoveLeaderRequest) (*pb.MoveLeaderResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: not supported")
}

func (maintenance) Downgrade(context.Context, *pb.DowngradeRequest) (*pb.DowngradeResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: not supported")
}

// Cluster: present the proxy as the only member, so clients never bypass it.

type cluster struct {
	*proxy
	pb.UnimplementedClusterServer
}

func (c cluster) MemberList(ctx context.Context, r *pb.MemberListRequest) (*pb.MemberListResponse, error) {
	st, err := forward(c.proxy, func() (*pb.StatusResponse, error) { return c.maint.Status(ctx, &pb.StatusRequest{}) })
	if err != nil {
		return nil, err
	}
	return &pb.MemberListResponse{
		Header:  st.Header,
		Members: []*pb.Member{{ID: st.Header.MemberId, Name: "veil-proxy", ClientURLs: []string{c.self}}},
	}, nil
}

func (cluster) MemberAdd(context.Context, *pb.MemberAddRequest) (*pb.MemberAddResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberRemove(context.Context, *pb.MemberRemoveRequest) (*pb.MemberRemoveResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberUpdate(context.Context, *pb.MemberUpdateRequest) (*pb.MemberUpdateResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}

func (cluster) MemberPromote(context.Context, *pb.MemberPromoteRequest) (*pb.MemberPromoteResponse, error) {
	return nil, status.Error(codes.PermissionDenied, "veil: membership is managed by the backend operator")
}
