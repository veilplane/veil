// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func testSealer(t *testing.T, b byte) *sealer {
	t.Helper()
	s, err := newSealer(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------- crypto

func TestPadme(t *testing.T) {
	// Values from the Padmé paper / reference implementation.
	cases := map[int]int{1: 1, 2: 2, 9: 10, 10: 10, 33: 36, 100: 104, 1000: 1024, 1025: 1088, 100000: 100352}
	for in, want := range cases {
		if got := padme(in); got != want {
			t.Errorf("padme(%d) = %d, want %d", in, got, want)
		}
	}
	for l := 2; l < 200000; l += 37 {
		if p := padme(l); p < l || float64(p) > float64(l)*1.13 {
			t.Fatalf("padme(%d) = %d out of bounds", l, p)
		}
	}
}

func TestPadRoundTrip(t *testing.T) {
	for _, in := range []string{"", "a", strings.Repeat("x", 31), strings.Repeat("y", 32), "ends with 0x80 \x80", "zeros\x00\x00"} {
		out, err := unpad(pad([]byte(in), 32))
		if err != nil || string(out) != in {
			t.Fatalf("round trip %q: got %q, %v", in, out, err)
		}
	}
	if _, err := unpad([]byte{1, 2, 3}); err == nil {
		t.Fatal("unpad must reject data without marker")
	}
}

func TestKeyRoundTripAndDeterminism(t *testing.T) {
	s := testSealer(t, 1)
	for _, k := range []string{"/registry/pods/default/nginx", "/registry/", "compact_rev_key", "/bootstrap/abc", "/a//b/"} {
		e := s.encKey(k)
		if e != s.encKey(k) || strings.Count(e, "/") != strings.Count(k, "/") {
			t.Fatalf("not deterministic or structure changed for %q", k)
		}
		if d, err := s.decKey(e); err != nil || d != k {
			t.Fatalf("round trip %q: got %q, %v", k, d, err)
		}
	}
	if testSealer(t, 1).encKey("/registry/pods/x") != s.encKey("/registry/pods/x") {
		t.Fatal("instances with the same key disagree")
	}
	if testSealer(t, 2).encKey("/registry/pods/x") == s.encKey("/registry/pods/x") {
		t.Fatal("different keys produce the same ciphertext")
	}
}

func TestPrefixAndLinkability(t *testing.T) {
	s := testSealer(t, 1)
	prefix := s.encKey("/registry/pods/default/")
	if !strings.HasPrefix(s.encKey("/registry/pods/default/nginx"), prefix) {
		t.Fatal("encrypted key does not start with encrypted prefix")
	}
	a := strings.Split(s.encKey("/registry/configmaps/team-a/config"), "/")
	b := strings.Split(s.encKey("/registry/configmaps/team-b/config"), "/")
	if a[4] == b[4] {
		t.Fatal("same object name in different namespaces must not be linkable")
	}
}

func TestLengthsHidden(t *testing.T) {
	s := testSealer(t, 1)
	if len(s.encSegment("/registry", "a")) != len(s.encSegment("/registry", strings.Repeat("b", 31))) {
		t.Fatal("segment lengths 1 and 31 distinguishable")
	}
	if len(s.sealRecord("/k", 1, 0, []byte("x"))) != len(s.sealRecord("/k", 1, 0, bytes.Repeat([]byte("y"), 100))) {
		t.Fatal("small values distinguishable by length")
	}
}

func TestTamperingDetected(t *testing.T) {
	s := testSealer(t, 1)
	enc := s.encKey("/registry/secrets/prod/db")
	segs := strings.Split(enc, "/")
	raw, _ := base64.RawURLEncoding.DecodeString(segs[4])
	raw[len(raw)-1] ^= 1
	segs[4] = base64.RawURLEncoding.EncodeToString(raw)
	if _, err := s.decKey(strings.Join(segs, "/")); err == nil {
		t.Fatal("flipped bit in key segment not detected")
	}
	other := strings.Split(s.encKey("/registry/secrets/dev/db"), "/")
	moved := append(append([]string{}, other[:4]...), strings.Split(enc, "/")[4])
	if _, err := s.decKey(strings.Join(moved, "/")); err == nil {
		t.Fatal("segment moved to another namespace not detected")
	}
	v := s.sealRecord("/registry/secrets/prod/db", 7, 0, []byte("password"))
	if _, _, _, err := s.openRecord("/registry/secrets/dev/db", v); err == nil {
		t.Fatal("value swapped between keys not detected")
	}
	if got, prev, _, err := s.openRecord("/registry/secrets/prod/db", v); err != nil || string(got) != "password" || prev != 7 {
		t.Fatalf("record round trip: %q %d %v", got, prev, err)
	}
}

func TestReceiptRoundTrip(t *testing.T) {
	in := map[string]int64{"/a": 3, "/registry/pods/x/y": 99}
	out, err := parseReceipt(buildReceipt(in))
	if err != nil || len(out) != 2 || out["/a"] != 3 || out["/registry/pods/x/y"] != 99 {
		t.Fatalf("receipt round trip: %v %v", out, err)
	}
}

// ---------------------------------------------------------------- replica rules

func emptyReplica(t *testing.T, s *sealer) *replica {
	r := newReplica(s, time.Hour)
	r.loaded, r.rev, r.base = true, 1, 1
	return r
}

func put(s *sealer, key string, rev, prev, create, ver, lease int64, val string) *mvccpb.Event {
	return &mvccpb.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: []byte(s.encKey(key)),
		Value: s.sealRecord(key, prev, lease, []byte(val)), ModRevision: rev, CreateRevision: create, Version: ver, Lease: lease}}
}

func del(s *sealer, key string, rev int64) *mvccpb.Event {
	return &mvccpb.Event{Type: mvccpb.DELETE, Kv: &mvccpb.KeyValue{Key: []byte(s.encKey(key)), ModRevision: rev}}
}

func receipt(s *sealer, rev int64, m map[string]int64) *mvccpb.Event {
	return &mvccpb.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: []byte(s.encKey(receiptKey)),
		Value: s.sealRecord(receiptKey, 0, 0, buildReceipt(m)), ModRevision: rev, CreateRevision: rev, Version: 1}}
}

func mustApply(t *testing.T, r *replica, rev int64, evs ...*mvccpb.Event) {
	t.Helper()
	if err := r.apply(rev, evs); err != nil {
		t.Fatalf("revision %d: %v", rev, err)
	}
}

func mustReject(t *testing.T, r *replica, rev int64, want string, evs ...*mvccpb.Event) {
	t.Helper()
	err := r.apply(rev, evs)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("revision %d: want error containing %q, got %v", rev, want, err)
	}
}

func read(t *testing.T, r *replica, key string, at int64) (string, bool) {
	t.Helper()
	resp, err := r.serveRange(&pb.RangeRequest{}, keyRange{single: true, start: key}, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Kvs) == 0 {
		return "", false
	}
	return string(resp.Kvs[0].Value), true
}

func TestReplicaAppliesValidHistory(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustApply(t, r, 2, put(s, "/a", 2, 0, 2, 1, 0, "v1"))
	mustApply(t, r, 3, put(s, "/a", 3, 2, 2, 2, 0, "v2"), put(s, "/b", 3, 0, 3, 1, 0, "b"))
	mustApply(t, r, 4, del(s, "/a", 4), receipt(s, 4, map[string]int64{"/a": 3}))
	mustApply(t, r, 5, put(s, "/a", 5, 0, 5, 1, 0, "new"))
	for at, want := range map[int64]string{2: "v1", 3: "v2", 4: "", 5: "new"} {
		if got, _ := read(t, r, "/a", at); got != want {
			t.Errorf("/a at %d = %q, want %q", at, got, want)
		}
	}
}

func TestReplicaRejectsReplayedValue(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	old := put(s, "/registry/clusterrolebindings/admin", 2, 0, 2, 1, 0, "alice is admin")
	mustApply(t, r, 2, old)
	mustApply(t, r, 3, put(s, "/registry/clusterrolebindings/admin", 3, 2, 2, 2, 0, "nobody is admin"))
	// The backend re-plays the old, validly encrypted value as a new write.
	replay := &mvccpb.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{Key: old.Kv.Key, Value: old.Kv.Value, ModRevision: 4, CreateRevision: 2, Version: 3}}
	mustReject(t, r, 4, "replayed", replay)
}

func TestReplicaRejectsForgedDelete(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustApply(t, r, 2, put(s, "/registry/networkpolicies/prod/deny-all", 2, 0, 2, 1, 0, "deny"))
	mustReject(t, r, 3, "forged delete", del(s, "/registry/networkpolicies/prod/deny-all", 3))
}

func TestReplicaRejectsReceiptForOtherVersion(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustApply(t, r, 2, put(s, "/a", 2, 0, 2, 1, 0, "v1"))
	mustApply(t, r, 3, del(s, "/a", 3), receipt(s, 3, map[string]int64{"/a": 2}))
	mustApply(t, r, 4, put(s, "/a", 4, 0, 4, 1, 0, "again"))
	// An old receipt (for revision 2) replayed together with a delete.
	mustReject(t, r, 5, "forged delete", del(s, "/a", 5), receipt(s, 5, map[string]int64{"/a": 2}))
}

func TestReplicaAllowsLeaseExpiry(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustApply(t, r, 2, put(s, "/registry/events/default/e1", 2, 0, 2, 1, 42, "event"))
	mustApply(t, r, 3, del(s, "/registry/events/default/e1", 3))
}

func TestReplicaRejectsGapsAndForgedMetadata(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustReject(t, r, 3, "gap", put(s, "/a", 3, 0, 3, 1, 0, "x"))
	mustReject(t, r, 2, "metadata", put(s, "/a", 2, 0, 2, 5, 0, "x"))                     // wrong version
	mustReject(t, r, 2, "metadata", &mvccpb.Event{Type: mvccpb.PUT, Kv: &mvccpb.KeyValue{ // lease swapped
		Key: []byte(s.encKey("/a")), Value: s.sealRecord("/a", 0, 0, []byte("x")), ModRevision: 2, CreateRevision: 2, Version: 1, Lease: 9}})
	mustReject(t, r, 2, "without matching delete", receipt(s, 2, map[string]int64{"/zzz": 1}))
}

// The digest must equal a fresh computation over the current state, so a
// snapshot load reproduces exactly what incremental updates produced.
func TestDigestIncrementalEqualsFull(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	mustApply(t, r, 2, put(s, "/a", 2, 0, 2, 1, 0, "1"), put(s, "/b", 2, 0, 2, 1, 0, "2"))
	mustApply(t, r, 3, put(s, "/a", 3, 2, 2, 2, 0, "3"))
	mustApply(t, r, 4, del(s, "/b", 4), receipt(s, 4, map[string]int64{"/b": 2}))
	full := new(big.Int)
	for k := range r.keys {
		if v, ok := r.latestLocked(k); ok {
			full.Add(full, r.entryHash(k, v))
		}
	}
	full.Mod(full, mod256)
	if full.Cmp(r.digest) != 0 {
		t.Fatal("incremental digest differs from full recomputation")
	}
}

func TestForkDetectedByClaim(t *testing.T) {
	s := testSealer(t, 1)
	a, b := emptyReplica(t, s), emptyReplica(t, s)
	mustApply(t, a, 2, put(s, "/x", 2, 0, 2, 1, 0, "seen by a"))
	mustApply(t, b, 2, put(s, "/y", 2, 0, 2, 1, 0, "seen by b"))
	cp, _ := a.checkpoint()
	b.claim(cp)
	time.Sleep(50 * time.Millisecond)
	if b.err() == nil || !strings.Contains(b.err().Error(), "fork") {
		t.Fatalf("fork not detected: %v", b.err())
	}
	// A claim for a revision not reached yet is checked when it is applied.
	c := emptyReplica(t, s)
	c.claim(cp)
	mustReject(t, c, 2, "fork", put(s, "/y", 2, 0, 2, 1, 0, "seen by b"))
}

func TestHistoryTrim(t *testing.T) {
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	r.window = 0
	mustApply(t, r, 2, put(s, "/a", 2, 0, 2, 1, 0, "1"))
	mustApply(t, r, 3, put(s, "/a", 3, 2, 2, 2, 0, "2"))
	if _, err := r.serveRange(&pb.RangeRequest{}, keyRange{single: true, start: "/a"}, 2); err != errCompacted {
		t.Fatalf("old revision should be compacted, got %v", err)
	}
	if got, _ := read(t, r, "/a", 3); got != "2" {
		t.Fatalf("latest lost after trim: %q", got)
	}
}

func TestEvalCompare(t *testing.T) {
	v := version{modRev: 5, createRev: 3, ver: 2, lease: 7}
	cmp := func(target pb.Compare_CompareTarget, res pb.Compare_CompareResult, u any) *pb.Compare {
		c := &pb.Compare{Target: target, Result: res}
		switch x := u.(type) {
		case *pb.Compare_ModRevision:
			c.TargetUnion = x
		case *pb.Compare_Version:
			c.TargetUnion = x
		case *pb.Compare_CreateRevision:
			c.TargetUnion = x
		case *pb.Compare_Lease:
			c.TargetUnion = x
		}
		return c
	}
	for _, tc := range []struct {
		c    *pb.Compare
		v    version
		want bool
	}{
		{cmp(pb.Compare_MOD, pb.Compare_EQUAL, &pb.Compare_ModRevision{ModRevision: 5}), v, true},
		{cmp(pb.Compare_MOD, pb.Compare_EQUAL, &pb.Compare_ModRevision{ModRevision: 0}), version{}, true},
		{cmp(pb.Compare_VERSION, pb.Compare_GREATER, &pb.Compare_Version{Version: 1}), v, true},
		{cmp(pb.Compare_CREATE, pb.Compare_LESS, &pb.Compare_CreateRevision{CreateRevision: 3}), v, false},
		{cmp(pb.Compare_LEASE, pb.Compare_NOT_EQUAL, &pb.Compare_Lease{Lease: 7}), v, false},
	} {
		if got := evalCompare(tc.c, tc.v); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.c, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------- checkpoints between instances

func TestCheckpointPersist(t *testing.T) {
	s := testSealer(t, 1)
	a := emptyReplica(t, s)
	mustApply(t, a, 2, put(s, "/x", 2, 0, 2, 1, 0, "1"))
	fa := newFreshness(filepath.Join(t.TempDir(), "a"), a)
	fa.persist()
	latest, _, ok, err := newFreshness(fa.file, a).loadFile()
	if err != nil || !ok || latest.rev != 2 {
		t.Fatalf("persisted checkpoint lost: %v %v %v", latest, ok, err)
	}
}

// Checkpoint records of other instances travel through the backend like all data: the
// replica notes them, and a record whose digest differs from our own at that revision is a
// fork.
func TestCheckpointRecords(t *testing.T) {
	s := testSealer(t, 1)
	b := emptyReplica(t, s)
	b.self = "b"
	mustApply(t, b, 2, put(s, "/x", 2, 0, 2, 1, 0, "1"))
	good, _ := b.digestAt(2)
	at := time.Now().Add(-time.Hour)
	rec := string(formatRecord(checkpoint{rev: 2, digest: good}, at))
	mustApply(t, b, 3, put(s, checkpointPrefix+"a", 3, 0, 3, 1, 0, rec))
	if b.newestRecord() != 2 {
		t.Fatalf("newest record %d", b.newestRecord())
	}
	if ages := b.peerAges(time.Now()); len(ages) != 1 || ages["a"] > time.Minute {
		t.Fatalf("peer ages %v (seen counts, not the writer's clock)", ages)
	}
	// our own record is not a peer
	mustApply(t, b, 4, put(s, checkpointPrefix+"b", 4, 0, 4, 1, 0, string(formatRecord(checkpoint{rev: 3, digest: good}, at))))
	if ages := b.peerAges(time.Now()); len(ages) != 1 {
		t.Fatalf("own record listed: %v", ages)
	}
	// a record that names revision 2 with another digest: two histories
	forked := string(formatRecord(checkpoint{rev: 2, digest: [32]byte{1}}, at))
	mustReject(t, b, 5, "fork", put(s, checkpointPrefix+"a", 5, 3, 3, 2, 0, forked))
	// records are not visible to clients
	resp, err := b.serveRange(&pb.RangeRequest{}, keyRange{all: true}, 0)
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Key) != "/x" {
		t.Fatalf("records leaked to clients: %v %v", resp, err)
	}
}

func TestRecordFormat(t *testing.T) {
	cp := checkpoint{rev: 42, digest: [32]byte{7, 8}}
	at := time.Unix(1_800_000_000, 0)
	got, gotAt, err := parseRecord(formatRecord(cp, at))
	if err != nil || got != cp || !gotAt.Equal(at) {
		t.Fatalf("%v %v %v", got, gotAt, err)
	}
	for _, bad := range []string{"", "42", "42 xx 1", "x 0707 1", "42 " + strings.Repeat("0", 64) + " now"} {
		if _, _, err := parseRecord([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFreshnessRejectsRollback(t *testing.T) {
	f := newFreshness(filepath.Join(t.TempDir(), "s"), nil)
	before := f.floor()
	if err := f.check(before, &pb.ResponseHeader{Revision: 100}); err != nil {
		t.Fatal(err)
	}
	if err := f.check(before, &pb.ResponseHeader{Revision: 90}); err != nil {
		t.Fatalf("overtaken response wrongly rejected: %v", err)
	}
	if err := f.check(f.floor(), &pb.ResponseHeader{Revision: 90}); status.Code(err) != codes.DataLoss {
		t.Fatalf("rollback not detected: %v", err)
	}
}

// ---------------------------------------------------------------- attacks against a real etcd
//
// Run with: E2E_ETCD_DIR=/path/to/etcd-release go test -run Attack -v

func needEtcd(t *testing.T) string {
	dir := os.Getenv("E2E_ETCD_DIR")
	if dir == "" {
		t.Skip("set E2E_ETCD_DIR to run attacks against a real etcd")
	}
	return dir
}

// startEtcd runs a throw-away etcd and returns a raw (attacker) client to it.
func startEtcd(t *testing.T, dir string, port int) (string, pb.KVClient) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(filepath.Join(dir, "etcd"), "--data-dir", t.TempDir(),
		"--listen-client-urls", "http://"+addr, "--advertise-client-urls", "http://"+addr,
		"--listen-peer-urls", fmt.Sprintf("http://127.0.0.1:%d", port+1),
		"--initial-advertise-peer-urls", fmt.Sprintf("http://127.0.0.1:%d", port+1),
		"--initial-cluster", fmt.Sprintf("default=http://127.0.0.1:%d", port+1))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	kv := dial(t, addr)
	for i := 0; i < 100; i++ {
		if _, err := kv.Range(context.Background(), &pb.RangeRequest{Key: []byte("x")}); err == nil {
			return addr, kv
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("etcd did not start")
	return "", nil
}

func dial(t *testing.T, addr string) pb.KVClient {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewKVClient(conn)
}

func startProxy(t *testing.T, ctx context.Context, upstream string, mods ...func(*config)) *proxy {
	t.Helper()
	return startProxyWithState(t, ctx, upstream, "", mods...)
}

// startProxyAfter starts a new instance with the state of an existing one, as veilctl join
// does with the state from the invite file.
func startProxyAfter(t *testing.T, ctx context.Context, upstream string, from *proxy, mods ...func(*config)) *proxy {
	t.Helper()
	cp, ok := from.rep.checkpoint()
	if !ok {
		t.Fatal("no checkpoint to start from")
	}
	return startProxyWithState(t, ctx, upstream, "latest "+formatCheckpoint(cp)+"\nanchor 0 "+strings.Repeat("0", 64)+"\n", mods...)
}

var instances atomic.Int32

func startProxyWithState(t *testing.T, ctx context.Context, upstream, state string, mods ...func(*config)) *proxy {
	t.Helper()
	file := filepath.Join(t.TempDir(), "state")
	if state != "" {
		os.WriteFile(file, []byte(state), 0o600)
	}
	cfg := config{listen: "127.0.0.1:0", upstream: upstream, node: fmt.Sprintf("i%d", instances.Add(1)),
		stateFile: file, master: bytes.Repeat([]byte{7}, 32), history: 10 * time.Minute}
	for _, m := range mods {
		m(&cfg)
	}
	p, err := start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// eventually waits until a read through the proxy fails with DataLoss containing want.
func eventually(t *testing.T, kv pb.KVClient, key, want string) {
	t.Helper()
	var err error
	for i := 0; i < 50; i++ {
		_, err = kv.Range(context.Background(), &pb.RangeRequest{Key: []byte(key)})
		if status.Code(err) == codes.DataLoss && strings.Contains(err.Error(), want) {
			t.Logf("refused as expected: %v", status.Convert(err).Message())
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected DataLoss containing %q, last error: %v", want, err)
}

func TestAttackNormalOperationTwoInstances(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := startEtcd(t, dir, 23790)
	a := startProxy(t, ctx, addr)
	b := startProxy(t, ctx, addr)
	ka, kb := dial(t, a.addr), dial(t, b.addr)

	if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte("/registry/secrets/prod/db"), Value: []byte("v1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte("/registry/secrets/prod/db"), Value: []byte("v2")}); err != nil {
		t.Fatal(err)
	}
	resp, err := kb.Range(ctx, &pb.RangeRequest{Key: []byte("/registry/secrets/prod/db")})
	if err != nil || len(resp.Kvs) != 1 || string(resp.Kvs[0].Value) != "v2" || resp.Kvs[0].Version != 2 {
		t.Fatalf("instance B does not read A's write: %v %v", resp, err)
	}
	if _, err := kb.DeleteRange(ctx, &pb.DeleteRangeRequest{Key: []byte("/registry/secrets/prod/db")}); err != nil {
		t.Fatal(err)
	}
	resp, err = ka.Range(ctx, &pb.RangeRequest{Key: []byte("/registry/secrets/prod/db")})
	if err != nil || len(resp.Kvs) != 0 {
		t.Fatalf("delete via B not visible via A: %v %v", resp, err)
	}
}

// RangeStream (etcd 3.7): the same keys as Range, in chunks, header, more and count in the last.
func TestRangeStream(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := startEtcd(t, dir, 23794)
	p := startProxy(t, ctx, addr)
	kv := dial(t, p.addr)
	n := rangeChunk + rangeChunk/2
	for i := 0; i < n; i++ {
		if _, err := kv.Put(ctx, &pb.PutRequest{Key: []byte(fmt.Sprintf("/registry/pods/p%04d", i)), Value: []byte("v")}); err != nil {
			t.Fatal(err)
		}
	}
	req := &pb.RangeRequest{Key: []byte("/registry/pods/"), RangeEnd: []byte("/registry/pods0")}
	want, err := kv.Range(ctx, req)
	if err != nil || len(want.Kvs) != n {
		t.Fatalf("range: %d keys, %v", len(want.Kvs), err)
	}
	stream, err := kv.RangeStream(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	var got []*mvccpb.KeyValue
	var chunks int
	var last *pb.RangeResponse
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		chunks++
		got = append(got, r.RangeResponse.Kvs...)
		last = r.RangeResponse
	}
	if chunks != 2 || len(got) != n || last.Count != int64(n) || last.Header == nil || last.Header.Revision != want.Header.Revision {
		t.Fatalf("%d chunks, %d keys, last %+v", chunks, len(got), last)
	}
	for i := range got {
		if string(got[i].Key) != string(want.Kvs[i].Key) || string(got[i].Value) != "v" {
			t.Fatalf("key %d: %s", i, got[i].Key)
		}
	}
}

func TestBackendTarget(t *testing.T) {
	for _, c := range []struct{ in, target, host string }{
		{"127.0.0.1:2379", "dns:///127.0.0.1:2379", "127.0.0.1"},
		{"backend.veilplane.com:443", "dns:///backend.veilplane.com:443", "backend.veilplane.com"},
		{"10.0.0.1:2379, 10.0.0.2:2379", "veil-backends:///backend", "10.0.0.1"},
	} {
		target, _, host := Target(c.in)
		if target != c.target || host != c.host {
			t.Errorf("%q: got %q %q, want %q %q", c.in, target, host, c.target, c.host)
		}
	}
}

// With several backend addresses, a dead one is skipped: calls go to the instances that work.
func TestSeveralBackendAddresses(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := startEtcd(t, dir, 23880)
	a := startProxy(t, ctx, "127.0.0.1:1,"+addr) // nothing listens on port 1
	ka := dial(t, a.addr)
	for i := 0; i < 20; i++ {
		if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte(fmt.Sprintf("/k/%d", i)), Value: []byte("v")}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	resp, err := ka.Range(ctx, &pb.RangeRequest{Key: []byte("/k/"), RangeEnd: []byte("/k0")})
	if err != nil || resp.Count != 20 {
		t.Fatalf("range: %v %v", resp, err)
	}
}

func TestAttackReplayedValue(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, backend := startEtcd(t, dir, 23800)
	a := startProxy(t, ctx, addr)
	ka := dial(t, a.addr)
	key := "/registry/clusterrolebindings/admin"
	r1, err := ka.Put(ctx, &pb.PutRequest{Key: []byte(key), Value: []byte("alice is admin")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte(key), Value: []byte("alice removed")}); err != nil {
		t.Fatal(err)
	}
	// The hoster cannot decrypt, but copies the old ciphertext back.
	ek := []byte(a.s.encKey(key))
	old, err := backend.Range(ctx, &pb.RangeRequest{Key: ek, Revision: r1.Header.Revision})
	if err != nil || len(old.Kvs) != 1 {
		t.Fatal(err)
	}
	if _, err := backend.Put(ctx, &pb.PutRequest{Key: ek, Value: old.Kvs[0].Value}); err != nil {
		t.Fatal(err)
	}
	eventually(t, ka, key, "replayed")
}

func TestAttackForgedDelete(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, backend := startEtcd(t, dir, 23810)
	a := startProxy(t, ctx, addr)
	ka := dial(t, a.addr)
	key := "/registry/networkpolicies/prod/deny-all"
	if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte(key), Value: []byte("deny everything")}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.DeleteRange(ctx, &pb.DeleteRangeRequest{Key: []byte(a.s.encKey(key))}); err != nil {
		t.Fatal(err)
	}
	eventually(t, ka, key, "forged delete")
}

// A new instance without any checkpoint must not blindly trust a backend that
// already holds data: it could be a rolled back or forged state.
func TestAttackNewInstanceWithoutCheckpoint(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := startEtcd(t, dir, 23840)
	a := startProxy(t, ctx, addr)
	if _, err := dial(t, a.addr).Put(ctx, &pb.PutRequest{Key: []byte("/registry/x/y"), Value: []byte("data")}); err != nil {
		t.Fatal(err)
	}
	lonely := startProxy(t, ctx, addr) // no state file
	eventually(t, dial(t, lonely.addr), "/registry/x/y", "no checkpoint")
	// a restart must not turn what it was shown into a verified checkpoint
	file := lonely.fresh.file
	lonely.shutdown()
	again := startProxy(t, ctx, addr, func(c *config) { c.stateFile = file })
	eventually(t, dial(t, again.addr), "/registry/x/y", "no checkpoint")
	invited := startProxyAfter(t, ctx, addr, a)
	if resp, err := dial(t, invited.addr).Range(ctx, &pb.RangeRequest{Key: []byte("/registry/x/y")}); err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("instance with the checkpoint of an existing one should verify and serve: %v %v", resp, err)
	}
}

func TestAttackFork(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr1, _ := startEtcd(t, dir, 23820)
	addr2, _ := startEtcd(t, dir, 23830)
	a := startProxy(t, ctx, addr1)
	ka := dial(t, a.addr)
	for i := 0; i < 3; i++ {
		if _, err := ka.Put(ctx, &pb.PutRequest{Key: []byte("/registry/pods/x/a"), Value: []byte(fmt.Sprint(i))}); err != nil {
			t.Fatal(err)
		}
	}
	b := startProxyAfter(t, ctx, addr2, a) // the "other history" is empty
	eventually(t, dial(t, b.addr), "/registry/pods/x/a", "back in time")
}

// Instances write checkpoint records; the others see them, and one that stops writing is
// reported as silent (down, or hidden by the backend).
func TestAttackSilentPeer(t *testing.T) {
	dir := needEtcd(t)
	fast := func(c *config) { c.checkpointEvery, c.silentAfter = 300*time.Millisecond, 2*time.Second }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr, _ := startEtcd(t, dir, 23890)
	actx, acancel := context.WithCancel(ctx)
	a := startProxy(t, actx, addr, fast)
	b := startProxyAfter(t, ctx, addr, a, fast)
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if ok() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out: %s", what)
	}
	waitFor("b sees a's record", func() bool { _, ok := b.rep.peerAges(time.Now())[a.node]; return ok })
	if age := b.rep.peerAges(time.Now())[a.node]; age > b.silentAfter {
		t.Fatalf("a is silent while running: %v", age)
	}
	acancel() // a stops
	a.shutdown()
	waitFor("a reported silent", func() bool { return b.rep.peerAges(time.Now())[a.node] > b.silentAfter })
	if b.rep.err() != nil {
		t.Fatalf("a silent instance must not stop the others: %v", b.rep.err())
	}
	// leaving removes the record: no more waiting for it
	c := startProxyAfter(t, ctx, addr, b, fast)
	waitFor("b sees c", func() bool { _, ok := b.rep.peerAges(time.Now())[c.node]; return ok })
	if err := c.removeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor("c's record removed", func() bool { _, ok := b.rep.peerAges(time.Now())[c.node]; return !ok })
}

// ---------------------------------------------------------------- operations

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestOpsEndpointsAndShutdown(t *testing.T) {
	dir := needEtcd(t)
	ctx, cancel := context.WithCancel(context.Background())
	addr, _ := startEtcd(t, dir, 23870)
	state := filepath.Join(t.TempDir(), "state")
	p, err := start(ctx, config{listen: "127.0.0.1:0", upstream: addr, opsListen: "127.0.0.1:0", stateFile: state,
		master: bytes.Repeat([]byte{7}, 32), history: 10 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	kv := dial(t, p.addr)
	kv.Put(ctx, &pb.PutRequest{Key: []byte("/registry/a/b"), Value: []byte("x")})
	kv.Range(ctx, &pb.RangeRequest{Key: []byte("/registry/a/b")})
	base := "http://" + p.opsAddr
	if code, _ := httpGet(t, base+"/healthz"); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	if code, body := httpGet(t, base+"/readyz"); code != 200 {
		t.Fatalf("readyz %d %s", code, body)
	}
	_, m := httpGet(t, base+"/metrics")
	for _, want := range []string{"veil_replica_failed 0", "veil_replica_tracked_keys 1",
		`veil_grpc_requests_total{method="/etcdserverpb.KV/Put",code="OK"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q:\n%s", want, m)
		}
	}
	// The verified state is persisted (every minute, and at shutdown).
	rev := p.rep.current()
	p.fresh.persist()
	// After a detected attack: alive, not ready, failed=1.
	p.rep.fail(dataLoss("test"))
	if code, _ := httpGet(t, base+"/readyz"); code != 503 {
		t.Fatalf("readyz after failure: %d", code)
	}
	if _, m := httpGet(t, base+"/metrics"); !strings.Contains(m, "veil_replica_failed 1") {
		t.Fatal("failure not visible in metrics")
	}
	// Shutting down after the failure keeps the last verified checkpoint: what a stopped
	// replica holds is never written as verified.
	if _, ok := p.fresh.current(); ok {
		t.Fatal("a stopped replica offers its state for invites")
	}
	cancel()
	p.shutdown()
	latest, _, ok, err := newFreshness(state, nil).loadFile()
	if err != nil || !ok || latest.rev != rev {
		t.Fatalf("checkpoint after shutdown: %v (want rev %d) %v", latest, rev, err)
	}
}

// ---------------------------------------------------------------- scale

// 100k keys: applying them and listing a namespace must stay fast.
func TestLargeReplica(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	s := testSealer(t, 1)
	r := emptyReplica(t, s)
	const namespaces, perNS = 100, 1000
	rev := int64(2)
	t0 := time.Now()
	for ns := 0; ns < namespaces; ns++ {
		var evs []*mvccpb.Event
		for i := 0; i < perNS; i++ {
			evs = append(evs, put(s, fmt.Sprintf("/registry/configmaps/ns-%03d/cm-%04d", ns, i), rev, 0, rev, 1, 0, "v"))
		}
		mustApply(t, r, rev, evs...)
		rev++
	}
	apply := time.Since(t0)
	t0 = time.Now()
	resp, err := r.serveRange(&pb.RangeRequest{}, keyRange{prefix: "/registry/configmaps/ns-042/", start: "/registry/configmaps/ns-042/"}, 0)
	list := time.Since(t0)
	if err != nil || len(resp.Kvs) != perNS {
		t.Fatalf("list: %d %v", len(resp.Kvs), err)
	}
	t0 = time.Now()
	count, _ := r.serveRange(&pb.RangeRequest{CountOnly: true}, keyRange{prefix: "/registry/configmaps/", start: "/registry/configmaps/"}, 0)
	countAll := time.Since(t0)
	t.Logf("100k keys: apply %v (%.0f µs/key incl. decryption), list one namespace (1000 keys) %v, count all %v (%d)",
		apply, float64(apply.Microseconds())/float64(namespaces*perNS), list, countAll, count.Count)
	if list > 50*time.Millisecond {
		t.Errorf("listing one namespace took %v", list)
	}
}

// ---------------------------------------------------------------- fuzzing
//
// go test -run x -fuzz FuzzX -fuzztime 30s

func FuzzParseReceipt(f *testing.F) {
	f.Add(buildReceipt(map[string]int64{"/a": 1}))
	f.Fuzz(func(t *testing.T, b []byte) { parseReceipt(b) })
}

// The base64 decoder skips line breaks even in strict mode; a key with one inserted must not
// decode, or the backend could store the same plaintext key under several spellings.
func TestDecKeyRejectsLineBreaks(t *testing.T) {
	s, _ := newSealer(bytes.Repeat([]byte{1}, 32))
	ek := s.encKey("/registry/pods")
	for _, lb := range []string{"\n", "\r", "\r\n"} {
		bad := ek[:10] + lb + ek[10:]
		if pk, err := s.decKey(bad); err == nil {
			t.Errorf("decKey accepted %q -> %q", bad, pk)
		}
	}
	if _, err := s.decKey(ek); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecKey(f *testing.F) {
	s, _ := newSealer(bytes.Repeat([]byte{1}, 32))
	f.Add(s.encKey("/registry/pods/x/y"))
	f.Add("/a//b/")
	ek := s.encKey("/registry/pods")
	f.Add(ek[:10] + "\n" + ek[10:])
	f.Fuzz(func(t *testing.T, k string) {
		if pk, err := s.decKey(k); err == nil && s.encKey(pk) != k {
			t.Fatalf("decKey accepted a non-canonical key %q -> %q", k, pk)
		}
	})
}

func FuzzOpenRecord(f *testing.F) {
	s, _ := newSealer(bytes.Repeat([]byte{1}, 32))
	f.Add(s.sealRecord("/k", 1, 0, []byte("v")))
	f.Fuzz(func(t *testing.T, b []byte) { s.openRecord("/k", b) })
}

func FuzzParseRange(f *testing.F) {
	f.Add([]byte("/registry/pods/"), []byte("/registry/pods0"))
	f.Add([]byte("a\x00"), []byte("b"))
	f.Fuzz(func(t *testing.T, k, e []byte) {
		kr, err := parseRange(k, e)
		if err == nil && !kr.single && !kr.all && !strings.HasPrefix(kr.start, kr.prefix) {
			t.Fatalf("start %q outside prefix %q", kr.start, kr.prefix)
		}
	})
}

func FuzzParseCheckpoint(f *testing.F) {
	f.Add("5 " + strings.Repeat("ab", 32))
	f.Fuzz(func(t *testing.T, s string) { parseCheckpoint(s) })
}

// A backend must not be able to create a second ciphertext spelling of the
// same key (e.g. base64 with non-zero unused bits): one plaintext key, one
// backend key.
func TestCanonicalCiphertextKeys(t *testing.T) {
	s := testSealer(t, 1)
	for n := 1; n < 80; n++ {
		enc := s.encSegment("/registry", strings.Repeat("x", n))
		last := enc[len(enc)-1]
		for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
			if byte(c) == last {
				continue
			}
			alt := enc[:len(enc)-1] + string(c)
			if pt, err := s.decSegment("/registry", alt); err == nil {
				t.Fatalf("length %d: alternative spelling %q accepted (decodes to %d bytes)", n, alt, len(pt))
			}
		}
	}
}

// A watch stream that never says anything (stuck somewhere on the way to the backend): the
// replica asks it for progress after watchProbe, gives it up after watchSilence instead of
// waiting for it forever, and follow opens a new one.
func TestSilentWatchIsReplaced(t *testing.T) {
	oldSilence, oldProbe := watchSilence, watchProbe
	watchSilence, watchProbe = 200*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { watchSilence, watchProbe = oldSilence, oldProbe })
	w := &silentWatch{}
	r := newReplica(testSealer(t, 1), time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err := r.followOnce(ctx, &proxy{watch: w})
	if err == nil || !strings.Contains(err.Error(), "no word from the backend") {
		t.Fatalf("followOnce: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("gave up only after %v", d)
	}
	if w.opened.Load() != 1 || w.creates.Load() != 1 || w.probes.Load() == 0 {
		t.Fatalf("%d streams, %d create requests, %d progress requests", w.opened.Load(), w.creates.Load(), w.probes.Load())
	}
}

// A quiet stream that answers when asked stays: the progress requests keep it, not the watchdog.
func TestQuietWatchThatAnswersStays(t *testing.T) {
	oldSilence, oldProbe := watchSilence, watchProbe
	watchSilence, watchProbe = 300*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { watchSilence, watchProbe = oldSilence, oldProbe })
	w := &silentWatch{answer: true}
	r := newReplica(testSealer(t, 1), time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := r.followOnce(ctx, &proxy{watch: w})
	if ctx.Err() == nil || (err != nil && strings.Contains(err.Error(), "no word from the backend")) {
		t.Fatalf("followOnce ended before its context: %v", err)
	}
	if w.probes.Load() < 5 {
		t.Fatalf("only %d progress requests in a second", w.probes.Load())
	}
}

// A stream whose far end is gone fails at the first progress request, long before watchSilence.
func TestDeadWatchFailsAtTheFirstProbe(t *testing.T) {
	oldSilence, oldProbe := watchSilence, watchProbe
	watchSilence, watchProbe = 10*time.Second, 50*time.Millisecond
	t.Cleanup(func() { watchSilence, watchProbe = oldSilence, oldProbe })
	w := &silentWatch{dead: true}
	r := newReplica(testSealer(t, 1), time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := r.followOnce(ctx, &proxy{watch: w}); err == nil || ctx.Err() != nil {
		t.Fatalf("followOnce: %v (context: %v)", err, ctx.Err())
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("noticed only after %v", d)
	}
}

// silentWatch: streams that never send anything by themselves. answer: progress requests get a
// progress answer. dead: progress requests fail, as on a stream whose far end is gone.
type silentWatch struct {
	answer, dead            bool
	opened, creates, probes atomic.Int32
}

func (w *silentWatch) Watch(ctx context.Context, _ ...grpc.CallOption) (pb.Watch_WatchClient, error) {
	w.opened.Add(1)
	return &silentStream{ctx: ctx, w: w, answers: make(chan struct{}, 16)}, nil
}

type silentStream struct {
	grpc.ClientStream
	ctx     context.Context
	w       *silentWatch
	answers chan struct{}
}

func (s *silentStream) Send(r *pb.WatchRequest) error {
	if r.GetCreateRequest() != nil {
		s.w.creates.Add(1)
		return nil
	}
	s.w.probes.Add(1)
	if s.w.dead {
		return io.EOF
	}
	if s.w.answer {
		s.answers <- struct{}{}
	}
	return nil
}

func (s *silentStream) Recv() (*pb.WatchResponse, error) {
	select {
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-s.answers:
		return &pb.WatchResponse{WatchId: -1}, nil
	}
}
