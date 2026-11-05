// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package mesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testMaster(t *testing.T) []byte {
	m := make([]byte, 32)
	rand.Read(m)
	return m
}

func TestMeshKeyIsPerClusterAndStable(t *testing.T) {
	m := testMaster(t)
	a1, _ := meshKey(m, "alpha")
	a2, _ := meshKey(m, "alpha")
	b, _ := meshKey(m, "beta")
	if !a1.Equal(a2) {
		t.Fatal("same master key and cluster must give the same mesh key")
	}
	if a1.Equal(b) {
		t.Fatal("another cluster must give another mesh key")
	}
	if _, err := meshKey(m[:31], "alpha"); err == nil {
		t.Fatal("short master key accepted")
	}
}

func TestCertificates(t *testing.T) {
	k, _ := meshKey(testMaster(t), "alpha")
	var wg [32]byte
	rand.Read(wg[:])
	c := Cert{Cluster: "alpha", Node: "w-1", Role: "worker", WireGuard: wg, Address: netip.MustParseAddr("100.96.0.2"),
		Issued: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)}
	s, err := issue(k, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyCert(k.Public().(ed25519.PublicKey), s)
	if err != nil || got != c {
		t.Fatalf("round trip: %v %+v", err, got)
	}

	other, _ := meshKey(testMaster(t), "alpha")
	if _, err := verifyCert(other.Public().(ed25519.PublicKey), s); err == nil {
		t.Fatal("certificate of another master key accepted")
	}
	// the backend changes the address or the key: the signature breaks
	text, _ := base64.RawURLEncoding.DecodeString(strings.Split(s, ".")[0])
	forged := strings.Replace(string(text), "100.96.0.2", "100.96.0.3", 1)
	f := base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + strings.Split(s, ".")[1]
	if _, err := verifyCert(k.Public().(ed25519.PublicKey), f); err == nil {
		t.Fatal("altered certificate accepted")
	}
	for _, bad := range []Cert{{Cluster: "alpha", Node: "x", Role: "admin", Address: c.Address}, {Cluster: "alpha", Node: "x", Role: "worker"}} {
		if _, err := issue(k, bad); err == nil {
			t.Fatalf("issued %+v", bad)
		}
	}
}

func TestCandidateOrder(t *testing.T) {
	a := &agent{observed: netip.MustParseAddrPort("203.0.113.5:40001")}
	lan := []netip.AddrPort{netip.MustParseAddrPort("10.0.1.11:51820"), netip.MustParseAddrPort("[2001:db8::11]:51820")}
	// behind the same public address: the LAN address first
	c := a.candidates(lan, netip.MustParseAddrPort("203.0.113.5:40002"))
	if c[0].addr.String() != "10.0.1.11:51820" || !c[0].lan || c[1].addr.String() != "203.0.113.5:40002" {
		t.Fatalf("same NAT: %+v", c)
	}
	// elsewhere: the public address first, the interface addresses after it
	c = a.candidates(lan, netip.MustParseAddrPort("198.51.100.7:52000"))
	if c[0].addr.String() != "198.51.100.7:52000" || c[0].lan || len(c) != 4 || c[1].addr.String() != "198.51.100.7:51820" || c[2].lan {
		t.Fatalf("other NAT: %+v", c)
	}
	// not yet observed: interface addresses only
	if c = a.candidates(lan, netip.AddrPort{}); len(c) != 2 {
		t.Fatalf("unobserved: %+v", c)
	}
}

// The backend hands out a member whose certificate was not signed with the mesh key, a member
// that claims another's address, and one with a valid certificate: only the last is accepted.
func TestApplyRefusesWhatTheBackendCannotProve(t *testing.T) {
	m := testMaster(t)
	k, _ := meshKey(m, "alpha")
	mk := func(node string, addr string, key ed25519.PrivateKey) (string, [32]byte) {
		var wg [32]byte
		rand.Read(wg[:])
		s, err := issue(key, Cert{Cluster: "alpha", Node: node, Role: "worker", WireGuard: wg, Address: netip.MustParseAddr(addr)})
		if err != nil {
			t.Fatal(err)
		}
		return s, wg
	}
	self, selfWG := mk("cp-1", "100.96.0.1", k)
	good, _ := mk("w-1", "100.96.0.2", k)
	foreign, _ := mk("w-2", "100.96.0.3", ed25519.NewKeyFromSeed(make([]byte, 32)))
	dupe, _ := mk("w-3", "100.96.0.2", k)
	_ = selfWG

	a := &agent{cfg: &Config{Cluster: "alpha"}, peers: map[string]*peer{}, meshKey: k.Public().(ed25519.PublicKey),
		prefix: netip.MustParsePrefix("100.96.0.0/16"), wg: nil}
	var err error
	if a.self, err = verifyCert(a.meshKey, self); err != nil {
		t.Fatal(err)
	}
	a.wg = fakeWG(t)
	a.apply(&PeerList{Peers: []Peer{
		{Node: "cp-1", Certificate: self},
		{Node: "w-1", Certificate: good, Endpoints: []Endpoint{{Address: "198.51.100.7:51820", Kind: Observed}}},
		{Node: "w-2", Certificate: foreign},
		{Node: "w-3", Certificate: dupe},
		{Node: "w-4", Certificate: good}, // someone else's certificate
	}})
	want := map[string]peerState{"w-1": stateTrying, "w-2": stateRefused,
		"w-3": stateRefused, "w-4": stateRefused}
	for node, st := range want {
		if p := a.peers[node]; p == nil || p.state != st {
			t.Errorf("%s: %+v, want %v", node, p, st)
		}
	}
	if len(a.peers) != 4 {
		t.Errorf("own entry must not become a peer: %d peers", len(a.peers))
	}
}

func fakeWG(t *testing.T) *wgInterface { return &wgInterface{name: "test", mode: "test"} }
