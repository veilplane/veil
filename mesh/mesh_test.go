// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package mesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
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
	c := Cert{Cluster: "alpha", Node: "w-1", Role: "worker", WireGuard: wg, Address: netip.MustParseAddr("10.200.0.2"),
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
	forged := strings.Replace(string(text), "10.200.0.2", "10.200.0.3", 1)
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
	self, selfWG := mk("cp-1", "10.200.0.1", k)
	good, _ := mk("w-1", "10.200.0.2", k)
	foreign, _ := mk("w-2", "10.200.0.3", ed25519.NewKeyFromSeed(make([]byte, 32)))
	dupe, _ := mk("w-3", "10.200.0.2", k)
	_ = selfWG

	a := &agent{cfg: &Config{Cluster: "alpha"}, peers: map[string]*peer{}, meshKey: k.Public().(ed25519.PublicKey),
		prefix: netip.MustParsePrefix("10.200.0.0/16"), wg: nil}
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

// What gets in the way of the mesh network on a machine: an overlapping address or route on
// another interface, and Tailscale when the mesh network lies in its range.
func TestConflicts(t *testing.T) {
	pf := netip.MustParsePrefix
	nets := []hostNet{
		{iface: "lo", prefix: pf("127.0.0.1/8")},
		{iface: "eth0", prefix: pf("192.168.11.124/24")},
		{iface: "veil0", prefix: pf("10.200.0.1/16")},         // our own: never a conflict
		{iface: "eth0", prefix: pf("0.0.0.0/0"), route: true}, // the default route: neither
		{iface: "cni0", prefix: pf("10.42.0.1/24")},
		{iface: "tailscale0", prefix: pf("100.120.165.66/32")},
	}
	if got := conflicts(pf("10.200.0.0/16"), "veil0", nets); len(got) != 0 {
		t.Fatalf("no conflict expected: %v", got)
	}
	// the old mesh network, in Tailscale's range
	got := conflicts(pf("100.96.0.0/16"), "veil0", append(nets, hostNet{iface: "veil0", prefix: pf("100.96.0.1/16")}))
	if len(got) != 1 || !strings.Contains(got[0], "Tailscale") || !strings.Contains(got[0], "iptables -I INPUT 1 -i veil0 -j ACCEPT") {
		t.Fatalf("Tailscale not reported: %v", got)
	}
	// a network of another interface inside the mesh network, and a route into it
	got = conflicts(pf("10.200.0.0/16"), "veil0", append(nets,
		hostNet{iface: "docker0", prefix: pf("10.200.5.1/24")},
		hostNet{iface: "wg9", prefix: pf("10.0.0.0/8"), route: true}))
	if len(got) != 2 || !strings.Contains(got[0], "docker0") || !strings.Contains(got[1], "wg9 (a route)") {
		t.Fatalf("overlaps: %v", got)
	}
}

func TestParseRoutes(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t010BA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t000BA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"veil0\t0000C80A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
	got := parseRoutes(table)
	if len(got) != 2 || got[0].prefix.String() != "192.168.11.0/24" || got[1].prefix.String() != "10.200.0.0/16" || got[1].iface != "veil0" {
		t.Fatalf("%+v", got)
	}
}

// The interface is put back when something else takes it down or removes its address, and its
// disappearance is reported. Needs root (CAP_NET_ADMIN); skipped without.
func TestRepairInterface(t *testing.T) {
	const name = "vguard0"
	if err := ip("link", "add", name, "type", "bridge"); err != nil {
		t.Skipf("cannot create interfaces here: %v", err)
	}
	t.Cleanup(func() { _ = ip("link", "del", name) })
	addr := netip.MustParsePrefix("10.200.0.9/16")

	fixed, err := repairInterface(name, addr) // new: down, without the address
	if err != nil || !strings.Contains(fixed, "address was removed") || !strings.Contains(fixed, "taken down") {
		t.Fatalf("first: %q %v", fixed, err)
	}
	if fixed, err := repairInterface(name, addr); err != nil || fixed != "" {
		t.Fatalf("nothing to do: %q %v", fixed, err)
	}
	if err := ip("link", "set", name, "down"); err != nil {
		t.Fatal(err)
	}
	if fixed, err := repairInterface(name, addr); err != nil || fixed != "it was taken down" {
		t.Fatalf("down: %q %v", fixed, err)
	}
	if err := ip("address", "flush", "dev", name); err != nil {
		t.Fatal(err)
	}
	if fixed, err := repairInterface(name, addr); err != nil || fixed != "its address was removed" {
		t.Fatalf("flushed: %q %v", fixed, err)
	}
	i, _ := net.InterfaceByName(name)
	if i == nil || i.Flags&net.FlagUp == 0 {
		t.Fatalf("not up again: %v", i)
	}
	if err := ip("link", "del", name); err != nil {
		t.Fatal(err)
	}
	if _, err := repairInterface(name, addr); err == nil || !strings.Contains(err.Error(), "is gone") {
		t.Fatalf("gone: %v", err)
	}
}
