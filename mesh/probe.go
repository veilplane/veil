// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package mesh

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

// Probes: a WireGuard handshake proves that two nodes can exchange encrypted packets, not that
// the packets reach anyone. A firewall on veil0 (or Tailscale, see conflicts) can drop them after
// WireGuard decrypted them, and the peer still looks connected. So every node answers small UDP
// probes on its mesh address, and asks every connected peer every probeEvery: that tests the
// whole way, through both machines' firewalls, and measures the round trip on the way.
const probePort = 51819 // UDP, on the mesh address only; below WireGuard's 51820-52819

var (
	probeEvery = 5 * time.Second  // a probe to every connected peer
	probeDead  = 20 * time.Second // no answer for so long, with a live handshake: blocked
)

// a probe: magic, kind, sequence number, the sender's clock (echoed back, so the sender measures
// the round trip with its own clock alone)
var probeMagic = [4]byte{'v', 'p', 'r', 'b'}

const (
	probeAsk    = 1
	probeAnswer = 2
	probeSize   = 4 + 1 + 8 + 8
)

func probePacket(kind byte, seq uint64, sent time.Time) []byte {
	b := make([]byte, probeSize)
	copy(b, probeMagic[:])
	b[4] = kind
	binary.BigEndian.PutUint64(b[5:], seq)
	binary.BigEndian.PutUint64(b[13:], uint64(sent.UnixNano()))
	return b
}

func parseProbe(b []byte) (kind byte, seq uint64, sent time.Time, ok bool) {
	if len(b) != probeSize || !bytes.Equal(b[:4], probeMagic[:]) || (b[4] != probeAsk && b[4] != probeAnswer) {
		return 0, 0, time.Time{}, false
	}
	return b[4], binary.BigEndian.Uint64(b[5:]), time.Unix(0, int64(binary.BigEndian.Uint64(b[13:]))), true
}

// probe answers the peers' probes and probes the peers, until ctx ends.
func (a *agent) probe(ctx context.Context) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: a.self.Address.AsSlice(), Port: probePort})
	if err != nil {
		log.Printf("mesh: no probes (%v): peers are judged by their handshakes alone", err)
		return
	}
	every, dead := probeEvery, probeDead
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	answering := make(chan struct{})
	go func() {
		defer close(answering)
		a.answerProbes(conn, dead)
	}()
	defer func() { conn.Close(); <-answering }()
	t := time.NewTicker(every)
	defer t.Stop()
	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		for _, to := range a.dueProbes(now, dead) {
			seq++
			conn.WriteToUDPAddrPort(probePacket(probeAsk, seq, now), netip.AddrPortFrom(to, probePort))
		}
	}
}

// answerProbes reads probes and answers: it answers asks, and books answers to its own probes.
// Only packets from the mesh network count (they came through WireGuard, from a peer).
func (a *agent) answerProbes(conn *net.UDPConn, dead time.Duration) {
	buf := make([]byte, 64)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // closed
		}
		kind, seq, sent, ok := parseProbe(buf[:n])
		if !ok || !a.prefix.Contains(from.Addr().Unmap()) {
			continue
		}
		switch kind {
		case probeAsk:
			conn.WriteToUDPAddrPort(probePacket(probeAnswer, seq, sent), from)
		case probeAnswer:
			a.probeAnswered(from.Addr().Unmap(), time.Since(sent), time.Now(), dead)
		}
	}
}

// dueProbes: the peers to probe now (those with a live handshake), and the verdict on those that
// stopped answering.
func (a *agent) dueProbes(now time.Time, dead time.Duration) []netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []netip.Addr
	for _, p := range a.peers {
		if p.refused != "" || p.state != stateConnected {
			if !p.probeSince.IsZero() || p.blocked {
				p.probeSince, p.blocked, p.rtt = time.Time{}, false, 0 // a new connection starts afresh
			}
			continue
		}
		if p.probeSince.IsZero() {
			p.probeSince = now
		}
		heard := p.probeSince
		if p.lastAnswer.After(heard) {
			heard = p.lastAnswer
		}
		if !p.blocked && now.Sub(heard) > dead {
			p.blocked = true
			a.peersChanged = true
			log.Printf("peer %s: %s", p.node, blockedText)
		}
		p.probes++
		out = append(out, p.cert.Address)
	}
	return out
}

// blockedText explains a peer whose handshake works while probes get no answer.
var blockedText = fmt.Sprintf("the WireGuard handshake works, but probes over the mesh got no answer for %v: something "+
	"on one of the two machines drops mesh traffic (a firewall on the mesh interface, Tailscale; see veil status there)", probeDead)

func (a *agent) probeAnswered(from netip.Addr, rtt time.Duration, now time.Time, dead time.Duration) {
	if rtt < 0 || rtt > dead {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if p.cert.Address != from || p.refused != "" {
			continue
		}
		p.answers++
		p.lastAnswer = now
		if p.rtt == 0 {
			p.rtt = rtt
		} else {
			p.rtt = (p.rtt*7 + rtt*3) / 10 // smoothed
		}
		if p.blocked {
			p.blocked = false
			a.peersChanged = true
			log.Printf("peer %s answers probes again (%v)", p.node, rtt.Round(100*time.Microsecond))
		}
		return
	}
}
