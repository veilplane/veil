// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package mesh

import (
	"context"
	"strings"
	"time"
)

// Backend is how the mesh talks to the backend: the agent API (/agent/v1/mesh/..., with the
// node's access token). The agent implements it.
type Backend interface {
	// Register hands in this node's certificate and local addresses.
	Register(ctx context.Context, certificate string, endpoints []string) (*Registration, error)
	// Peers returns the member list. With the ETag of the last answer it waits for a change
	// (long polling) and returns nil if there was none.
	Peers(ctx context.Context, etag string) (*PeerList, string, error)
	// Report tells the backend how this node reaches each peer (shown in the dashboard).
	Report(ctx context.Context, peers []PeerReport) error
	// Clock is the backend's time.
	Clock(ctx context.Context) (time.Time, error)
}

// Registration: where the reflector is, and the mesh network.
type Registration struct {
	Prefix       string `json:"prefix"`
	Reflector    string `json:"reflector"`    // host:port, empty without one
	ReflectorKey []byte `json:"reflectorKey"` // its WireGuard public key (base64 in JSON)
}

// Endpoint kinds.
const (
	Local    = "local"    // an address of the node's own interfaces
	Observed = "observed" // where the reflector saw it (behind NAT: the router's)
)

type Endpoint struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
}

// Peer is a member as the backend lists it.
type Peer struct {
	Node        string     `json:"node"`
	Certificate string     `json:"certificate"`
	Endpoints   []Endpoint `json:"endpoints"`
}

type PeerList struct {
	Peers []Peer `json:"peers"`
}

// PeerReport: how this node reaches one peer.
type PeerReport struct {
	Node          string `json:"node"`
	State         string `json:"state"` // trying, connected, unreachable, refused
	Path          string `json:"path,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	LastHandshake int64  `json:"lastHandshake,omitempty"` // Unix seconds
}

// peerState is what this node knows about reaching a peer.
type peerState int

const (
	stateTrying peerState = iota
	stateConnected
	stateUnreachable
	stateRefused
)

func (s peerState) String() string {
	return [...]string{"TRYING", "CONNECTED", "UNREACHABLE", "REFUSED"}[s]
}

func (s peerState) name() string { return strings.ToLower(s.String()) }
