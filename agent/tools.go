// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/veilplane/veil/mesh"
)

// The tools: one-shot commands next to the running agent, on the same files.

// session: identity, device key and API of an enrolled node.
type session struct {
	id  *Identity
	api *api
	tok *tokens
	cfg *Config
}

func open(p Paths, version string) (*session, error) {
	cfg, err := LoadConfig(p)
	if err != nil {
		return nil, err
	}
	id, err := loadIdentity(p)
	if err != nil {
		return nil, err
	}
	if id == nil {
		return nil, fmt.Errorf("this node is not enrolled yet (no %s)", p.state(identityFile))
	}
	key, err := loadDeviceKey(p)
	if err != nil {
		return nil, err
	}
	caFile := cfg.APICA
	if caFile == "" {
		if _, err := os.Stat(p.state(apiCAFile)); err == nil {
			caFile = p.state(apiCAFile)
		}
	}
	api, err := newAPI(cmpOr(id.API, cfg.API), caFile, version)
	if err != nil {
		return nil, err
	}
	return &session{id: id, api: api, cfg: cfg, tok: &tokens{api: api, cluster: id.Cluster, node: id.Node, key: key}}, nil
}

// InviteOptions of "veil invite".
type InviteOptions struct {
	Node   string        // the new node's name (required for a worker)
	Worker bool          // a worker: mesh only, no master key
	TTL    time.Duration // validity of the code (the backend caps it)
}

// CreateInvite writes an invite file for one more node. It runs on a control plane node: a
// further control plane node gets the master key (half of its key stays with the backend until
// the code is redeemed), a worker gets its WireGuard key and a mesh certificate signed with the
// cluster's mesh key.
func CreateInvite(ctx context.Context, p Paths, version string, o InviteOptions) (*Invite, error) {
	s, err := open(p, version)
	if err != nil {
		return nil, err
	}
	if s.id.Role != "control-plane" {
		return nil, errors.New("run this on a control plane node: only they hold the master key")
	}
	master, err := LoadMasterKey(p.state(masterKey))
	if err != nil {
		return nil, err
	}
	t, err := s.tok.get(ctx)
	if err != nil {
		return nil, err
	}
	inv := &Invite{Kind: InviteKind, Version: 2, API: s.api.base, Cluster: s.id.Cluster, Node: o.Node,
		InvitedBy: s.id.Cluster + "/" + s.id.Node}
	if ca := cmpOr(s.cfg.APICA, ""); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		inv.APICA = string(pem)
	} else if pem, err := os.ReadFile(p.state(apiCAFile)); err == nil {
		inv.APICA = string(pem)
	}
	req := map[string]any{"ttlSeconds": int64(o.TTL.Seconds())}
	if o.TTL == 0 {
		delete(req, "ttlSeconds")
	}
	if o.Node != "" {
		req["node"] = o.Node
	}
	var priv, pub string
	if o.Worker {
		if o.Node == "" {
			return nil, errors.New("a worker invite needs the node's name")
		}
		inv.Role = "worker"
		priv, pub = wireGuardKeys()
		req["role"], req["wireguardKey"] = "worker", pub
	} else {
		inv.Role = "control-plane"
		var server string
		if inv.FileSecret, inv.Box, server, err = inviteSeal(master); err != nil {
			return nil, err
		}
		req["serverSecret"] = server
		inv.State = currentState(ctx, p, s.cfg)
	}
	var answer struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expiresAt"`
		Address   string    `json:"address"`
		Prefix    string    `json:"prefix"`
	}
	if _, err := s.api.do(ctx, "POST", "/agent/v1/invites", t, req, &answer, nil); err != nil {
		return nil, fmt.Errorf("invite: %v", err)
	}
	inv.Code, inv.ExpiresAt = answer.Code, answer.ExpiresAt
	if o.Worker {
		k, err := mesh.MeshKey(master, s.id.Cluster)
		if err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(answer.Address)
		if err != nil {
			return nil, fmt.Errorf("the backend's mesh address %q: %v", answer.Address, err)
		}
		c := mesh.Cert{Cluster: s.id.Cluster, Node: o.Node, Role: "worker", Address: ip}
		raw, _ := base64.StdEncoding.DecodeString(pub)
		copy(c.WireGuard[:], raw)
		if inv.Certificate, err = mesh.Issue(k, c); err != nil {
			return nil, err
		}
		inv.Address, inv.Prefix, inv.WireGuardKey = answer.Address, answer.Prefix, priv
		inv.MeshKey = base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
		var st meshState
		if raw, err := os.ReadFile(p.state(meshFile)); err == nil && json.Unmarshal(raw, &st) == nil {
			inv.ControlPlane = st.Address
		}
	}
	return inv, nil
}

// currentState: the etcd proxy's verified checkpoints, from the running proxy if it can be
// asked (the newest), else from its state file. The new node checks the backend against them.
func currentState(ctx context.Context, p Paths, cfg *Config) string {
	if st, err := ReadStatus(p); err == nil {
		if f := st.Features["proxy"]; f != nil && f.State == "running" {
			if ops := cmpOr(cfg.Proxy.OpsListen, "127.0.0.1:9390"); ops != "off" {
				req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ops+"/state", nil)
				if resp, err := http.DefaultClient.Do(req); err == nil {
					raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
					resp.Body.Close()
					if resp.StatusCode == 200 {
						return string(raw)
					}
				}
			}
		}
	}
	raw, _ := os.ReadFile(p.state(proxyState))
	return string(raw)
}

// WriteInvite writes an invite file with mode 0600; it holds secrets.
func WriteInvite(inv *Invite, file string) error {
	if _, err := os.Stat(file); err == nil {
		return fmt.Errorf("%s exists already", file)
	}
	return writeJSON(file, inv, 0o600)
}

// Leave unenrolls this node: the etcd proxy's checkpoint record is removed (so the other
// control plane nodes stop expecting it), then the backend refuses the node. The running agent
// notices within seconds and stops everything.
func Leave(ctx context.Context, p Paths, version string) error {
	s, err := open(p, version)
	if err != nil {
		return err
	}
	if st, err := ReadStatus(p); err == nil {
		if f := st.Features["proxy"]; f != nil && f.State == "running" {
			ops := cmpOr(s.cfg.Proxy.OpsListen, "127.0.0.1:9390")
			if ops != "off" {
				req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+ops+"/leave", nil)
				if resp, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}
	}
	t, err := s.tok.get(ctx)
	if err != nil {
		return err
	}
	_, err = s.api.do(ctx, "POST", "/agent/v1/leave", t, nil, nil, nil)
	return err
}

// ReadStatus reads the status file.
func ReadStatus(p Paths) (*Status, error) {
	raw, err := os.ReadFile(p.Lock())
	if err != nil {
		return nil, fmt.Errorf("no status (is the agent running?): %v", err)
	}
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// FormatStatus is the status file for people.
func FormatStatus(s *Status) string {
	var b strings.Builder
	age := time.Since(s.Updated).Round(time.Second)
	backend := "not connected"
	if s.Backend.Connected {
		backend = "connected"
	}
	fmt.Fprintf(&b, "%s  %s of cluster %s (%s), backend %s, updated %v ago\n", orDash(s.State), orDash(s.Node), orDash(s.Cluster),
		orDash(s.Role), backend, age)
	if s.Error != "" {
		fmt.Fprintf(&b, "  %s\n", s.Error)
	}
	for _, name := range features {
		f := s.Features[name]
		if f == nil {
			continue
		}
		detail := ""
		switch {
		case f.Error != "":
			detail = f.Error
		case name == "proxy" && f.State == "running":
			detail = fmt.Sprintf("etcd on %s, revision %d", f.Listen, f.Revision)
		case name == "mesh" && f.Mesh != nil:
			detail = fmt.Sprintf("%s on %s (%s), public %s", f.Mesh.Address, f.Mesh.Interface, f.Mesh.Mode, orDash(f.Mesh.Public))
		}
		fmt.Fprintf(&b, "  %-6s %-9s %s\n", name, f.State, detail)
		if name == "mesh" && f.Mesh != nil {
			for _, p := range f.Mesh.Peers {
				d := p.Path
				if p.Endpoint != "" {
					d += " " + p.Endpoint
				}
				if p.Refused != "" {
					d = p.Refused
				}
				fmt.Fprintf(&b, "         %-20s %-15s %-13s %-12s %s\n", p.Node, orDash(p.Address), orDash(p.Role), p.State, d)
			}
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
