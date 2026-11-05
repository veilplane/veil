// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// Mesh certificates: who belongs to the mesh of a cluster.
//
// The cluster's mesh key is an Ed25519 key derived from the cluster's master key:
//
//	seed = HKDF-SHA256(master key, salt = none, info = "veilplane mesh v1 " + cluster)
//
// Only control plane nodes hold the master key, so only they can sign. A certificate binds a
// node name and role to its WireGuard public key and its mesh address:
//
//	veilplane-mesh-certificate v1
//	cluster: k7f3m2x9q1ab
//	node: worker-1
//	role: worker
//	wireguard: <WireGuard public key, base64>
//	address: 100.96.0.2
//	issued: 2026-11-02T09:00:00Z
//
// encoded as base64url(text) "." base64url(Ed25519 signature over text). Every node knows the
// public half of the mesh key (control plane nodes derive it, workers get it in their invite
// file) and accepts a peer only with a valid certificate. The backend, which distributes the
// certificates, cannot make one: it cannot add a member or swap a WireGuard key.

package mesh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const certHeader = "veilplane-mesh-certificate v1"

// meshKey derives the cluster's mesh signing key from its master key.
func meshKey(master []byte, cluster string) (ed25519.PrivateKey, error) {
	if len(master) != 32 {
		return nil, errors.New("the master key must be 32 bytes")
	}
	if cluster == "" {
		return nil, errors.New("the mesh key needs the cluster id")
	}
	seed, err := hkdf.Key(sha256.New, master, nil, "veilplane mesh v1 "+cluster, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Cert is a mesh certificate's content.
type Cert struct {
	Cluster   string
	Node      string
	Role      string // control-plane or worker
	WireGuard [32]byte
	Address   netip.Addr
	Issued    time.Time
}

func (c Cert) text() []byte {
	return []byte(fmt.Sprintf("%s\ncluster: %s\nnode: %s\nrole: %s\nwireguard: %s\naddress: %s\nissued: %s\n",
		certHeader, c.Cluster, c.Node, c.Role, base64.StdEncoding.EncodeToString(c.WireGuard[:]), c.Address,
		c.Issued.UTC().Format(time.RFC3339)))
}

func validRole(r string) bool { return r == "control-plane" || r == "worker" }

// issue signs a certificate with the mesh key.
func issue(key ed25519.PrivateKey, c Cert) (string, error) {
	if !validRole(c.Role) || c.Node == "" || c.Cluster == "" || !c.Address.Is4() {
		return "", errors.New("a mesh certificate needs cluster, node, role (control-plane or worker) and an IPv4 address")
	}
	if c.Issued.IsZero() {
		c.Issued = time.Now()
	}
	text := c.text()
	return base64.RawURLEncoding.EncodeToString(text) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, text)), nil
}

// verifyCert checks the signature with the mesh key's public half and reads the certificate.
func verifyCert(root ed25519.PublicKey, encoded string) (Cert, error) {
	var c Cert
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return c, errors.New("not a mesh certificate")
	}
	text, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return c, errors.New("not a mesh certificate")
	}
	if len(root) != ed25519.PublicKeySize || !ed25519.Verify(root, text, sig) {
		return c, errors.New("not signed with this cluster's mesh key")
	}
	return parseCertText(text)
}

func parseCertText(text []byte) (Cert, error) {
	var c Cert
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	if len(lines) == 0 || lines[0] != certHeader {
		return c, errors.New("not a mesh certificate")
	}
	f := map[string]string{}
	for _, l := range lines[1:] {
		k, v, ok := strings.Cut(l, ": ")
		if !ok {
			return c, errors.New("malformed mesh certificate")
		}
		f[k] = v
	}
	c.Cluster, c.Node, c.Role = f["cluster"], f["node"], f["role"]
	wg, err := base64.StdEncoding.DecodeString(f["wireguard"])
	if err != nil || len(wg) != 32 {
		return c, errors.New("mesh certificate: bad WireGuard key")
	}
	copy(c.WireGuard[:], wg)
	if c.Address, err = netip.ParseAddr(f["address"]); err != nil || !c.Address.Is4() {
		return c, errors.New("mesh certificate: bad address")
	}
	if c.Issued, err = time.Parse(time.RFC3339, f["issued"]); err != nil {
		return c, errors.New("mesh certificate: bad time")
	}
	if c.Cluster == "" || c.Node == "" || !validRole(c.Role) {
		return c, errors.New("mesh certificate: missing cluster, node or role")
	}
	// the text must be exactly what text() writes, so there is one encoding per content
	if !bytes.Equal(c.text(), text) {
		return c, errors.New("mesh certificate: not in canonical form")
	}
	return c, nil
}

// MeshKey is the cluster's mesh signing key, derived from the master key.
func MeshKey(master []byte, cluster string) (ed25519.PrivateKey, error) {
	return meshKey(master, cluster)
}

// Issue signs a mesh certificate with the cluster's mesh key.
func Issue(key ed25519.PrivateKey, c Cert) (string, error) { return issue(key, c) }

// VerifyCert checks a mesh certificate against the public half of the mesh key.
func VerifyCert(root ed25519.PublicKey, encoded string) (Cert, error) {
	return verifyCert(root, encoded)
}
