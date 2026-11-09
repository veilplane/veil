// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------- paths

// Paths are the two directories the agent uses. Config is written by people (or veilctl) and
// only read by the agent; State belongs to the agent.
type Paths struct {
	Config string // default /etc/veil
	State  string // default /var/lib/veil
}

func (p Paths) ConfigFile() string { return filepath.Join(p.Config, "agent.json") }

// Lock is the status file: what the agent actually runs, rewritten whenever it changes.
func (p Paths) Lock() string { return filepath.Join(p.State, "veil.lock") }

func (p Paths) state(name string) string { return filepath.Join(p.State, name) }

// Files in the state directory.
const (
	identityFile = "identity.json" // who this node is, after joining
	deviceKey    = "device.key"    // Ed25519 seed (base64): the node's identity towards the backend
	masterKey    = "master.key"    // the cluster's master key (64 hex characters), control plane nodes only
	proxyState   = "proxy.state"   // verified checkpoints of the etcd proxy
	wgKey        = "wg.key"        // WireGuard private key (base64)
	meshFile     = "mesh.json"     // address and certificate in the mesh
	apiCAFile    = "api-ca.pem"    // the backend's CA from an invite file
)

// ---------------------------------------------------------------- agent.json

// Config is agent.json: what this node is allowed and how it runs things. The backend decides
// which features run; Allow decides which of them this node accepts.
type Config struct {
	// API is the agent API to join at, default https://api.veilplane.com (or the invite file's).
	// After joining, the agent uses the address the backend names for the cluster's region.
	API string `json:"api,omitempty"`
	// APICA: a PEM file with the CA of the backend's certificates (API and gRPC). Empty: the
	// system's CAs, or the one in the invite file.
	APICA string `json:"apiCa,omitempty"`
	// Node is this node's name in the cluster, default the host name (or the invite file's).
	Node string `json:"node,omitempty"`
	// Join: a join code (vp1....) or an invite file (a path, relative to the config directory).
	// Used once; after that the node is enrolled and this is ignored, until the node is revoked
	// and the value changes.
	Join string `json:"join,omitempty"`
	// Allow: the features the backend may switch on. Default: all ("proxy", "mesh").
	Allow *[]string   `json:"allow,omitempty"`
	Proxy ProxyConfig `json:"proxy"`
	Mesh  MeshConfig  `json:"mesh"`
}

type ProxyConfig struct {
	Listen       string   `json:"listen,omitempty"`    // default 127.0.0.1:2379
	OpsListen    string   `json:"opsListen,omitempty"` // default 127.0.0.1:9390, "off": none
	History      Duration `json:"history,omitempty"`   // default 10m
	TrustBackend bool     `json:"trustBackend,omitempty"`
	Verbose      bool     `json:"verbose,omitempty"`
}

type MeshConfig struct {
	Interface string `json:"interface,omitempty"` // default veil0
	Port      int    `json:"port,omitempty"`      // default: chosen once at random, 51820-52819
	Mode      string `json:"mode,omitempty"`      // auto (default), kernel or userspace
	MTU       int    `json:"mtu,omitempty"`       // default 1420
}

// Duration is a time.Duration written as "10m" in JSON.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

var features = []string{"proxy", "mesh"}

func (c *Config) allowed(feature string) bool {
	if c.Allow == nil {
		return true
	}
	for _, f := range *c.Allow {
		if f == feature {
			return true
		}
	}
	return false
}

// LoadConfig reads agent.json. A missing file is an empty configuration.
func LoadConfig(p Paths) (*Config, error) {
	c := &Config{}
	raw, err := os.ReadFile(p.ConfigFile())
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %v", p.ConfigFile(), err)
	}
	if c.Allow != nil {
		for _, f := range *c.Allow {
			if f != "proxy" && f != "mesh" {
				return nil, fmt.Errorf("%s: allow: unknown feature %q (proxy, mesh)", p.ConfigFile(), f)
			}
		}
	}
	return c, nil
}

// ---------------------------------------------------------------- identity

// Identity is who this node is, written after joining.
type Identity struct {
	API      string    `json:"api"`
	Cluster  string    `json:"cluster"`
	Node     string    `json:"node"`
	Role     string    `json:"role"` // control-plane or worker
	JoinedAt time.Time `json:"joinedAt"`
	Join     string    `json:"join"` // SHA-256 of the join value used, to notice a new one
}

func loadIdentity(p Paths) (*Identity, error) {
	raw, err := os.ReadFile(p.state(identityFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("%s: %v", identityFile, err)
	}
	return &id, nil
}

func joinHash(join string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(join)))
	return hex.EncodeToString(h[:8])
}

// ---------------------------------------------------------------- keys

func writeFileAtomic(name string, data []byte, perm os.FileMode) error {
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

func writeJSON(name string, v any, perm os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(name, append(raw, '\n'), perm)
}

func newDeviceKey() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

func encodeDeviceKey(k ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(k.Seed()) + "\n")
}

func loadDeviceKey(p Paths) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(p.state(deviceKey))
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not an Ed25519 key", deviceKey)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadMasterKey reads a master key file: 64 hex characters.
func LoadMasterKey(file string) ([]byte, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: must contain exactly 64 hex characters", file)
	}
	if st, err := os.Stat(file); err == nil && st.Mode().Perm()&0o077 != 0 {
		log.Printf("warning: master key file %s has mode %v; it should be 0600", file, st.Mode().Perm())
	}
	return key, nil
}

func encodeMasterKey(k []byte) []byte { return []byte(hex.EncodeToString(k) + "\n") }

// NewMasterKey is 32 random bytes.
func NewMasterKey() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

// wireGuardKeys: a new WireGuard key pair, base64.
func wireGuardKeys() (priv, pub string) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func wireGuardPublic(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ---------------------------------------------------------------- invite files
//
// A further control plane node gets the master key from an invite file that an existing node
// writes ("veil invite"). The file holds the master key encrypted with a key made of two random
// halves: one is in the file, the other one goes to the backend with the invite, which hands it
// out exactly once, to the node that redeems the code, and then deletes it.
//
//	key = HKDF-SHA256(file secret | server secret, "veil invite v1")
//	box = nonce | AES-256-GCM(key, nonce, master key, aad = "veil invite v1")
//
// The backend alone has one half and no box; the file alone is useless once the code was
// redeemed (or expired). Until then the file must be handled like a password.
//
// A worker's invite file holds no master key: its WireGuard key, its mesh certificate (signed by
// the inviting node with the cluster's mesh key) and the mesh key's public half.

const (
	InviteKind = "veilplane-invite"
	inviteInfo = "veil invite v1"
)

// Invite is an invite file.
type Invite struct {
	Kind      string    `json:"kind"`
	Version   int       `json:"version"`
	Role      string    `json:"role"` // control-plane or worker
	API       string    `json:"api"`
	APICA     string    `json:"apiCa,omitempty"` // PEM
	Cluster   string    `json:"cluster"`
	Node      string    `json:"node,omitempty"`
	InvitedBy string    `json:"invitedBy"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
	// control plane
	FileSecret string `json:"fileSecret,omitempty"`
	Box        string `json:"box,omitempty"`
	State      string `json:"state,omitempty"` // the inviting node's verified checkpoints
	// worker
	Address      string `json:"address,omitempty"`
	Prefix       string `json:"prefix,omitempty"`
	WireGuardKey string `json:"wireguardPrivateKey,omitempty"`
	Certificate  string `json:"certificate,omitempty"`
	MeshKey      string `json:"meshKey,omitempty"`
	ControlPlane string `json:"controlPlane,omitempty"` // the inviting node's mesh address
}

func loadInvite(file string) (*Invite, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("invite file: %v", err)
	}
	var inv Invite
	if err := json.Unmarshal(raw, &inv); err != nil || inv.Kind != InviteKind || inv.Version != 2 {
		return nil, fmt.Errorf("%s is not a Veilplane invite file", file)
	}
	need := map[string]string{"code": inv.Code, "cluster": inv.Cluster, "api": inv.API}
	if inv.Role == "worker" {
		need["node"], need["address"], need["prefix"] = inv.Node, inv.Address, inv.Prefix
		need["wireguardPrivateKey"], need["certificate"], need["meshKey"] = inv.WireGuardKey, inv.Certificate, inv.MeshKey
	} else if inv.Role == "control-plane" {
		need["fileSecret"], need["box"] = inv.FileSecret, inv.Box
	} else {
		return nil, fmt.Errorf("%s: unknown role %q", file, inv.Role)
	}
	for k, v := range need {
		if v == "" {
			return nil, fmt.Errorf("%s: no %s", file, k)
		}
	}
	return &inv, nil
}

func inviteKey(fileSecret, serverSecret []byte) (cipher.AEAD, error) {
	if len(fileSecret) != 32 || len(serverSecret) != 32 {
		return nil, errors.New("invite secrets must be 32 bytes each")
	}
	k, err := hkdf.Key(sha256.New, append(append([]byte(nil), fileSecret...), serverSecret...), nil, inviteInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// inviteSeal encrypts the master key: the file's half and box, and the backend's half.
func inviteSeal(master []byte) (fileSecret, box, serverSecret string, err error) {
	fs, ss := make([]byte, 32), make([]byte, 32)
	rand.Read(fs)
	rand.Read(ss)
	gcm, err := inviteKey(fs, ss)
	if err != nil {
		return "", "", "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(fs), enc(gcm.Seal(nonce, nonce, master, []byte(inviteInfo))), enc(ss), nil
}

// inviteOpen decrypts the master key of an invite file with the backend's half.
func inviteOpen(fileSecret, box, serverSecret string) ([]byte, error) {
	dec := base64.RawURLEncoding.DecodeString
	fs, err1 := dec(fileSecret)
	ss, err2 := dec(serverSecret)
	b, err3 := dec(box)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("malformed invite: %v", err)
	}
	gcm, err := inviteKey(fs, ss)
	if err != nil {
		return nil, err
	}
	if len(b) < gcm.NonceSize() {
		return nil, errors.New("malformed invite")
	}
	master, err := gcm.Open(nil, b[:gcm.NonceSize()], b[gcm.NonceSize():], []byte(inviteInfo))
	if err != nil || len(master) != 32 {
		return nil, errors.New("the invite does not decrypt (damaged file, or not the backend's half for it)")
	}
	return master, nil
}

// meshState is mesh.json: this node's place in the mesh.
type meshState struct {
	Address      string `json:"address"`
	Prefix       string `json:"prefix"`
	Certificate  string `json:"certificate"`
	MeshKey      string `json:"meshKey"`      // public half (base64)
	WireGuardKey string `json:"wireguardKey"` // public key (base64); the private one is in wg.key
	Port         int    `json:"port"`
}
