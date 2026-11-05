// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/veilplane/veil/mesh"
	"github.com/veilplane/veil/proxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultAPI is the agent API of Veilplane.
const DefaultAPI = "https://api.veilplane.com"

// api is a client of the backend's agent API (OpenAPI group "agent").
type api struct {
	base    string
	roots   *x509.CertPool // nil: the system's
	http    *http.Client
	version string
}

// apiError is an answer other than 2xx.
type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%d %s", e.Status, e.Detail)
	}
	return fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status))
}

func statusOf(err error) int {
	var e *apiError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func loadRoots(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	return pool, nil
}

func newAPI(base, caFile, version string) (*api, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("the API address must be https://host[:port] (http only for development): %q", base)
	}
	roots, err := loadRoots(caFile)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	return &api{base: strings.TrimRight(base, "/"), roots: roots, http: &http.Client{Transport: tr}, version: version}, nil
}

// do sends in as JSON and decodes the answer into out. 304 is no error (out stays as it is).
func (a *api) do(ctx context.Context, method, path, token string, in, out any, header http.Header) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "veil/"+a.version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp, err
	}
	if resp.StatusCode == http.StatusNotModified {
		return resp, nil
	}
	if resp.StatusCode/100 != 2 {
		var problem struct{ Detail, Title string }
		json.Unmarshal(raw, &problem)
		return resp, &apiError{Status: resp.StatusCode, Detail: cmpOr(problem.Detail, problem.Title)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, fmt.Errorf("%s %s: unreadable answer: %v", method, path, err)
		}
	}
	return resp, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---------------------------------------------------------------- join and tokens

type joined struct {
	Cluster      string `json:"cluster"`
	Node         string `json:"node"`
	Role         string `json:"role"`
	MasterKey    string `json:"masterKey"` // create, receive or none
	InviteSecret string `json:"inviteSecret"`
}

func (a *api) join(ctx context.Context, code, node string, key ed25519.PrivateKey) (*joined, error) {
	msg := "veilplane join v1\n" + code + "\n" + node
	var out joined
	_, err := a.do(ctx, "POST", "/agent/v1/join", "", map[string]string{
		"code": code, "node": node,
		"publicKey": base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(msg))),
	}, &out, nil)
	return &out, err
}

type accessToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Role      string    `json:"role"`
}

func (a *api) token(ctx context.Context, cluster, node string, key ed25519.PrivateKey) (*accessToken, error) {
	now := time.Now().Unix()
	n := make([]byte, 16)
	rand.Read(n)
	nonce := hex.EncodeToString(n)
	msg := "veilplane token v1\n" + cluster + "\n" + node + "\n" + strconv.FormatInt(now, 10) + "\n" + nonce
	var out accessToken
	_, err := a.do(ctx, "POST", "/agent/v1/token", "", map[string]any{
		"cluster": cluster, "node": node, "time": now, "nonce": nonce,
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(msg))),
	}, &out, nil)
	return &out, err
}

// ---------------------------------------------------------------- config

// RemoteConfig is what the backend wants this agent to run.
type RemoteConfig struct {
	Cluster string `json:"cluster"`
	Node    string `json:"node"`
	Role    string `json:"role"`
	Backend struct {
		GRPC string `json:"grpc"`
		TLS  bool   `json:"tls"`
	} `json:"backend"`
	Features struct {
		Proxy struct {
			Enabled bool `json:"enabled"`
		} `json:"proxy"`
		Mesh struct {
			Enabled bool   `json:"enabled"`
			Prefix  string `json:"prefix"`
		} `json:"mesh"`
	} `json:"features"`
}

func (r *RemoteConfig) wants(feature string) bool {
	switch feature {
	case "proxy":
		return r.Features.Proxy.Enabled
	case "mesh":
		return r.Features.Mesh.Enabled
	}
	return false
}

// config asks for the config; with etag, the backend waits up to wait for a change and the
// answer is nil if there was none.
func (a *api) config(ctx context.Context, token, etag string, wait time.Duration) (*RemoteConfig, string, error) {
	h := http.Header{}
	if etag != "" {
		h.Set("If-None-Match", etag)
	}
	var out RemoteConfig
	resp, err := a.do(ctx, "GET", fmt.Sprintf("/agent/v1/config?wait=%d", int(wait.Seconds())), token, nil, &out, h)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}
	return &out, resp.Header.Get("ETag"), nil
}

// ---------------------------------------------------------------- tokens for gRPC and the API

// tokens keeps a current access token. It is the gRPC per-RPC credential of the agent's
// connection: every call carries "authorization: Bearer vt1....".
type tokens struct {
	api           *api
	cluster, node string
	key           ed25519.PrivateKey
	secure        bool // the connection uses TLS (the token must not travel in the clear)

	mu      sync.Mutex
	current *accessToken
	issued  time.Time
	revoked bool
}

// get returns a token that is valid for a while longer, fetching a new one when two thirds of
// the old one's lifetime are over.
func (t *tokens) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.current != nil && now.Before(t.issued.Add(t.current.ExpiresAt.Sub(t.issued)*2/3)) {
		return t.current.Token, nil
	}
	tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tok, err := t.api.token(tctx, t.cluster, t.node, t.key)
	if err != nil {
		if statusOf(err) == http.StatusForbidden {
			t.revoked = true
		}
		if t.current != nil && now.Before(t.current.ExpiresAt.Add(-30*time.Second)) {
			return t.current.Token, nil // the old one still works
		}
		return "", fmt.Errorf("access token: %w", err)
	}
	t.current, t.issued, t.revoked = tok, now, false
	return tok.Token, nil
}

func (t *tokens) isRevoked() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.revoked
}

func (t *tokens) setRevoked() {
	t.mu.Lock()
	t.revoked = true
	t.mu.Unlock()
}

func (t *tokens) forget() {
	t.mu.Lock()
	t.current = nil
	t.mu.Unlock()
}

func (t *tokens) expires() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return time.Time{}
	}
	return t.current.ExpiresAt
}

func (t *tokens) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	tok, err := t.get(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

func (t *tokens) RequireTransportSecurity() bool { return t.secure }

// dial opens the gRPC connection to the backend: TLS with the server certificate only (or none,
// for development), the identity in the access token. A proxy in front of the backend can end
// TLS: nothing depends on the connection itself.
func dial(addr string, useTLS bool, roots *x509.CertPool, tok *tokens) (*grpc.ClientConn, error) {
	target, resolverOpt, firstHost := proxy.Target(addr)
	creds := insecure.NewCredentials()
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{RootCAs: roots, ServerName: firstHost, MinVersion: tls.VersionTLS12})
	}
	opts := append(proxy.DialOptions(), grpc.WithTransportCredentials(creds), grpc.WithPerRPCCredentials(tok), resolverOpt)
	return grpc.Dial(target, opts...)
}

// ---------------------------------------------------------------- the mesh's backend

// meshBackend is the mesh's side of the agent API (mesh.Backend).
type meshBackend struct {
	api *api
	tok *tokens
}

func (m *meshBackend) Register(ctx context.Context, certificate string, endpoints []string) (*mesh.Registration, error) {
	t, err := m.tok.get(ctx)
	if err != nil {
		return nil, err
	}
	var out mesh.Registration
	_, err = m.api.do(ctx, "POST", "/agent/v1/mesh/register", t, map[string]any{"certificate": certificate, "endpoints": endpoints}, &out, nil)
	return &out, err
}

func (m *meshBackend) Peers(ctx context.Context, etag string) (*mesh.PeerList, string, error) {
	t, err := m.tok.get(ctx)
	if err != nil {
		return nil, "", err
	}
	h := http.Header{}
	if etag != "" {
		h.Set("If-None-Match", etag)
	}
	cctx, cancel := context.WithTimeout(ctx, configWait+30*time.Second)
	defer cancel()
	var out mesh.PeerList
	resp, err := m.api.do(cctx, "GET", fmt.Sprintf("/agent/v1/mesh/peers?wait=%d", int(configWait.Seconds())), t, nil, &out, h)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode == http.StatusNotModified {
		return nil, etag, nil
	}
	return &out, resp.Header.Get("ETag"), nil
}

func (m *meshBackend) Report(ctx context.Context, peers []mesh.PeerReport) error {
	t, err := m.tok.get(ctx)
	if err != nil {
		return err
	}
	_, err = m.api.do(ctx, "PUT", "/agent/v1/mesh/report", t, map[string]any{"peers": peers}, nil, nil)
	return err
}

func (m *meshBackend) Clock(ctx context.Context) (time.Time, error) {
	var out struct {
		UnixMicros int64 `json:"unixMicros"`
	}
	if _, err := m.api.do(ctx, "GET", "/agent/v1/clock", "", nil, &out, nil); err != nil {
		return time.Time{}, err
	}
	return time.UnixMicro(out.UnixMicros), nil
}
