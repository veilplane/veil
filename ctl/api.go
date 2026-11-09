// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultAPI is the management API of Veilplane.
const DefaultAPI = "https://api.veilplane.com"

// ---------------------------------------------------------------- the client

// Client talks to the management API, as a signed-in person (session) or with an API token.
type Client struct {
	Base    string
	Session string // "name=value" of the session cookie
	Token   string // vpt_...
	Trial   string // X-Veilplane-Trial, for the trial endpoints
	UA      string
	HTTP    *http.Client
}

// Problem is an error answer of the API (RFC 9457).
type Problem struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

func (p *Problem) Error() string {
	switch {
	case p.Detail != "":
		return p.Detail
	case p.Status == http.StatusUnauthorized:
		return "not signed in"
	case p.Title != "":
		return strings.ToLower(p.Title)
	}
	return fmt.Sprintf("the API answered %d %s", p.Status, http.StatusText(p.Status))
}

// IsStatus tells whether err is an API answer with that status.
func IsStatus(err error, status int) bool {
	var p *Problem
	return errors.As(err, &p) && p.Status == status
}

// Do sends a request. body (if not nil) goes as JSON; out (if not nil) gets the JSON answer, a
// *json.RawMessage gets it as it is. It returns the answer's headers.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) (http.Header, error) {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	req.Header.Set("User-Agent", c.UA)
	switch {
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case c.Session != "":
		req.Header.Set("Cookie", c.Session)
	}
	if c.Trial != "" {
		req.Header.Set("X-Veilplane-Trial", c.Trial)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			return nil, fmt.Errorf("cannot reach %s: %v", c.Base, ue.Err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return resp.Header, err
	}
	if resp.StatusCode >= 300 {
		p := &Problem{}
		if json.Unmarshal(raw, p) != nil || p.Status == 0 {
			p = &Problem{Status: resp.StatusCode}
			if s := strings.TrimSpace(string(raw)); s != "" && len(s) < 200 && !strings.HasPrefix(s, "<") {
				p.Detail = s
			}
		}
		p.Status = resp.StatusCode
		return resp.Header, p
	}
	if out != nil && len(raw) > 0 {
		if r, ok := out.(*json.RawMessage); ok {
			*r = append((*r)[:0], raw...)
		} else if err := json.Unmarshal(raw, out); err != nil {
			return resp.Header, fmt.Errorf("unexpected answer from %s %s: %v", method, path, err)
		}
	}
	return resp.Header, nil
}

func userAgent(version string) string {
	return fmt.Sprintf("veilctl/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)
}

// esc escapes one path segment.
func esc(s string) string { return url.PathEscape(s) }

// ---------------------------------------------------------------- configuration

// Config is veilctl's file: contexts (an API with its sign-in and default organization) and
// which one is current. It holds secrets (sessions, tokens), so it is written 0600.
type Config struct {
	Current  string              `json:"current,omitempty"`
	Contexts map[string]*Context `json:"contexts,omitempty"`

	path string
}

// Context is one API with its sign-in.
type Context struct {
	API     string    `json:"api,omitempty"`
	Email   string    `json:"email,omitempty"`
	Session string    `json:"session,omitempty"` // cookie "name=value"
	Token   string    `json:"token,omitempty"`   // API token, instead of a session
	Org     string    `json:"org,omitempty"`     // default organization
	Trial   *TrialRef `json:"trial,omitempty"`   // the trial cluster started here
}

// TrialRef is a trial cluster and the token to look at it.
type TrialRef struct {
	Cluster string    `json:"cluster"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
	Code    string    `json:"joinCode,omitempty"`
}

// configPath: VEILCTL_CONFIG, else <user config dir>/veilctl/config.json.
func configPath() (string, error) {
	if p := os.Getenv("VEILCTL_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no configuration directory (set VEILCTL_CONFIG): %v", err)
	}
	return filepath.Join(dir, "veilctl", "config.json"), nil
}

func loadConfig() (*Config, error) {
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	cfg := &Config{path: p, Contexts: map[string]*Context{}}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("%s: %v", p, err)
	}
	if cfg.Contexts == nil {
		cfg.Contexts = map[string]*Context{}
	}
	return cfg, nil
}

func (cfg *Config) save() error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.path), 0o700); err != nil {
		return err
	}
	tmp := cfg.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cfg.path)
}

// ---------------------------------------------------------------- the API's types (the fields shown)

type me struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	Name          string `json:"name"`
	Locale        string `json:"locale"`
}

type myOrg struct {
	Slug  string `json:"slug"`
	Name  string `json:"name"`
	Plan  string `json:"plan"`
	Admin bool   `json:"admin"`
}

type organization struct {
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	Status    string    `json:"status"`
	Admin     bool      `json:"admin"`
	CreatedAt time.Time `json:"createdAt"`
}

type member struct {
	UserID string    `json:"userId"`
	Email  string    `json:"email"`
	Name   string    `json:"name"`
	Admin  bool      `json:"admin"`
	Since  time.Time `json:"since"`
}

type invitation struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Admin     bool      `json:"admin"`
	InvitedBy string    `json:"invitedBy"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Link      string    `json:"link"`
}

type myInvitation struct {
	ID        string    `json:"id"`
	OrgName   string    `json:"orgName"`
	OrgSlug   string    `json:"orgSlug"`
	Admin     bool      `json:"admin"`
	InvitedBy string    `json:"invitedBy"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type invitationPreview struct {
	OrgName   string    `json:"orgName"`
	OrgSlug   string    `json:"orgSlug"`
	Email     string    `json:"email"`
	Admin     bool      `json:"admin"`
	InvitedBy string    `json:"invitedBy"`
	ExpiresAt time.Time `json:"expiresAt"`
	ForMe     bool      `json:"forMe"`
}

type features struct {
	Proxy bool `json:"proxy"`
	Mesh  bool `json:"mesh"`
}

type cluster struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Region            string     `json:"region"`
	CreatedAt         time.Time  `json:"createdAt"`
	Revision          int64      `json:"revision"`
	CompactRevision   int64      `json:"compactRevision"`
	Devices           int64      `json:"devices"`
	SizeBytes         int64      `json:"sizeBytes"`
	QuotaBytes        int64      `json:"quotaBytes"`
	DeletedAt         *time.Time `json:"deletedAt"`
	PurgeAt           *time.Time `json:"purgeAt"`
	Features          features   `json:"features"`
	RegionUnavailable bool       `json:"regionUnavailable"`
}

type joinCode struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// agentStatus is the part of an agent's report that veilctl shows; it may hold more.
type agentStatus struct {
	Version string `json:"version"`
	State   string `json:"state"`
	Error   string `json:"error"`
	Backend struct {
		Connected bool `json:"connected"`
	} `json:"backend"`
	Features map[string]*struct {
		Wanted   bool   `json:"wanted"`
		Allowed  bool   `json:"allowed"`
		State    string `json:"state"`
		Error    string `json:"error"`
		Listen   string `json:"listen"`
		Revision int64  `json:"revision"`
	} `json:"features"`
}

type device struct {
	Node      string     `json:"node"`
	FirstSeen time.Time  `json:"firstSeen"`
	LastSeen  *time.Time `json:"lastSeen"`
	RevokedAt *time.Time `json:"revokedAt"`
	Role      string     `json:"role"`
	Agent     *struct {
		ReportedAt time.Time   `json:"reportedAt"`
		Status     agentStatus `json:"status"`
	} `json:"agent"`
}

type meshView struct {
	Prefix  string `json:"prefix"`
	Members []struct {
		Node       string     `json:"node"`
		Role       string     `json:"role"`
		Address    string     `json:"address"`
		Registered bool       `json:"registered"`
		Online     bool       `json:"online"`
		Observed   string     `json:"observed"`
		Endpoints  []string   `json:"endpoints"`
		ReportedAt *time.Time `json:"reportedAt"`
		Peers      []struct {
			Node          string     `json:"node"`
			State         string     `json:"state"`
			Path          string     `json:"path"`
			LastHandshake *time.Time `json:"lastHandshake"`
		} `json:"peers"`
	} `json:"members"`
}

type apiToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"createdBy"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	Token      string     `json:"token"`
}

type auditEntry struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	ActorKind string    `json:"actorKind"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Details   string    `json:"details"`
	IP        string    `json:"ip"`
}

type region struct {
	Name string `json:"name"`
	Home bool   `json:"home"`
}

type session struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"userAgent"`
	Current    bool      `json:"current"`
}

type passkey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

type signedIn struct {
	UserID     string `json:"userId"`
	Email      string `json:"email"`
	NewAccount bool   `json:"newAccount"`
	HasPasskey bool   `json:"hasPasskey"`
}

type trial struct {
	Cluster      string    `json:"cluster"`
	ExpiresAt    time.Time `json:"expiresAt"`
	JoinCode     string    `json:"joinCode"`
	Command      string    `json:"command"`
	Token        string    `json:"token"`
	DashboardURL string    `json:"dashboardUrl"`
	Revision     int64     `json:"revision"`
	SizeBytes    int64     `json:"sizeBytes"`
	QuotaBytes   int64     `json:"quotaBytes"`
	MaxNodes     int       `json:"maxNodes"`
	Devices      []device  `json:"devices"`
}
