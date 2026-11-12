// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The agent works with Veilplane's backend only. An address check alone would not do: whoever
// runs a backend of their own also controls the machine, and can point api.veilplane.com at it
// (/etc/hosts) with a CA of their own in the system's store. So the backend proves itself: every
// access token comes with Veilplane's signature over the agent's random nonce (an attestation),
// made with a key only Veilplane's backend holds; its public half is built into veil. Without a
// valid one the agent does not take the token, and nothing runs. On top, the addresses must be
// https://*.veilplane.com and the system's CAs are the only ones trusted.
//
// Development builds (go build -tags veildev) and the tests talk to any backend, trust a CA of
// their own (apiCa) and the development key (dev.go).

// productionKeys: the public halves of Veilplane's attestation keys (Ed25519, base64 of the 32
// bytes). Two while a key is being replaced: add the new one, release, switch the backend, remove
// the old one with a later release. A release refuses to build without one (attest_release_test.go).
var productionKeys = []string{"iBF1udEdKs/vKEii0bL9D3rJGPNVftFy8QBHk+DdEIA="}

var (
	attestationKeys = productionKeys
	devMode         = false // dev.go (veildev builds) and the tests turn it on
)

// errNotVeilplane: the backend could not prove that it is Veilplane's.
var errNotVeilplane = errors.New("the backend could not prove that it is Veilplane's (no valid attestation): " +
	"veil works with Veilplane's backend only")

// attestationMessage is what the backend signs for an access token.
func attestationMessage(cluster, node, nonce string, expires time.Time) []byte {
	return []byte("veilplane attestation v1\n" + cluster + "\n" + node + "\n" + nonce + "\n" + strconv.FormatInt(expires.Unix(), 10))
}

// verifyAttestation checks Veilplane's signature on an access token's answer.
func verifyAttestation(cluster, node, nonce string, expires time.Time, attestation string) error {
	if len(attestationKeys) == 0 {
		return errors.New("this build of veil has no Veilplane attestation key, so it trusts no backend")
	}
	sig, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errNotVeilplane
	}
	msg := attestationMessage(cluster, node, nonce, expires)
	for _, k := range attestationKeys {
		pub, err := base64.StdEncoding.DecodeString(k)
		if err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return errNotVeilplane
}

// veilplaneHost: veilplane.com or a name below it.
func veilplaneHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "veilplane.com" || strings.HasSuffix(host, ".veilplane.com")
}

// checkAPI: the agent API must be https on a Veilplane name (development builds: anything).
func checkAPI(u *url.URL) error {
	if devMode {
		return nil
	}
	if u.Scheme != "https" || !veilplaneHost(u.Hostname()) {
		return fmt.Errorf("%s: veil talks to Veilplane's backend only (https://*.veilplane.com)", u.Redacted())
	}
	return nil
}

// checkGRPC: the backend's gRPC address must be a Veilplane name, with TLS.
func checkGRPC(addr string, useTLS bool) error {
	if devMode {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if !useTLS || !veilplaneHost(host) {
		return fmt.Errorf("gRPC %s: veil talks to Veilplane's backend only (*.veilplane.com, TLS)", addr)
	}
	return nil
}

// checkCA: a CA of one's own (apiCa, or an invite's) is for development builds only.
func checkCA(caFile string) error {
	if caFile != "" && !devMode {
		return fmt.Errorf("apiCa (%s) is for development builds only: veil trusts the system's CAs", caFile)
	}
	return nil
}
