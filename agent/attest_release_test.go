// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

//go:build release

package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// The release workflow runs this (go test -tags release): a release without Veilplane's
// attestation key would trust no backend at all.
func TestProductionKeys(t *testing.T) {
	if len(productionKeys) == 0 {
		t.Fatal("agent/attest.go: productionKeys is empty: add the public half of Veilplane's attestation key")
	}
	for _, k := range productionKeys {
		if pub, err := base64.StdEncoding.DecodeString(k); err != nil || len(pub) != ed25519.PublicKeySize {
			t.Errorf("productionKeys: %q is not a base64 Ed25519 public key", k)
		}
		if k == "XBeqx5iAH1eKL3AtZPhV41gpLUBljpGsAjoEVZq2tsw=" { // dev.go's
			t.Error("productionKeys holds the development key")
		}
	}
}
