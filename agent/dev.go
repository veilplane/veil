// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

//go:build veildev

package agent

// A development build (go build -tags veildev): it talks to any backend, trusts a CA of its own
// (apiCa) and, besides Veilplane's keys, the development key, whose private half the backend's
// tests and development setups use. Never for production: releases are built without the tag.
const devKey = "XBeqx5iAH1eKL3AtZPhV41gpLUBljpGsAjoEVZq2tsw="

func init() {
	devMode = true
	attestationKeys = append(append([]string{}, productionKeys...), devKey)
}
