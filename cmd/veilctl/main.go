// SPDX-License-Identifier: FSL-1.1-ALv2
// Copyright 2026 Julian Siebert. See LICENSE.md.

// veilctl: Veilplane from the terminal. Organizations, members, clusters, join codes, nodes,
// API tokens, the audit log and trial clusters, through the management API. "veilctl --help"
// lists the commands; the package ctl has them.
package main

import (
	"os"

	"github.com/veilplane/veil/ctl"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3"
var version = "dev"

func main() {
	os.Exit(ctl.Main(os.Args[1:], version))
}
