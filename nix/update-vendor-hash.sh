#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Sets vendorHash in nix/package.nix to the hash of the Go dependencies (after a change to go.mod
# or go.sum). Needs Nix with flakes.
set -euo pipefail
cd "$(dirname "$0")/.."
sed -i 's|vendorHash = .*;|vendorHash = lib.fakeHash;|' nix/package.nix
out=$(nix --extra-experimental-features 'nix-command flakes' build .#veil --no-link 2>&1 || true)
hash=$(printf '%s\n' "$out" | sed -n 's/^ *got: *\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | head -n1)
if [ -z "$hash" ]; then
  printf '%s\n' "$out" >&2
  echo "no hash found in the output above" >&2
  exit 1
fi
sed -i "s|vendorHash = lib.fakeHash;|vendorHash = \"$hash\";|" nix/package.nix
echo "vendorHash = $hash"
