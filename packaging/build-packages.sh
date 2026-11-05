#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Builds the deb and rpm packages for amd64 and arm64 from the static binaries in DIST
# (veil-linux-amd64, veil-linux-arm64) into DIST. Needs nfpm.
#
#   packaging/build-packages.sh 1.2.3 dist
#
# With SIGNING_KEY (an armored GPG private key file) and NFPM_PASSPHRASE, both packages carry a
# signature (rpm: in the header, deb: an origin signature); without, they are unsigned (tests).
set -euo pipefail
version=${1:?version, e.g. 1.2.3}
dist=${2:?directory with the binaries}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
version=${version#v}
key=${SIGNING_KEY:-}
for arch in amd64 arm64; do
  binary="$dist/veil-linux-$arch"
  [ -x "$binary" ] || { echo "missing $binary" >&2; exit 1; }
  sed -e "s|\${ARCH}|$arch|g" -e "s|\${VERSION}|$version|g" -e "s|\${BINARY}|$binary|g" -e "s|\${SIGNING_KEY}|$key|g" \
    packaging/nfpm.yaml > "$work/nfpm-$arch.yaml"
  for format in deb rpm; do
    nfpm package --config "$work/nfpm-$arch.yaml" --packager "$format" --target "$dist/"
  done
done
ls -l "$dist"/*.deb "$dist"/*.rpm
