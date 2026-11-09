#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Builds the deb and rpm packages of veil and veilctl for amd64 and arm64 from the static binaries
# in DIST (veil-linux-amd64, veil-linux-arm64, veilctl-linux-amd64, veilctl-linux-arm64) into
# DIST. Needs nfpm; veilctl's shell completions come from the binary for this machine.
#
#   packaging/build-packages.sh 1.2.3 dist
#
# With SIGNING_KEY (an armored GPG private key file) and NFPM_PASSPHRASE, all packages carry a
# signature (rpm: in the header, deb: an origin signature); without, they are unsigned (tests).
set -euo pipefail
version=${1:?version, e.g. 1.2.3}
dist=${2:?directory with the binaries}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
version=${version#v}
key=${SIGNING_KEY:-}

case $(uname -m) in
  x86_64) here=amd64 ;;
  aarch64 | arm64) here=arm64 ;;
  *) echo "no veilctl binary runs here ($(uname -m)) to write the completions" >&2; exit 1 ;;
esac
mkdir -p "$work/completions"
"$dist/veilctl-linux-$here" completion bash > "$work/completions/veilctl.bash"
"$dist/veilctl-linux-$here" completion zsh > "$work/completions/_veilctl"
"$dist/veilctl-linux-$here" completion fish > "$work/completions/veilctl.fish"

for arch in amd64 arm64; do
  for name in veil veilctl; do
    binary="$dist/$name-linux-$arch"
    [ -x "$binary" ] || { echo "missing $binary" >&2; exit 1; }
    config=packaging/nfpm.yaml
    [ "$name" = veilctl ] && config=packaging/nfpm-veilctl.yaml
    sed -e "s|\${ARCH}|$arch|g" -e "s|\${VERSION}|$version|g" -e "s|\${BINARY}|$binary|g" -e "s|\${SIGNING_KEY}|$key|g" \
      -e "s|\${COMPLETIONS}|$work/completions|g" "$config" > "$work/nfpm-$name-$arch.yaml"
    for format in deb rpm; do
      nfpm package --config "$work/nfpm-$name-$arch.yaml" --packager "$format" --target "$dist/"
    done
  done
done
ls -l "$dist"/*.deb "$dist"/*.rpm
