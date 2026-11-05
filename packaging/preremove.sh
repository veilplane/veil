#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Before removing (not before an upgrade): stop and disable the agent. Its state in
# /var/lib/veil (keys, master key) stays; delete it yourself if the node leaves for good.
# deb calls this with "remove" or "upgrade", rpm with the number of versions left (0: removal).
set -e
command -v systemctl > /dev/null 2>&1 || exit 0
case "${1:-}" in
  remove | 0) systemctl disable --now veil.service > /dev/null 2>&1 || true ;;
esac
