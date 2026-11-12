#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# After removing the package. deb calls this with "remove", "purge", "upgrade", ...; rpm with the
# number of versions left (0: removal, 1: upgrade).
#
# Always on removal: forget the unit and the udev rule. Only on "apt purge":
#   - /etc/veil (agent.json, which may hold a join code),
#   - the repository entry of install.sh, unless veilctl still uses it,
#   - /var/lib/veil, but only after "veil leave" (the file "left" in it) or when the node never
#     joined. Otherwise it holds this node's identity and, on a control plane node, the cluster's
#     master key, possibly the only copy: it stays, with a note.
# rpm knows no purge: there, the README's "Removing a node completely" lists what to delete.
set -e

case "${1:-}" in
  remove | purge | 0) ;;
  *) exit 0 ;;
esac

if command -v systemctl > /dev/null 2>&1; then
  systemctl daemon-reload > /dev/null 2>&1 || true
fi
if command -v udevadm > /dev/null 2>&1; then
  udevadm control --reload > /dev/null 2>&1 || true
fi

[ "${1:-}" = purge ] || exit 0

rm -rf /etc/veil

if ! command -v veilctl > /dev/null 2>&1; then
  rm -f /etc/apt/sources.list.d/veil.list /etc/apt/keyrings/veil.asc
fi

state=/var/lib/veil
if [ -d "$state" ]; then
  if [ -e "$state/left" ] || [ ! -e "$state/identity.json" ]; then
    rm -rf "$state"
  else
    echo "veil: kept $state: this node never ran \"veil leave\"." >&2
    echo "veil: it holds the node's identity and, on a control plane node, the cluster's master key." >&2
    echo "veil: back up master.key if no other control plane node has it, then delete the directory." >&2
  fi
fi
exit 0
