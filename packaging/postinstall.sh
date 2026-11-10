#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# After installing or upgrading: reload udev's rules and systemd; an upgrade restarts a running
# agent (which creates veil0 anew, now under the udev rule). A new
# installation does not start it: the node first needs "join" in /etc/veil/agent.json.
# deb calls this with "configure <old version>", rpm with the number of installed versions.
set -e
# the udev rule that keeps NetworkManager away from veil0, for the next time it is created
if command -v udevadm > /dev/null 2>&1; then udevadm control --reload-rules || true; fi
command -v systemctl > /dev/null 2>&1 || exit 0
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload || true
upgrade=0
case "${1:-}" in
  configure) [ -n "${2:-}" ] && upgrade=1 ;;
  [2-9]) upgrade=1 ;;
esac
if [ "$upgrade" = 1 ]; then
  systemctl try-restart veil.service || true
else
  echo "veil installed. Set \"join\" in /etc/veil/agent.json, then: systemctl enable --now veil"
fi
