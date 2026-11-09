#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Installs the veil agent from the package repository and, with arguments, joins the node:
#
#   curl -fsSL https://packages.veilplane.com/install.sh | sudo sh                        install only
#   curl -fsSL https://packages.veilplane.com/install.sh | sudo sh -s -- join <code>      join a cluster
#   curl -fsSL https://packages.veilplane.com/install.sh | sudo sh -s -- join worker.invite
#   curl -fsSL https://packages.veilplane.com/install.sh | sudo sh -s -- try              a trial cluster
#
# It adds the signed repository (apt or dnf, as on the repository's start page), installs the
# package "veil", writes "join" into /etc/veil/agent.json and starts the agent. "try" first asks
# the API for a trial cluster (30 minutes, no account) and joins it. An agent.json that is already
# there is left alone: then set "join" in it yourself.
#
# Environment:
#   VEIL_PACKAGES  the package repository (default: https://packages.veilplane.com)
#   VEIL_API       the API for "try" (default: https://api.veilplane.com)
#   VEIL_CONFIG    the configuration directory (default: /etc/veil)
#
# POSIX sh on purpose: it runs before anything else is installed.
set -eu

REPO=${VEIL_PACKAGES:-https://packages.veilplane.com}
REPO=${REPO%/}
API=${VEIL_API:-https://api.veilplane.com}
API=${API%/}
CONFIG=${VEIL_CONFIG:-/etc/veil}

say() { printf '%s\n' "$*" >&2; }
die() { say "install: $*"; exit 1; }

# ---------------------------------------------------------------- what to do

action=install
arg=
case "${1:-}" in
  "") ;;
  join)
    [ $# -eq 2 ] || die "usage: ... sh -s -- join <code or invite file>"
    action=join arg=$2 ;;
  try)
    [ $# -eq 1 ] || die "usage: ... sh -s -- try"
    action=try ;;
  *) die "unknown command \"$1\" (join <code>, join <invite file>, try)" ;;
esac

# ---------------------------------------------------------------- checks

[ "$(uname -s)" = Linux ] || die "Linux only"
[ "$(id -u)" = 0 ] || die "run as root (curl ... | sudo sh -s -- ...)"
command -v curl > /dev/null 2>&1 || die "curl is needed"
command -v systemctl > /dev/null 2>&1 || die "systemd is needed (the package installs a systemd service)"

if [ "$action" = join ] && [ -f "$arg" ]; then
  invite=$arg # a file here: an invite for a worker, copied next to agent.json below
else
  invite=
fi
if [ "$action" != install ] && [ -s "$CONFIG/agent.json" ]; then
  die "$CONFIG/agent.json exists already; set \"join\" in it yourself, then: systemctl enable --now veil"
fi

# ---------------------------------------------------------------- install

if command -v apt-get > /dev/null 2>&1; then
  say "adding the apt repository $REPO"
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL --retry 3 -o /etc/apt/keyrings/veil.asc "$REPO/veil-packages.asc"
  echo "deb [signed-by=/etc/apt/keyrings/veil.asc] $REPO/deb ./" > /etc/apt/sources.list.d/veil.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq veil
elif command -v dnf > /dev/null 2>&1 || command -v yum > /dev/null 2>&1; then
  say "adding the dnf repository $REPO"
  curl -fsSL --retry 3 -o /etc/yum.repos.d/veil.repo "$REPO/rpm/veil.repo"
  if command -v dnf > /dev/null 2>&1; then dnf -y -q install veil; else yum -y -q install veil; fi
else
  die "neither apt nor dnf found; packages for Debian, Ubuntu, Fedora, RHEL, Rocky and Alma are at $REPO"
fi
say "installed: $(veil version 2>/dev/null || echo veil)"

# ---------------------------------------------------------------- trial

if [ "$action" = try ]; then
  say "asking $API for a trial cluster"
  answer=$(curl -fsS --retry 2 -X POST "$API/api/v1/trial") || die "no trial cluster now (one per address at a time, a few per day)"
  field() { printf '%s' "$answer" | sed -n "s/.*\"$1\" *: *\"\([^\"]*\)\".*/\1/p"; }
  arg=$(field joinCode)
  [ -n "$arg" ] || die "unexpected answer: $answer"
  say "trial cluster $(field cluster), until $(field expiresAt)"
  say "watch it live: $(field dashboardUrl)"
fi

# ---------------------------------------------------------------- join

if [ "$action" != install ]; then
  install -d -m 0755 "$CONFIG"
  if [ -n "$invite" ]; then
    name=$(basename "$invite")
    install -m 0600 "$invite" "$CONFIG/$name"
    arg=$name
  fi
  case $arg in
    *[\"\\]*) die "a join code or file name with \" or \\ in it is not valid" ;;
  esac
  umask 077
  printf '{\n  "join": "%s"\n}\n' "$arg" > "$CONFIG/agent.json"
  systemctl enable --now veil
  say "joining; see how it goes: veil status (or journalctl -u veil -f)"
else
  say "next: set \"join\" in $CONFIG/agent.json, then: systemctl enable --now veil"
fi
