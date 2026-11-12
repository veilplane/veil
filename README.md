# veil

The agent of [Veilplane](https://veilplane.com) and its tools. It runs in the background on
every node of a Kubernetes cluster and does what the node needs from Veilplane:

- **The etcd proxy** (control plane nodes): kube-apiserver's datastore, end-to-end encrypted.
  Veilplane hosts the data but can neither read it nor change it unnoticed.
- **The mesh**: WireGuard between all nodes of the cluster, control plane and workers, also
  behind NAT, without relays.
- Later perhaps more, such as running Kubernetes itself.

Which of these run on a node is decided by the backend (per cluster, in the dashboard) and
limited by the node: its `agent.json` says what the backend may switch on. The agent is
configured only declaratively, with files, and reports what it actually runs in a status file.

**veilctl** (section 10) is the command line for Veilplane itself: organizations, members,
clusters, join codes, nodes, API tokens and the audit log, from the terminal, on Linux, macOS
and Windows.

This repository is the public, source-available part of Veilplane: everything that runs on a
customer's machines. License: FSL-1.1-ALv2 (section 15).

## Contents

1. [Overview](#1-overview)
2. [Installing and running](#2-installing-and-running)
3. [Configuration: agent.json](#3-configuration-agentjson)
4. [The status file and metrics](#4-the-status-file-and-metrics)
5. [Joining a cluster](#5-joining-a-cluster)
6. [Talking to the backend](#6-talking-to-the-backend)
7. [What the backend can and cannot do](#7-what-the-backend-can-and-cannot-do)
8. [Files](#8-files)
9. [Commands](#9-commands)
10. [veilctl: Veilplane from the terminal](#10-veilctl-veilplane-from-the-terminal)
11. [Repository layout](#11-repository-layout)
12. [Building and testing](#12-building-and-testing)
13. [Continuous integration and releases](#13-continuous-integration-and-releases)
14. [Known limitations](#14-known-limitations)
15. [License](#15-license)

## 1. Overview

```
 node (customer)                                                    Veilplane (untrusted)
 +---------------------------------------------------+
 | kube-apiserver / k3s                              |
 |     | etcd v3, localhost                          |
 |     v                                             |    HTTPS: agent API (join, token,      +-----------+
 | veil agent ------ etcd proxy (control plane)  ---------> config, status, invites)  ------> |  backend  |
 |   |      \------- mesh: WireGuard interface      |    gRPC: etcd only              -----> |           |
 |   |                  ^                          |    (access token on every call)        +-----------+
 |   |                  | WireGuard, direct         |     may pass a proxy that ends TLS           ^
 |   |                  v                          |                                              | UDP: reflector
 | /etc/veil/agent.json    (people, veilctl)         |                                              | (mesh only,
 | /var/lib/veil/          (the agent: keys, state)  |                                              |  direct)
 | /var/lib/veil/veil.lock (status, for veilctl)     |
 +---------------------------------------------------+
```

The agent's loop:

1. **Join.** A node that is not enrolled yet joins with the join code or invite file named in
   `agent.json`. It creates its device key (Ed25519) on the node; the backend only ever gets
   the public half.
2. **Token.** The agent gets a short-lived access token (15 minutes) with a request signed by
   the device key, and a new one before it expires. The token is the node's identity on every
   agent API request and on the etcd proxy's gRPC calls. Nothing depends on TLS client
   certificates, so a proxy in front of the backend can end TLS.
3. **Config.** The agent asks the backend what to run. The request waits (long polling) until
   the answer differs from what the agent has, so changes in the dashboard arrive within a
   second.
4. **Run.** It starts and stops the etcd proxy and the mesh to match, unless `agent.json`
   refuses a feature.
5. **Report.** It writes the status file on every change and sends the same to the backend,
   which shows it in the dashboard.

Details of the two features: [proxy/README.md](proxy/README.md) (encryption, the verified
replica, checkpoints, the threat model) and [mesh/README.md](mesh/README.md) (certificates,
hole punching, status).

## 2. Installing and running

Every release has deb and rpm packages for amd64 and arm64 (section 13): they install the
binary as `/usr/bin/veil`, the systemd unit and `/etc/veil`, and depend on iproute2. The
package repository keeps them up to date with the system's other packages. In one step, it
adds the repository, installs veil and joins the node (`packaging/install.sh`, served by the
repository; `-- try` instead joins a trial cluster, no arguments only installs):

```sh
curl -fsSL https://packages.veilplane.com/install.sh | sudo sh -s -- join vp1.mzxw6ytboi3tcnzrgq2tmmzz
```

By hand, the repository's page shows the same commands with its address:

```sh
# Debian, Ubuntu
install -d -m 0755 /etc/apt/keyrings
curl -fsSLo /etc/apt/keyrings/veil.asc https://packages.veilplane.com/veil-packages.asc
echo "deb [signed-by=/etc/apt/keyrings/veil.asc] https://packages.veilplane.com/deb ./" > /etc/apt/sources.list.d/veil.list
apt update && apt install veil

# Fedora, RHEL, Rocky, Alma
curl -fsSLo /etc/yum.repos.d/veil.repo https://packages.veilplane.com/rpm/veil.repo
dnf install veil
```

A single package from a release works too (`apt install ./veil_1.2.3-1_amd64.deb`,
`dnf install ./veil-1.2.3-1.x86_64.rpm`). Then:

```sh
echo '{"join": "vp1.mzxw6ytboi3tcnzrgq2tmmzz"}' > /etc/veil/agent.json   # the join code from the dashboard
systemctl enable --now veil
```

An upgrade restarts a running agent (section "Updating and removing" below has the rest).

On **NixOS**, the flake has the package and a module:

```nix
# flake.nix of the machine: inputs.veil.url = "github:veilplane/veil/v1.2.3";
imports = [ veil.nixosModules.default ];
services.veil = {
  enable = true;
  settings.join = "/run/secrets/veil.invite";   # agent.json as Nix; never a code or invite in the store
};
```

`nix run github:veilplane/veil/v1.2.3 -- version` runs it anywhere with Nix. Keep join codes and
invite files out of the Nix store (it is readable by everyone on the machine): `settings.join`
points to a file you put there yourself, or one from sops-nix or agenix.

Without a package, the agent is one static binary and a systemd unit:

```sh
install -m 755 veil-linux-amd64 /usr/bin/veil
install -m 644 veil.service /etc/systemd/system/veil.service
install -d -m 755 /etc/veil
echo '{"join": "vp1.mzxw6ytboi3tcnzrgq2tmmzz"}' > /etc/veil/agent.json   # the join code from the dashboard
systemctl daemon-reload && systemctl enable --now veil
veil status
```

The agent takes nothing but the two directories (flags or environment):

| Flag | Environment | Default | Content |
|---|---|---|---|
| `-config` | `VEIL_CONFIG` | `/etc/veil` | `agent.json`, and invite files if you like; only read by the agent |
| `-state` | `VEIL_STATE` | `/var/lib/veil` | the agent's own files (section 8) and its status file |

It runs as root: the mesh creates a network interface. It must run on the node, not inside
the Kubernetes cluster: the API server cannot start without the etcd proxy. The unit
(`packaging/veil.service`) orders it before `k3s.service` and `kubelet.service`.

Only one agent can use a state directory at a time (it holds a lock on the directory).

### Updating and removing

**Updating** is the system's package manager: `apt update && apt upgrade` or `dnf upgrade`. The
package restarts a running agent; Kubernetes keeps running meanwhile (the API server waits for
its etcd for a moment). The repository's metadata is valid for an hour, so `dnf` sees a new
release within that time; `dnf upgrade --refresh` looks at once. Without a package: replace
`/usr/bin/veil` and `systemctl restart veil`. On NixOS: a new tag in the flake's input.

**Removing the package** (`apt remove veil`, `dnf remove veil`) stops and disables the agent and
nothing else: `/etc/veil` and `/var/lib/veil` stay, so installing it again carries on as before.
`apt purge veil` also deletes `/etc/veil` and the repository entry of `install.sh` (unless
veilctl is still installed), and `/var/lib/veil`, but the last one only if the node left the
cluster with `veil leave` first (or never joined). Otherwise it stays, with a note: it holds the
node's identity and, on a control plane node, the cluster's master key, perhaps its only copy.
rpm has no purge; there, delete these by hand (below).

**Removing a node completely**, in this order:

1. Kubernetes first, while the node is still a member: drain it and remove it from the cluster
   (`kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`, `kubectl delete node
   <node>`), then uninstall it (k3s: `k3s-uninstall.sh` or `k3s-agent-uninstall.sh`). A control
   plane node's API server needs the etcd proxy until it is stopped.
2. `veil leave`: the backend refuses the node from then on and the agent stops. On the **last
   control plane node** of a cluster, first copy `/var/lib/veil/master.key` somewhere safe if the
   cluster's data should stay readable: without it, nobody can decrypt it, Veilplane neither.
3. Remove the package: `apt purge veil`, or `dnf remove veil` and then
   `rm -rf /etc/veil /var/lib/veil`.
4. What is left: the repository entry if nothing else uses it (`/etc/apt/sources.list.d/veil.list`
   and `/etc/apt/keyrings/veil.asc`, or `/etc/yum.repos.d/veil.repo`), a firewall rule you opened
   for the mesh port, and on your own computer veilctl's session (`~/.config/veilctl`).

The mesh interface `veil0` disappears when the agent stops.

## 3. Configuration: agent.json

```json
{
  "join": "vp1.mzxw6ytboi3tcnzrgq2tmmzz",
  "node": "cp-1",
  "allow": ["proxy", "mesh"],
  "proxy": { "listen": "127.0.0.1:2379", "opsListen": "127.0.0.1:9390" },
  "mesh": { "interface": "veil0", "mode": "auto" },
  "metrics": { "listen": "127.0.0.1:9391" }
}
```

Every field is optional; an empty file (or none) is valid and leaves the node waiting for a
`join`.

| Field | Default | Meaning |
|---|---|---|
| `api` | `https://api.veilplane.com`, or the invite file's | the agent API to join at, always `https://` and a name under `veilplane.com` (section 6). The backend may send the join on to the cluster's region and name that region's API in its answer; the agent stores it in `identity.json` and uses it from then on |
| `apiCa` | the system's CAs | a PEM file with the CA of the backend's TLS certificates. Development builds only (section 12); a released agent refuses to start with it |
| `node` | the host name, or the invite file's | the node's name in the cluster: lower case letters, digits, `-` and `.` |
| `join` | | a join code (`vp1....`) or an invite file (a path, relative to the config directory) |
| `allow` | `["proxy", "mesh"]` | the features the backend may switch on. `[]` refuses everything. |
| `proxy.listen` | `127.0.0.1:2379` | where kube-apiserver connects (plaintext gRPC: keep it local) |
| `proxy.opsListen` | `127.0.0.1:9390` | `/healthz`, `/readyz`, `/metrics`, `/state`, `/leave` of the proxy; `"off"` disables |
| `proxy.history` | `10m` | verified history kept in memory; longer than the API server's compaction interval |
| `proxy.trustBackend` | `false` | accept the backend's state without verification, once, to recover (proxy/README.md, section 8) |
| `proxy.verbose` | `false` | log every request with its plaintext key (development only) |
| `mesh.interface` | `veil0` | the WireGuard interface |
| `mesh.port` | random, 51820-52819, kept | the WireGuard UDP port |
| `mesh.mode` | `auto` | `kernel`, `userspace` (wireguard-go) or `auto` (kernel if available) |
| `mesh.mtu` | `1420` | |
| `metrics.listen` | `127.0.0.1:9391` | the agent's Prometheus metrics, `/metrics` (section 4); `"off"` disables |

Unknown fields are an error, so that a typo (`"alow"`) does not silently allow everything. The
agent notices changes to the file by itself, within a second: a changed `allow` starts or stops
features, a changed `proxy` or `mesh` section restarts that feature, a changed `metrics.listen`
moves the metrics address.

`join` is used once. After joining, the node's identity is in the state directory and `join` is
ignored, until the node is revoked: then a **new** `join` value makes the agent forget the old
identity and join again (section 5).

## 4. The status file and metrics

`/var/lib/veil/veil.lock` is what the agent actually runs, as JSON, rewritten atomically on
every change and at least every 30 seconds. It is how veilctl, monitoring or a person looks at
the agent without talking to it; `veil status` prints it for people.

```json
{
  "version": "v1.0.0",
  "pid": 812,
  "updated": "2026-11-02T16:37:26Z",
  "state": "running",
  "cluster": "k7f3m2x9q1ab",
  "node": "cp-1",
  "role": "control-plane",
  "api": "https://api.veilplane.com",
  "backend": {
    "connected": true,
    "grpc": "grpc.veilplane.com:443",
    "lastContact": "2026-11-02T16:37:01Z",
    "tokenExpires": "2026-11-02T16:51:56Z",
    "configEtag": "\"dd118f2d3b122ebdea87ada8\""
  },
  "features": {
    "proxy": { "wanted": true, "allowed": true, "state": "running", "listen": "127.0.0.1:2379", "revision": 4711 },
    "mesh":  { "wanted": true, "allowed": false, "state": "refused", "error": "agent.json does not allow it" }
  }
}
```

| Field | Values |
|---|---|
| `state` | `starting`, `joining` (no identity yet, or the join failed: see `error`), `running`, `revoked` (the backend refuses the node), `error`, `stopped` |
| `features.*.wanted` / `allowed` | what the backend wants / what `agent.json` allows |
| `features.*.state` | `off`, `refused` (wanted, not allowed), `starting`, `running`, `error` (see `error`) |
| `features.proxy` | `listen`, `revision` (newest verified revision) |
| `features.mesh.mesh` | address, interface, WireGuard mode, public address, and every peer with its state and path (mesh/README.md, section 8) |

`updated` older than a minute, or a `pid` that does not run, means the agent is not running.
The file holds nothing secret (mode 644).

### Metrics (Prometheus, Grafana)

Every node, workers too, serves its metrics on `http://127.0.0.1:9391/metrics` (Prometheus'
text format; `metrics.listen` in `agent.json` moves it or turns it off). It holds what the
status file holds, as numbers, plus the etcd proxy's own series (the same as on the proxy's ops
address, `127.0.0.1:9390/metrics`):

| Metric | |
|---|---|
| `veil_agent_info{version,node,cluster,role}` | always 1: join on `instance` to name the node in queries |
| `veil_agent_state{state}`, `veil_agent_feature_state{feature,state}` | 1 for the current state |
| `veil_agent_backend_connected`, `veil_agent_backend_last_contact_timestamp_seconds`, `veil_agent_token_expiry_timestamp_seconds` | the connection to the backend |
| `veil_mesh_up`, `veil_mesh_warnings`, `veil_mesh_interface_repairs_total` | the mesh on this node, what gets in its way, how often its interface had to be put back |
| `veil_mesh_peers{state}`, `veil_mesh_peer_up{peer}`, `veil_mesh_peer_state{peer,state}`, `veil_mesh_peer_path{peer,path}` | every peer: `connected`, `blocked` (a live handshake, but probes get no answer), `trying`, `unreachable`, `refused` |
| `veil_mesh_peer_rtt_seconds{peer}`, `veil_mesh_peer_probes_total`, `veil_mesh_peer_probe_answers_total` | the probes' round trip and losses (mesh/README.md, section 8) |
| `veil_mesh_peer_receive_bytes_total`, `veil_mesh_peer_transmit_bytes_total`, `veil_mesh_peer_last_handshake_timestamp_seconds` | WireGuard's counters per peer |
| `veil_replica_revision`, `veil_replica_failed`, `veil_grpc_requests_total{method,code}`, `veil_watch_streams`, ... | the etcd proxy (control plane nodes) |

The address is local by default: the series name nodes and peers. For a Prometheus elsewhere,
listen on the mesh address (`"listen": "10.200.0.1:9391"`, reachable from the cluster's other
nodes only) or on all addresses behind a firewall. In Kubernetes, a scrape job for the nodes:

```yaml
scrape_configs:
  - job_name: veil
    kubernetes_sd_configs: [{ role: node }]
    relabel_configs:
      - source_labels: [__meta_kubernetes_node_address_InternalIP]
        target_label: __address__
        replacement: $1:9391
```

**Grafana**: `grafana/veil.json` (installed as `/usr/share/doc/veil/grafana-dashboard.json`) is a
dashboard for all of it: nodes and their state, the round trips and losses between nodes, mesh
traffic, revisions and etcd requests per node, with filters for cluster and node. Import it in
Grafana (Dashboards, New, Import) and choose the Prometheus data source.

## 5. Joining a cluster

**The first node** of a cluster (a control plane node) joins with a join code from the
dashboard or the management API. The backend answers "create": the agent creates the cluster's
master key (32 random bytes) in its state directory. It never leaves the node except in invite
files.

**Further control plane nodes** join with an invite file from a node that already runs:

```sh
veil invite -node cp-2 -o cp-2.invite          # on cp-1; the file has mode 600
# copy it to cp-2 like a password, then on cp-2:
echo '{"join": "cp-2.invite"}' > /etc/veil/agent.json
```

The file holds the master key, encrypted with a key of which one half is in the file and the
other half went to the backend with the invite. The backend hands its half out once, to the node
that redeems the code. Neither half alone opens anything; a used or expired file is worthless.
The file also carries cp-1's verified checkpoints, so that cp-2's proxy can check the backend
from its first start (proxy/README.md, sections 3 and 8).

**Workers** run only the mesh. Their invite holds no master key:

```sh
veil invite -worker -node worker-1 -o worker-1.invite    # on a control plane node
```

The control plane node creates the worker's WireGuard key and signs its mesh certificate with
the cluster's mesh key (derived from the master key). The worker's access token opens the mesh
service only; the backend refuses it on the etcd API.

**Leaving and revocation.** `veil leave` unenrolls the node: the proxy removes its checkpoint
record, the backend refuses the node from then on, and the agent stops everything within
seconds (state `revoked`). Revoking the device in the dashboard has the same effect. To join
again, put a new join code or invite file into `agent.json`: the agent forgets the old identity
and joins anew. A first node that joins a new cluster refuses to overwrite an existing
`master.key`: move it away first, on purpose.

## 6. Talking to the backend

The agent talks to the backend in two ways, both outbound only:

- **HTTPS and JSON** for everything the agent itself needs: joining, access tokens, what to
  run, its status, invites and the mesh. Changes (a feature switched in the dashboard, a new
  mesh member) reach the agent within a second, because it keeps a request open until something
  changes.
- **gRPC for the etcd API only**, because that is what kube-apiserver speaks: the etcd proxy
  passes the API server's requests on, encrypted, with the node's access token on every call.

**Identity.** The node's device key never leaves it. With a request signed by that key the agent
gets a short-lived access token, and a new one before it expires; every request carries it.
Nothing depends on TLS client certificates: TLS checks only the server's certificate, and it may
end at a proxy in front of the backend. A revoked node is refused at once, not only when its
token expires, and its agent stops everything.

**Only Veilplane's backend.** A released agent works with Veilplane's backend and no other.
Every access token comes with an attestation: Veilplane's Ed25519 signature over the cluster,
the node, a random nonce the agent chose for this request and the token's expiry. The public
half of that key is built into veil (`productionKeys` in `agent/attest.go`); the private half is
only on Veilplane's backend. Without a valid attestation the agent takes no token, and nothing
runs. Pointing `api.veilplane.com` at another server (`/etc/hosts` and a CA of one's own) does
not help: that server cannot sign. On top, the agent API must be `https://` under
`veilplane.com`, redirects too, the gRPC address a name under `veilplane.com` with TLS, and only
the system's CAs are trusted (`apiCa` and the CA in invite files are ignored or refused).
Development builds (section 12) drop these checks and trust a public development key instead.

Requests that wait for changes return after 50 seconds at most, so proxies on the way do not
cut them off. One exception to "through any proxy": the mesh learns a node's public address
from UDP packets, which go to an address of their own.

## 7. What the backend can and cannot do

The agent follows the backend in exactly one way: it switches features on and off, within what
`agent.json` allows. The backend cannot:

- get the master key, the device key or a WireGuard private key: they are created on the nodes
  and never sent anywhere (invite files go from node to node, through the customer's hands);
- read or change cluster data unnoticed: the proxy encrypts and verifies everything
  (proxy/README.md);
- add a member to the mesh or swap a member's key: every node checks every member's certificate
  against the cluster's mesh key (mesh/README.md);
- make the agent run commands, change its configuration, switch off a check or run a feature
  that `agent.json` does not allow. There is no such call.

What it can: refuse service, switch the features off, see metadata (which nodes, when, how
much, who reaches whom). Future features that act on the node (running Kubernetes) will stay
declarative, limited by `agent.json` in the same way.

## 8. Files

In the state directory (`/var/lib/veil`, mode 700):

| File | Mode | Content |
|---|---|---|
| `identity.json` | 600 | cluster, node, role, API, when it joined |
| `device.key` | 600 | Ed25519 seed (base64): the node's identity towards the backend |
| `master.key` | 600 | the cluster's master key (64 hex characters), control plane nodes only |
| `proxy.state` | 600 | the etcd proxy's verified checkpoints |
| `wg.key` | 600 | the WireGuard private key (base64) |
| `mesh.json` | 600 | mesh address, network, certificate, the public half of the mesh key, port |
| `api-ca.pem` | 644 | the backend's CA from an invite file, if it had one (development builds) |
| `left` | 600 | written by `veil leave`: the node left, its state may go (`apt purge` deletes it then) |
| `veil.lock` | 644 | the status file (section 4) |

Whoever has a copy of `master.key` can decrypt the cluster's data as the backend stores it, and
with `device.key` act as the node until it is revoked. Keep the directory out of backups that
are less protected than the node.

## 9. Commands

| Command | |
|---|---|
| `veil agent` | runs the agent (systemd) |
| `veil status [-json]` | the status file, for people or as it is |
| `veil invite -o FILE [-node NAME] [-worker] [-ttl 24h]` | an invite file for one more node (on a control plane node, next to the running agent) |
| `veil leave` | unenrolls this node |
| `veil version` | |

Every command takes `-config` and `-state` (or `VEIL_CONFIG`, `VEIL_STATE`).

## 10. veilctl: Veilplane from the terminal

`veilctl` does what the dashboard does, through the management API: organizations, members and
invitations, clusters (create, delete and restore, features, join codes, nodes, the mesh), API
tokens, the audit log, your account and sessions, and trial clusters. It is one static binary
without dependencies for Linux, macOS and Windows (amd64, arm64).

**Installing.** Linux: the package `veilctl` from the same repository as veil (section 2):
`apt install veilctl` or `dnf install veilctl`, with shell completions. macOS, Windows: the
binary from the release (`veilctl-darwin-arm64`, `veilctl-windows-amd64.exe`, ...), or Nix:
`nix run github:veilplane/veil#veilctl`.

```sh
veilctl login                                  # sign in with an e-mail link
veilctl orgs create "Acme Inc." --slug acme
veilctl clusters create web --region eu
veilctl join-code web                          # the code, and the command for the first node
veilctl clusters devices web --watch           # the nodes and what their agents run
veilctl clusters features web --mesh on
veilctl tokens create ci --expires 90d         # for scripts: VEILCTL_TOKEN=... veilctl ...
veilctl trial                                  # a cluster for 30 minutes, no account
```

How it behaves:

- **Commands** are *noun verb* (`clusters create`), flags may come anywhere, every command has
  `--help` with examples; a typo gets a "did you mean". A group alone runs its list
  (`veilctl clusters`). Clusters are named by id or name; ids shown shortened (sessions,
  tokens) work shortened.
- **Signing in**: `veilctl login` sends a sign-in link; copy it from the mail without opening it
  and paste it (opening it uses it up and signs in the browser instead). The session is kept in
  the configuration file (`<config dir>/veilctl/config.json`, mode 0600, or `VEILCTL_CONFIG`).
  For scripts and CI, an API token of one organization: `VEILCTL_TOKEN` and `--org` (or
  `veilctl login --token ... --org ...`).
- **Organization**: with one, it is used by itself; with several, `veilctl orgs use ORG` or
  `--org` (`VEILCTL_ORG`).
- **Contexts**: several APIs or sign-ins side by side (`veilctl login --context staging --api
  URL`, `veilctl context use staging`, `--context`).
- **Output**: tables for people, colors only on a terminal (not with `NO_COLOR` or
  `--no-color`); `--json` prints the API's answer as it is, for scripts. Data goes to stdout,
  messages to stderr: `CODE=$(veilctl join-code web)` gets only the code.
- **Safety**: deleting and revoking ask for the name of what goes; without a terminal they need
  `--yes`.
- **Completion**: `veilctl completion bash|zsh|fish` (installed by the package); it completes
  commands, flags and also clusters, nodes, organizations, members and tokens, asking the API.

| Command | |
|---|---|
| `login`, `logout`, `whoami` | sign in (e-mail link or API token), out, and who you are |
| `trial [start\|status\|end]` | a trial cluster without an account |
| `clusters [list\|create\|show\|rename\|delete\|restore]` | clusters |
| `clusters features CLUSTER --proxy on\|off --mesh on\|off` | what the agents run |
| `join-code CLUSTER [--node NAME]` | a join code for the first node |
| `clusters devices CLUSTER [NODE] [--watch]` | the nodes, their agents' reports |
| `clusters revoke CLUSTER NODE`, `clusters mesh CLUSTER` | revoke a node; who reaches whom |
| `orgs [list\|use\|create\|show\|update\|delete]` | organizations |
| `members [list\|invite\|invitations\|withdraw\|promote\|demote\|remove\|leave]` | members |
| `invitations [list\|show\|accept\|decline]` | invitations for you |
| `tokens [list\|create\|delete]`, `audit [--all]` | API tokens, the audit log |
| `me`, `sessions`, `passkeys`, `context` | your account, where you are signed in, contexts |
| `regions`, `completion SHELL`, `version` | |

The management API's OpenAPI description is at `https://api.veilplane.com/v1/spec.yml`.
Passkeys can be listed and deleted here; creating one needs a browser (the dashboard).

## 11. Repository layout

| Path | Content |
|---|---|
| `cmd/veil/` | the command |
| `cmd/veilctl/`, `ctl/` | veilctl: `cli.go` (commands, flags, help, completion), `api.go` (the API client, configuration, the API's types), `commands.go` (every command), `output.go` (tables, colors, questions) |
| `agent/` | the agent: `agent.go` (loop, features, status), `api.go` (agent API, tokens, gRPC connection), `files.go` (agent.json, keys, invite files), `tools.go` (invite, leave, status) |
| `proxy/` | the etcd proxy, with its own README |
| `mesh/` | the mesh, with its own README |
| `grafana/veil.json` | the Grafana dashboard for the metrics (section 4) |
| `packaging/` | the systemd unit; deb and rpm of veil and veilctl: nfpm configurations, install and removal scripts, `build-packages.sh`; `build-repo.sh` for the apt and dnf repository; `install.sh`, served by it |
| `flake.nix`, `nix/` | the Nix package and the NixOS module; `nix/update-vendor-hash.sh` after a change to the Go dependencies |

## 12. Building and testing

Go 1.24 or newer, Linux (veilctl also builds and runs on macOS and Windows).

```sh
go mod tidy                                                   # fills go.sum
go build -o veil ./cmd/veil
go build -o veilctl ./cmd/veilctl
go test ./...                                                 # unit tests
E2E_ETCD_DIR=/path/to/etcd-release go test -race ./...        # + the proxy's attack tests against a real etcd
go build -tags veildev -o veil ./cmd/veil                     # development build (below)
go test -tags release -run TestProductionKeys ./agent         # fails until the production key is built in
```

**Development builds.** A plain build only works with Veilplane's backend (section 6). To run
the agent against a backend on your own machine, build it with `-tags veildev` (`agent/dev.go`):
it then talks to any address, plain HTTP and gRPC without TLS included, takes `apiCa` and the CA
in invite files, and trusts the development attestation key, whose private half is public on
purpose (the backend's tests use it). Never ship such a build. Released binaries, packages and
the Nix package are built without the tag, and the release workflow first checks that a
production key is built in and that it is not the development key.

**Unit tests** (`agent/`) run agents against a fake backend: joining with a code, an invite and
a worker invite (and that a used invite gives nothing), the allowlist (also changed while
running), the backend switching a feature off within the long poll, revocation and joining
again with a new code (and the `left` marker), the attestation (a token without it, or a backend
outside `veilplane.com`, is refused), the metrics, the status report, one agent per state directory, unknown fields in
`agent.json`. veilctl's tests (`ctl/`) run it against a fake management API: signing in (the
session kept 0600), tables and JSON, clusters by name and typos, features, join codes on stdout,
confirmation before deleting, API tokens, usage errors, help, completion.

Releases are also tested end to end together with the backend (k3s on the etcd proxy, the mesh
behind real NAT); those tests are not part of this repository.

## 13. Continuous integration and releases

`.github/workflows/test.yml`: module verification, tidy check, formatting, vet, license
headers, unit and attack tests with the race detector (against etcd), builds for amd64 and
arm64 (veilctl also for macOS and Windows), 60 seconds of fuzzing per target of the proxy, the deb and rpm packages (unsigned; the
deb is installed and removed again), and the Nix flake (the package builds, the NixOS module
evaluates).

Releases: push a version tag (`git tag v1.2.3 && git push origin v1.2.3`; `v1.3.0-rc.1` is a
pre-release). The release workflow runs the tests and publishes:

| File | |
|---|---|
| `veil-linux-amd64`, `veil-linux-arm64` | static binaries |
| `veilctl-linux-*`, `veilctl-darwin-*`, `veilctl-windows-*.exe` | veilctl for Linux, macOS and Windows (amd64, arm64) |
| `veil.service` | the systemd unit, for an installation without a package |
| `veil_<version>-1_amd64.deb`, `veil_<version>-1_arm64.deb`, the same for `veilctl` | signed with the package key (origin signature) |
| `veil-<version>-1.x86_64.rpm`, `veil-<version>-1.aarch64.rpm`, the same for `veilctl` | signed with the package key (rpm header signature) |
| `*.deb.asc`, `*.rpm.asc` | detached signatures with the package key |
| `veil-packages.asc` | the package key's public half |
| `checksums.txt` | SHA-256 of all of the above |
| `*.sigstore.json` | a Sigstore bundle per file (keyless, GitHub OIDC) |

It also builds the Nix flake once; Nix users take it from the tag. All actions are pinned to
commit SHAs; nfpm (`NFPM_VERSION`) and Nix (`NIX_VERSION`) are pinned versions.

Verifying:

```sh
gpg --import veil-packages.asc
gpg --verify veil_1.2.3-1_amd64.deb.asc veil_1.2.3-1_amd64.deb
rpm --import veil-packages.asc && rpm -K veil-1.2.3-1.x86_64.rpm
cosign verify-blob --bundle veil-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/veilplane/veil/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com veil-linux-amd64
```

The repository needs these secrets for a release:

| Secret | |
|---|---|
| `PACKAGES_GPG_KEY` | the package key: an armored GPG private key (`gpg --armor --export-secret-keys KEYID`). Without it the release fails: packages are only published signed. |
| `PACKAGES_GPG_PASSPHRASE` | its passphrase |

No secret is needed for the attestation: its public key is in the source (`productionKeys` in
`agent/attest.go`). A release fails while that list is empty.

**Package repository.** After every stable release, `packages.yml` rebuilds the apt and dnf
repository at `https://packages.veilplane.com` from the newest ten stable releases
(`packaging/build-repo.sh`, with `install.sh` at its root), signs its metadata with the package key and force-pushes it as a
single commit to the branch `gh-pages`, which GitHub Pages serves. The workflow can also be run
by hand, for instance after deleting a release.

**Nix and the Go dependencies.** `nix/package.nix` holds the hash of the Go dependencies
(`vendorHash`). After a change to `go.mod` or `go.sum`, run `nix/update-vendor-hash.sh`; until
then the Nix job in CI fails and names the right hash.

## 14. Known limitations

- **veilctl** does not know the agent yet: it will write `agent.json` and read `veil.lock`.
  Until then, the files are edited by hand.
- **One control plane address for workers.** Workers reach the API server at the mesh address
  of one control plane node; several control plane nodes for workers (API server HA) are not
  set up by the agent yet.
- The proxy's and the mesh's own limitations: proxy/README.md, section 14; mesh/README.md,
  section 12.

## 15. License

veil is licensed under the Functional Source License, Version 1.1, with Apache 2.0 as future
license (FSL-1.1-ALv2), see `LICENSE.md`. In short: use, modification and internal production
use are allowed; offering it in a commercial product or service that competes with Veilplane is
not. Each version becomes available under the Apache License 2.0 two years after its release.

Third-party code and its licenses are listed in `NOTICE.md`. "Veilplane" is a trademark; the
license grants no rights to the name. Copyright 2026 Julian Siebert.
