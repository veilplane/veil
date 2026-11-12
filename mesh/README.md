# The mesh (package `mesh`)

The mesh of the veil agent ([Veilplane](https://veilplane.com)): it connects every node of a Kubernetes
cluster, control plane and workers, with WireGuard, also when they sit behind NAT in different
networks. The Veilplane backend coordinates the mesh, but it can neither read the traffic nor
add a member: every member's WireGuard key is signed with the cluster's mesh key, which only
the control plane nodes hold.

There are no relays. Nodes reach each other directly, through hole punching where both sit
behind NAT. Where that is impossible, the agent says so instead of failing silently, and the
dashboard shows which pair is affected and what helps.

It was a program of its own before (veil-mesh). The agent runs it when the backend switches
the feature `mesh` on for the cluster and the node's `agent.json` allows it.

## Contents

1. [Overview](#1-overview)
2. [Files](#2-files)
3. [How the agent runs it](#3-how-the-agent-runs-it)
4. [How nodes join](#4-how-nodes-join)
5. [Trust: what the backend can and cannot do](#5-trust-what-the-backend-can-and-cannot-do)
6. [Finding a path between two nodes](#6-finding-a-path-between-two-nodes)
7. [Kubernetes over the mesh](#7-kubernetes-over-the-mesh)
8. [Status and troubleshooting](#8-status-and-troubleshooting)
9. [Configuration](#9-configuration)
10. [Protocol](#10-protocol)
11. [Testing](#11-testing)
12. [Known limitations](#12-known-limitations)

## 1. Overview

```
   office (NAT)                      home lab (NAT)                    data centre
 +------------------+             +------------------+             +--------------+
 | cp-1   worker-1  |             |    worker-2      |             |   worker-3   |
 | 10.200.0.1  .0.2 |<===========>|    10.200.0.3    |<===========>|  10.200.0.4  |
 +--------+---------+  WireGuard  +--------+---------+  WireGuard  +------+-------+
          |            (direct)            |                              |
          +--------------------------------+------------------------------+
                                           |  agent API (HTTPS, JSON, access token):
                                           v  certificates, addresses, status. No traffic.
                                  +------------------+
                                  | Veilplane backend|  + UDP reflector
                                  +------------------+
```

- Every node gets an address in the cluster's mesh network (default `10.200.0.0/16`; not in
  `100.64.0.0/10`, see "Conflicts with the machine" below) and a
  WireGuard interface `veil0`.
- The agent registers with the backend, receives the list of members and keeps one WireGuard
  peer per member, each limited to that member's address.
- The backend hands out addresses and tells the nodes where the others can be reached. It never
  sees a WireGuard private key, and every node checks every member's certificate itself.
- WireGuard runs in the kernel where it can (Linux 5.6 and newer), otherwise as wireguard-go
  inside the agent (containers, older kernels). Both are configured the same way.

Control plane nodes run the mesh next to the etcd proxy, in the same agent; worker nodes run
only the mesh and never get the cluster's master key.

## 2. Files

| File | Content |
|---|---|
| `mesh.go` | `Run`: connection to the backend, member list, path finding, hole punching, status |
| `cert.go` | mesh key and mesh certificates |
| `wg.go` | the WireGuard interface: kernel or wireguard-go, configured through wgctrl |
| `mesh_test.go` | unit tests: certificates, address order, refusing forged members |

| `backend.go` | the calls to the backend (`Backend`, implemented by the agent with the agent API) and their JSON types |

## 3. How the agent runs it

The agent calls `mesh.Run(ctx, config)` with its side of the agent API (`Backend`: requests with
the node's access token), this node's certificate and WireGuard key, and a callback
for the status. `Run` brings the interface up, keeps the mesh connected and removes the
interface again when the agent stops it (the backend switched the feature off, the node was
revoked, or the agent stops).

It needs root (or `CAP_NET_ADMIN`) for the interface, and `ip` (iproute2).

## 4. How nodes join

```sh
# on a control plane node: an invite file for a worker
veil invite -worker -node worker-1 -o worker-1.invite          # mode 600

# on the worker: /etc/veil/agent.json
{"join": "/etc/veil/worker-1.invite"}
```

**Control plane node**: nothing to do. When the backend switches the mesh on, the agent creates
a WireGuard key, asks the backend for an address (a request with its access token), signs its
own mesh certificate with the cluster's mesh key and brings the interface up.

**Worker**: `veil invite -worker` on a control plane node creates the worker's WireGuard key,
asks the backend to reserve an address and a join code for that node name, and signs the
worker's certificate. The invite file holds the code, the worker's WireGuard private key, its
certificate and the public half of the mesh key, never the master key. The worker's agent
checks the certificate against its own key, joins as a device with the role `worker`: its
access token opens the mesh service only, the backend refuses it on the etcd API. Treat the
invite file like a password until it is used (once, within a day by default).

Leaving: `veil leave` unenrolls the node; the others drop it from WireGuard at once. Revoking a
device in the dashboard does the same, and the node's agent stops the mesh.

## 5. Trust: what the backend can and cannot do

The mesh key is derived from the cluster's master key:

```
seed = HKDF-SHA256(master key, salt = none, info = "veilplane mesh v1 " + cluster id)
mesh key = Ed25519(seed)
```

A mesh certificate is a short text signed with it:

```
veilplane-mesh-certificate v1
cluster: k7f3m2x9q1ab
node: worker-1
role: worker
wireguard: <WireGuard public key, base64>
address: 10.200.0.2
issued: 2026-11-02T09:00:00Z
```

encoded as `base64url(text) "." base64url(signature)`. The agent accepts a member only if its
certificate verifies with the cluster's mesh key, names this cluster and the node name it is
listed under, and its address and key are not used by another member.

| The backend can | The backend cannot |
|---|---|
| refuse to coordinate (the mesh stops learning new addresses; existing connections keep working) | read the traffic (WireGuard end to end) |
| see which nodes reach which, their public addresses and when (metadata) | add a member or swap a member's WireGuard key (no valid certificate: every node refuses it, the dashboard shows it in red) |
| leave out a member, or keep a revoked one in the list | get a WireGuard private key (created on the nodes; a worker's in its invite file) |

Revocation relies on the backend: a revoked member drops out of the list, but its certificate
stays valid. A backend that wants to keep a revoked node in the mesh could do so; see
section 12.

## 6. Finding a path between two nodes

Each node knows two kinds of addresses of every peer:

- **local**: the addresses of its interfaces with its WireGuard port (container and Kubernetes
  interfaces are left out);
- **observed**: the public address and port the backend saw (behind NAT: the router's).

**The reflector.** To learn its observed address, the agent points a WireGuard peer at the
backend's UDP reflector for a few seconds, every minute. WireGuard sends an ordinary handshake
from its own port, and the backend notes where it came from; the reflector never answers. This
works the same for kernel WireGuard and wireguard-go, without a second socket.

**Which path, and how.**

| Situation | What happens |
|---|---|
| same public address (same LAN) | the peer's local addresses, one after the other, until a handshake succeeds (routers rarely send traffic back into their own network) |
| peer has a public address (its observed address is one of its own) | its addresses one after the other, at once |
| we have a public address, peer is behind NAT | we wait: the peer comes to us, its packet opens its own router first, WireGuard answers to where it came from |
| both behind NAT, different networks | hole punching, see below |
| both behind symmetric NAT, or UDP blocked | no path; reported as unreachable |

**Hole punching.** Both nodes send to each other's observed address at the same moment, so that
each packet leaves its own router before the other one arrives there; each router then sees the
incoming packet as the answer to its own. The moment comes from the backend's clock
(`Clock`, measured like NTP: five samples, the shortest round trip wins), so both nodes usually agree
within a few milliseconds (in the test below: well under one), much less than the delay between
two networks. Attempts are 35 seconds apart, at a phase that depends on the pair,
and both nodes stay silent in between.

The silence matters. Many routers, Linux among them, record a packet that arrives before the
node behind them has sent anything as a connection of their own. When the node then answers,
its port is taken and the router picks a random one, and from then on it tends to reuse that
random port for every destination. The peer keeps knocking at the old one and nothing fits. 35
seconds is longer than Linux's timeout for unanswered UDP (30 s), so every attempt starts clean.
For the same reason a node with a public address never knocks at a node behind NAT first, and
a node that does not yet know whether it is behind NAT does not knock at anyone's public
address.

Two more details: each attempt uses a freshly configured WireGuard peer, because WireGuard
sends at most one handshake every five seconds and also counts attempts that failed for want
of an address (traffic to the peer while it was silent); and each node picks a random
WireGuard port (51820 to 52819), so that several nodes behind one router can keep their ports.

Once a handshake succeeds, WireGuard keeps the path alive (keepalive every 25 s) and follows the
peer if its address changes. If a connection is lost (no handshake for three minutes), the
search starts again.

## 7. Kubernetes over the mesh

The mesh connects the nodes; the CNI keeps doing pod networking on top. With k3s and its
default flannel:

```sh
# control plane node (with its etcd proxy)
k3s server --datastore-endpoint http://127.0.0.1:2379 \
  --node-ip 10.200.0.1 --advertise-address 10.200.0.1 --tls-san 10.200.0.1 --flannel-iface veil0

# worker
k3s agent --server https://10.200.0.1:6443 --node-ip 10.200.0.2 --flannel-iface veil0
```

Pod traffic then runs VXLAN inside WireGuard: encrypted between nodes, with an MTU of 1370 for
pods (1420 for WireGuard, minus 50 for VXLAN). Flannel sets this itself from the interface.
Routing pod networks directly through WireGuard, without VXLAN, is a later optimisation.

The node must allow UDP on its WireGuard port (`port` in the agent's `mesh.json`, or
`mesh.port` in `agent.json`) in its own firewall, and traffic on `veil0` (firewalld:
`firewall-cmd --permanent --zone=trusted --add-interface=veil0`).

## 8. Status and troubleshooting

```sh
veil status        # the agent's status file, /var/lib/veil/veil.lock
```

```
running  b1 of cluster edge (worker), backend connected, updated 2s ago
  proxy  off
  mesh   running   10.200.0.3 on veil0 (kernel), public 198.51.100.12:52700
         a2                   10.200.0.2      worker        connected    direct 198.51.100.11:52035
         cp1                  10.200.0.1      control-plane connected    direct 198.51.100.11:52702
         p1                   10.200.0.6      worker        connected    direct 198.51.100.31:51916
         s1                   10.200.0.4      worker        unreachable
```

`wg show veil0` shows the WireGuard side. The dashboard's cluster page shows the same for all
nodes, with a matrix of who reaches whom.

| Status | Meaning, and what helps |
|---|---|
| `connected lan` / `connected direct` | fine; the number after it is the round trip of the probes |
| `blocked` | the WireGuard handshake works, but probes over the mesh get no answer: something on one of the two machines drops mesh traffic after WireGuard decrypted it (a firewall on `veil0`, Tailscale: see "Conflicts with the machine"). Reported to the backend as `unreachable` |
| `trying` | still searching; hole punching takes up to a few attempts, 35 s apart |
| `unreachable` | no path: usually both nodes behind symmetric NAT (mobile networks, some corporate networks) or UDP blocked. A node with a public address, or a forwarded UDP port on one of the two, helps. |
| `refused` | the backend listed a member without a valid certificate of this cluster. The agent ignores it. If you did not invite it, report it. |
| backend not connected | the mesh keeps working with what it knows; new members and address changes wait |
| `! ...` under the mesh line | something on this machine gets in the way, see below |

**Probes.** A handshake proves that two nodes can exchange encrypted packets, not that the
packets arrive: a firewall can drop them after WireGuard decrypted them. So every node answers
small UDP probes on its mesh address (port 51819) and asks every connected peer every 5 seconds.
That tests the whole way, through both machines' firewalls, and measures the round trip. A peer
with a live handshake that has not answered for 20 seconds is `blocked`, and the backend hears
`unreachable` at once, not at the next regular report. Allow UDP 51819 on `veil0` (a trusted
zone does).

**The interface is the agent's.** The agent listens to the kernel's reports about `veil0`
(netlink): the moment something else takes it down or removes its address (NetworkManager, a
person with `ip`), it puts it back and says so in `veil status` for ten minutes; if the interface
is gone, the mesh starts again with a new one. A check every 30 seconds catches what a lost
report would miss. The packages keep NetworkManager away
from it (a udev rule, `/usr/lib/udev/rules.d/85-veil.rules`; NixOS: `networking.networkmanager.unmanaged`),
so desktops do not list it as a VPN to switch off.

**Conflicts with the machine.** Every 30 seconds the agent looks at the machine's interfaces and
routes and reports (in `veil status`, its log and to the dashboard) what gets in the way:

- **Another network overlapping the mesh network**: an address or a route on another interface
  (a VPN, Docker, a LAN) that covers mesh addresses. Traffic for them may go there instead.
- **Tailscale**, when the mesh network lies in `100.64.0.0/10`: Tailscale takes its addresses
  from there and drops every packet from that range that does not arrive through its own
  interface. The other nodes' mesh packets arrive through `veil0` and are dropped; the
  WireGuard handshake still works, so the peer shows `connected` while nothing gets through.
  This is why the default mesh network is `10.200.0.0/16`. Meshes that still use an address in
  `100.64.0.0/10` move when the backend's network changes: control plane nodes take their new
  address by themselves, workers need a new invite. Until then,
  `iptables -I INPUT 1 -i veil0 -j ACCEPT` lets the mesh through (until the next reboot).

## 9. Configuration

In `agent.json` (all optional):

| Field | Meaning |
|---|---|
| `mesh.interface` | WireGuard interface, default `veil0` |
| `mesh.port` | WireGuard UDP port; default: chosen once at random between 51820 and 52819 and kept in `mesh.json` |
| `mesh.mtu` | default 1420 |
| `mesh.mode` | `auto` (kernel if available), `kernel` or `userspace` |

The agent keeps the rest in its state directory: `wg.key` (the WireGuard private key, mode
600) and `mesh.json` (address, network, this node's certificate, the public half of the mesh
key, the port).

## 10. Talking to the backend

Through the agent's connection to the backend (HTTPS and JSON, with the node's access token):
the mesh registers its certificate and local addresses, receives the member list (again
whenever it changes: a request stays open until then), reports how it reaches each peer, and
reads the backend's clock, measured like NTP (five samples, the shortest round trip wins), so a
proxy on the way adds delay but little error. The interface is `Backend` in `backend.go`.

## 11. Testing

- `go test ./mesh`: certificates (forgery, other keys, canonical form), the mesh key per cluster,
  the order of addresses, and that a member list with a forged certificate, a stolen address or
  someone else's certificate gets everything but the valid member refused.

## 12. Known limitations

- **No relays.** Two nodes that both sit behind symmetric NAT, or behind firewalls that block
  UDP, do not reach each other. A node with a public address or a forwarded port solves it.
- **Revocation relies on the backend.** Certificates do not expire; a revoked member is removed
  by leaving it out of the list. Short-lived certificates renewed by the control plane would
  close this gap.
- **Kernel WireGuard** is the default path but the automated tests here run wireguard-go; the
  kernel path uses the same configuration calls (wgctrl) and wants a test on a real machine.
- **IPv6**: global IPv6 addresses are offered as local endpoints and work when both sides have
  them; the reflector and hole punching are IPv4 only.
- **Linux only**, one mesh per node.
