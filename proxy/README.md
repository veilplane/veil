# The etcd proxy (package `proxy`)

The etcd proxy is the part of the veil agent that keeps a Kubernetes control plane's data
secret from Veilplane. It runs next to kube-apiserver on every control plane node and speaks
the etcd v3 gRPC API to it. Behind it is the hosted, untrusted etcd-compatible backend. The
proxy encrypts every key and value before it reaches the backend and verifies every answer the
backend gives, so that the operator of the backend can neither read cluster data nor change it
unnoticed.

The agent starts it when the backend switches the feature `proxy` on and the node's
`agent.json` allows it (see the repository's README). This document describes how the proxy
works, which formats it uses and what has to be kept in mind when changing it. It was a program
of its own before (veil-proxy); "the proxy" and "an instance" below mean the proxy of one
control plane node.

Status: feature complete for kube-apiserver and k3s, not externally audited.
Tested with k3s v1.33 and etcd v3.7 as a stand-in backend.

## Contents

1. Overview
2. Files
3. How the agent runs it
4. Threat model
5. Cryptography and data formats
6. The verified replica
7. Request handling
8. Freshness, checkpoints and checkpoint records
9. Identity towards the backend
10. Key files
11. Operations
12. Testing
13. Working on the code
14. Known limitations

## 1. Overview

```
 control plane node (customer)                         hosted (untrusted)
 +--------------------------------------------+
 | kube-apiserver / k3s                       |
 |      | etcd v3 gRPC, plaintext, localhost  |
 |      v                                     |
 | veil agent: etcd proxy -- verified replica |      TLS, etcd v3 gRPC, access token (outbound only)
 |         \______________________________________> Veilplane backend
 |                                            |      (sees ciphertext only)
 | files: device key, master key (0600),      |      (a proxy in front of the backend may end TLS)
 |        state file (verified checkpoints)   |               | encrypted checkpoint records
 +--------------------------------------------+               |
                                    the proxies of the other control plane nodes
```

The proxy has three jobs:

- Confidentiality: keys and values are encrypted with a master key that only
  the customer's nodes hold. The backend stores ciphertext.
- Integrity and freshness: every instance follows the backend's complete change
  stream, checks each change and keeps a verified copy (the replica). Reads and
  watches are answered from that copy, never from backend answers.
- Consistency between instances: instances write encrypted checkpoint records
  of their state into the key space, which detects a backend that shows
  different histories to different instances. Instances never connect to each
  other.

The proxy does not protect availability. The backend can always refuse to
serve. It can not make the proxy accept false data.

## 2. Files

| File | Content |
|---|---|
| `proxy.go` | Options and start (called by the agent), startup verification, cryptography, key ranges, freshness and checkpoints, checkpoint records, operations endpoints, gRPC services, write path |
| `replica.go` | Verified replica: data model, verification of changes, state digest, history window, serving reads and watches |
| `proxy_test.go` | Unit tests, attack tests against a real etcd, operations, load test, fuzz targets |

Each source file is divided into sections marked with a comment line of the form
`// ------------- name`.

## 3. How the agent runs it

The agent calls `proxy.Start(ctx, conn, options)` with its connection to the backend (which
carries the access token on every call, section 9) and these options from `agent.json`:

| `agent.json` | Default | Meaning |
|---|---|---|
| `proxy.listen` | `127.0.0.1:2379` | Address kube-apiserver connects to (plaintext gRPC, keep it local) |
| `proxy.opsListen` | `127.0.0.1:9390` | `/healthz`, `/readyz`, `/metrics`, `/state`, `/leave`; `"off"` disables |
| `proxy.history` | `10m` | Verified history kept in memory; must exceed the API server's compaction interval (5 min by default) |
| `proxy.trustBackend` | `false` | Accept the backend state without verification (recovery only, see section 8) |
| `proxy.verbose` | `false` | Log every request including plaintext keys (development only) |

The master key is `master.key` in the agent's state directory, the verified checkpoints are in
`proxy.state` next to it, and the instance's name in checkpoint records is the node's name.
Point the API server at the proxy, for k3s with `--datastore-endpoint http://127.0.0.1:2379`.

The proxy keeps retrying while the backend is unreachable and refuses to serve after it detected
a violation (section 8); the agent shows both in its status file. When the backend switches the
feature off, or the node is revoked, the agent stops the proxy: it stops serving, writes a final
checkpoint and returns.

### The master key of further nodes

A new control plane node gets the master key from an invite file (`veil invite` on an existing
node), never from the backend alone:

```
key = HKDF-SHA256(file secret | server secret, "veil invite v1")      both secrets: 32 random bytes
box = nonce | AES-256-GCM(key, nonce, master key, aad = "veil invite v1")
```

The file holds `box` and the file secret; the server secret goes to the backend with the invite.
The backend hands it out once, to the node that redeems the code, and deletes it then or when the
code expires. So the backend alone (one half, no box) learns nothing, and the file alone is
useless once used. Until it is used, the file must be treated like a password.

The invite file also carries the inviting instance's verified checkpoints (fetched from the
running proxy's `/state`, else its state file), which the new instance uses to verify the
backend at its first start (section 8).

## 4. Threat model

Trusted:

- The customer's control plane nodes, including root on them, their disks and
  backups, and the code of the agent itself. The proxy does not try to
  protect against the customer.
- The master key, which only exists on customer nodes (section 10).
- The CA that signed the backend's (or its proxy's) TLS certificate: the system's, or `apiCa`
  in `agent.json`. It only protects the access token in transit; a wrong backend still learns
  nothing and cannot change data unnoticed.

Untrusted:

- The backend and everything between proxy and backend. The backend may read
  and write its storage arbitrarily, delay, reorder, replay or withhold
  messages, answer differently to different instances, and restore old
  backups.

Goals:

- The backend learns nothing about keys and values except what section 16 lists
  (structure, counts, sizes, timing).
- Any deviation of the backend from an honest etcd that could change what the
  API server sees is detected, and the affected instance stops serving.

Non-goals:

- Availability. The backend can stop serving at any time.
- Protection of the worker nodes or of workloads. That is not the proxy's job.
- Protection against a compromised customer node, or against someone who
  obtains a copy of its disk or backups. Root on a control plane node can read
  every Secret through the API server anyway.

## 5. Cryptography and data formats

### Key hierarchy

The 32-byte master key is the only long-term secret. All working keys are
derived with HKDF-SHA256, salt empty, info `"veil-proxy v1 " + purpose`:

| Purpose string | Length | Used for |
|---|---|---|
| `segment aes-siv` | 64 bytes | AES-256-SIV for key segments |
| `value aes-gcm` | 32 bytes | AES-256-GCM for values |
| `state digest` | 32 bytes | HMAC-SHA256 key of the replica's state digest |

All instances of a cluster must use the same master key. Because the key
encryption is deterministic, they then produce identical ciphertext keys; this
is what lets any number of instances work against the same backend without
coordination.

### Keys

etcd keys are paths such as `/registry/pods/default/nginx`. The proxy splits a
key at `/`, encrypts every non-empty segment on its own and joins the results
with `/`. Empty segments (a leading `/`, `//`, a trailing `/`) stay empty.

For a segment `s` with plaintext parent path `p` (all segments before it,
joined with `/`):

```
ciphertext = AES-256-SIV(key = segment key, plaintext = pad(s, 32), associated data = p)
segment    = base64url(ciphertext), no padding, strict decoding
```

Properties this gives, and which the rest of the code relies on:

- Determinism: the same key always encrypts to the same ciphertext.
- Prefix preservation: the encryption of `/registry/pods/default/` is a prefix
  of the encryption of every key below it. Prefix scans therefore work on the
  backend.
- Context binding: the same name under different parents gives different
  ciphertext, so equal names in different namespaces are not linkable, and a
  segment moved under another parent fails authentication.
- One spelling per key: decoding is strict (`base64.RawURLEncoding.Strict()`),
  so a backend cannot create a second ciphertext key that decrypts to the same
  plaintext key.

AES-SIV comes from Google Tink (`github.com/tink-crypto/tink-go/v2/daead/subtle`,
RFC 5297, 512-bit key as Tink requires).

Prefix scans are only possible on whole segments. `/registry/pods/` and
`/bootstrap` work; a scan for `/registry/po` cannot be expressed.

### Values (records)

Every value is stored as a record:

```
plaintext = prev (8 bytes, big endian) | lease (8 bytes, big endian) | payload
stored    = 0x03 | nonce (12 bytes) | AES-256-GCM(value key, nonce, pad(plaintext, 128), associated data = plaintext key)
```

- `0x03` is the format version (`valueVersion`).
- `prev` is the mod revision of the version this write replaces (0 for a
  create). It is the basis of replay detection (section 6).
- `lease` is the lease the write was made with; it must match the lease the
  backend reports.
- The associated data binds a value to its key, so values cannot be moved
  between keys.

### Padding

`pad(b, min)` appends `0x80` and zero bytes (ISO/IEC 7816-4) up to
`max(min, padme(len(b)+1))`. Padmé (Nikitin et al., 2019) rounds lengths so
that at most O(log log n) bits of the length remain visible, with at most
about 12% overhead. Minimum sizes are 32 bytes for key segments and 128 bytes
for value records. Padding is deterministic, which key segments require.

### Delete receipts

A delete has no value that could carry `prev`. Therefore every transaction
that deletes keys also writes a receipt to the reserved key
`/veil/delete-receipt`:

```
receipt payload = repeated: prev (8 bytes) | key length (4 bytes) | plaintext key
```

The payload is stored as a normal record (with prev = 0, lease = 0) under the
encrypted receipt key. It lists each deleted key with the mod revision it had.
Deletes of keys that do not exist need no receipt. The receipt key is never
shown to clients and keys below `/veil/` cannot be written by clients.

`/veil/read-index` is another reserved key. It is never written; a count-only
range on it is the cheapest way to ask the backend for its current revision.

## 6. The verified replica

`replica.go`. Every instance keeps the complete decrypted key space in memory
plus a window of history.

### Data model

| Field | Meaning |
|---|---|
| `keys map[string][]version` | All versions per plaintext key, ascending by mod revision. A delete is stored as a tombstone (`deleted: true`). |
| `order []string` | All keys of the map, sorted. Prefix scans are a binary search plus a linear walk. |
| `hist []revision` | Revisions in `(base, rev]`, each with its changes and the digest after it |
| `rev` | Last applied revision |
| `base` | Oldest revision whose state is fully known. Reads below it fail with "compacted". |
| `digest` | Keyed set hash of the state at `rev` |
| `claims` | Digests other instances reported for revisions not yet reached |

A version has `modRev`, `createRev`, `ver` (etcd's per-key version counter),
`lease` and `value`.

### Following the backend

`follow` / `followOnce` open one watch on the whole key space (`\x00` to
`\x00`) starting at `rev + 1`, with progress notifications. Events of one
revision are grouped and passed to `apply`. Before that, the response header's
revision must not be lower than `rev` (rollback). A compaction response from
the backend makes the replica fail: the history it needed is gone. Any other
interruption reconnects after one second, continuing at `rev + 1`.

### Verification rules (`apply`)

`apply(rev, events)` first verifies all events of a revision without changing
anything, then applies them together.

1. Gap-free: `rev` must be exactly the last applied revision plus one. Every
   etcd revision contains at least one change, so a missing revision means a
   withheld change.
2. Every event key must decrypt (authentication of every segment).
3. Delete receipts in the revision are decrypted and collected.
4. For a put of key `k`:
   - the value must decrypt with `k` as associated data;
   - the record's `prev` must equal the current mod revision of `k`, or 0 if
     `k` does not exist. This is what catches a replayed old ciphertext: its
     `prev` points to an older state;
   - the event's lease must equal the record's lease;
   - create revision and version must follow from the previous state
     (`createRev` = previous createRev or `rev` for a create, `ver` = previous
     ver + 1 or 1).
5. For a delete of key `k`:
   - `k` must exist;
   - either a receipt in the same revision lists `k` with its current mod
     revision, or `k` is attached to a lease (lease expiry and revocation are
     carried out by the backend and cannot carry a receipt).
6. Every receipt entry must be used by a delete, and the revision must contain
   at least one change.
7. After applying, if another instance claimed a digest for this revision, it
   must equal ours (fork detection).

On any violation the replica fails permanently (`fail`). From then on every
request returns gRPC `DataLoss` with the reason, `/readyz` returns 503 and
`veil_replica_failed` is 1. There is no automatic recovery: the backend has
been caught lying or losing data, and a human has to decide what happens.

### State digest

```
entry(k, v) = HMAC-SHA256(digest key, modRev | createRev | ver | lease | SHA256(value) | k)   (integers 8 bytes big endian)
digest      = sum of entry(k, v) over all live keys, modulo 2^256
```

The digest can be updated per change (subtract the old entry, add the new
one) and equals a full recomputation (`TestDigestIncrementalEqualsFull`). It is
keyed, so the backend can neither compute it nor steer it towards collisions.
It covers metadata as well as values, so two replicas with the same digest at
the same revision hold the same state.

A digest is recorded for every revision in the history window and for `base`.

### History window

`trimLocked` drops revisions older than `proxy.history` (default 10 minutes). For
every key changed in a dropped revision it keeps the newest version at or
below the new `base` and everything after it; a key whose only remaining
version is a tombstone is removed from `keys` and `order`. Watches and reads
need history back to the oldest revision the API server may ask for, which is
why `proxy.history` has to be longer than the API server's compaction interval.

### Snapshot loading (`load`)

`load(rev)` reads the backend's whole key space at revision `rev` (0 = latest)
and replaces the replica with it, with `base = rev`. Each entry must decrypt
and be internally consistent (`lease` matches, `prev < modRev`,
`createRev <= modRev`). Whether the snapshot is genuine is decided by the
caller, which compares the resulting digest with a checkpoint (section 8).

## 7. Request handling

### Reads (`Range`, `RangeStream`)

All reads are answered by `replica.serveRange`. `RangeStream` (etcd 3.7) gives the same
answer as `Range` in chunks of at most 500 keys, header, `more` and `count` in the last one:

- `revision > 0`: wait until the replica has applied that revision, then read
  at it. Revisions below `base` fail with etcd's "required revision has been
  compacted" error, which the API server handles like real etcd.
- `revision = 0`, linearizable (default): first a read index. The proxy asks
  the backend for its current revision with a count-only range on
  `/veil/read-index` and waits until the replica has applied that revision.
  This guarantees that the read reflects every write completed before it
  started, like etcd's linearizable reads.
- `revision = 0`, serializable: answered from the replica immediately.

`waitFor` gives up after 5 seconds with `Unavailable`. Results are returned in
plaintext key order with etcd's semantics for `limit`, `more`, `count`,
`keys_only`, `count_only`, min/max mod and create revision filters and
descending sort by key. Plaintext order matters: the API server mixes pages
served from its watch cache with pages served by etcd.

Supported key ranges (`parseRange`): a single key, the whole key space
(`\x00`, `\x00`), and a prefix scan on segment boundaries starting at the
prefix or at a key inside it (pagination continues at `lastKey + "\x00"`).

### Writes (`Put`, `DeleteRange`, `Txn`)

`Put` and `DeleteRange` are turned into transactions; everything goes through
`txn`:

1. Shape checks. Unsupported (returns `Unimplemented`): range compares, value
   compares, range deletes, nested transactions, writes in the failure branch,
   `ignore_value` / `ignore_lease`. Writes to `/veil/` are rejected.
2. Pins. Every written key needs the mod revision it replaces. kube-apiserver
   already compares `ModRevision(key) == X` on every write; that `X` is used.
   For keys without such a compare the proxy adds one, taking the revision from
   the replica.
3. The encrypted transaction is built: compares with encrypted keys, puts as
   records with `prev` = pin, deletes, and a delete receipt for every deleted
   key whose pin is not 0.
4. It is sent to the backend (`forward`, which checks freshness).
5. The proxy waits until the replica has applied the response revision `H`,
   then `checkTxn` checks the backend's verdict against the replica:
   - Did this transaction create revision `H`? Only if `H` exists in the
     history and changed one of the written keys.
   - Success: all compares (original and added) must hold at `H - 1` if the
     transaction wrote, otherwise at `H`; every put must be visible at `H` with
     the written value and lease; every delete of an existing key must have
     removed it. Otherwise the backend lied.
   - Failure: at least one compare must be false at `H`. If all hold, the
     backend lied. If only compares added by the proxy are false, the replica
     was behind and the transaction is retried (up to 50 times).
6. The response returned to the client is built from the replica (range
   results at `H`, previous key-values at `H - 1`), never from backend output.

Writes therefore cost one backend round trip plus the time until the change
arrives on the watch stream.

### Watches (`Watch`)

Watches are served from the replica's history (`Watch`, `runWatcher` in
`replica.go`), not proxied:

- Each watch gets its own goroutine that reads matching changes from `hist`
  starting at its next revision, sends them in batches of up to 1000 events
  without splitting a revision, and then waits for the next change.
- `prev_kv`, `NOPUT` / `NODELETE` filters and progress notifications (every 10
  minutes when requested) are supported.
- A start revision at or below `base` results in a canceled watch with
  `CompactRevision` set, as in etcd.
- A progress request (`WatchRequest_ProgressRequest`) is answered with
  `WatchId = -1` and revision `R` only after every watch on the stream has
  delivered everything up to `R`. kube-apiserver relies on exactly this to know
  that its watch cache is current.

### Leases, maintenance, cluster

- Lease calls are forwarded with freshness checks. `LeaseTimeToLive` decrypts
  the attached keys. `LeaseKeepAlive` is a proxied stream; its response
  revisions must not go backwards.
- `Status` and `Alarm` are forwarded. `Defragment`, `MoveLeader`, `Downgrade`
  are rejected (`PermissionDenied`), `Hash`, `HashKV`, `Snapshot` are
  `Unimplemented`: these are operations of the backend operator.
- `MemberList` returns the proxy itself as the only member, so etcd clients
  that sync endpoints never bypass the proxy. Member changes are rejected.
- `Compact` first records the digest at the compaction revision as anchor
  (section 8). It refuses revisions outside the verified history.

## 8. Freshness, checkpoints and checkpoint records

### Freshness rule

`freshness` keeps the floor: the highest backend revision seen. For every
backend call, the floor is read before sending; the response's revision must
be at least that value (`check`). Comparing with the floor taken before the
request avoids false alarms when responses overtake each other. The floor rises
with every response and with every revision the replica applies. A violation
fails the request with `DataLoss` ("backend went back in time").

### Checkpoints and the state file

A checkpoint is a revision and the replica's digest at it. The state file
(`proxy.state` in the state directory) holds two:

```
latest <revision> <digest hex>
anchor <revision> <digest hex>
```

- `latest` is the last verified state, written every second and on shutdown,
  atomically (temporary file and rename).
- `anchor` is the digest at the last compaction revision this instance
  forwarded. The backend keeps history from the compaction revision on, so the
  anchor stays verifiable after a longer outage, when `latest` has been
  compacted away.

The file is not secret (the backend knows revisions, and the digest is keyed).
It must be on persistent storage. A new instance gets the state file of an
existing one with its invite file (`veil invite`); without any state file, only an empty
backend is accepted.

### Checkpoint records

The instances of a cluster never connect to each other. Instead, every
instance writes its latest checkpoint once a minute to the reserved key
`/veil/checkpoint/<node>`:

```
<revision> <digest hex> <unix time of the writer>
```

The record is an ordinary value: encrypted with the master key, bound to its
key and to its predecessor revision, so the backend can neither forge, move nor
replay one. It travels through the backend like all data, so instances can sit
behind NAT. Keys under `/veil/` are never shown to clients.

- **Spliced histories.** When the replica applies another instance's record
  that names a revision it has verified with a different digest, the backend
  showed different histories: the replica fails (`claim`). Records for
  revisions not reached yet are kept and checked when reached.
- **Hidden writes.** A backend that forks and hides the other instances'
  records from this one makes them fall silent. Every instance tracks when it
  last saw each other instance's record; after five minutes the instance is
  logged as silent and counted in `veil_peers_silent`
  (`veil_peer_checkpoint_age_seconds{node}` per instance). This is a warning,
  not a failure: an instance that is simply down looks the same.
- **Leaving.** `POST /leave` on the ops address (`veil leave`) deletes the
  instance's record, so the others stop expecting it.

### Startup verification (`verifyAndLoad`)

1. Read `latest` and `anchor` from the state file.
2. Try them in descending revision order: load the backend's snapshot at that
   revision and compare digests.
   - "compacted": try the next, older candidate.
   - "future revision": the backend is behind a verified revision. The replica
     fails ("backend went back in time").
   - digest mismatch: the replica fails (forged or forked history).
   - match: verified. The replica then follows the change stream from there and
     verifies every change up to the present.
3. Both were compacted (long outage, or an old invite): the backend's current
   state is accepted if it holds a checkpoint record whose revision is at least
   that of `latest`. Such a record can only have been written by an instance of
   the cluster after that point, so the state is not rolled back. Otherwise the
   replica fails.
4. No state file: with `trustBackend` the current backend state is accepted
   unverified; otherwise only an empty backend (first start of a new cluster).

Infrastructure errors (backend unreachable) are retried every second.

Recovery after a deliberate restore of a backend backup: all instances will
refuse it. Delete the state files on all instances, start one instance once with
`proxy.trustBackend` in its `agent.json`, and set up the others again from it (invite).

A stopped replica never writes its state as a checkpoint: what the backend showed it is not
verified, and a restart must not turn it into something trusted. The state file keeps the last
checkpoint that was verified.

## 9. Identity towards the backend

The proxy does not identify itself: it uses the agent's gRPC connection, which sends the node's
access token with every call, which says which cluster the call belongs to; the proxy never
sends a tenant id itself. The token is short-lived and signed by the backend; the agent gets a
new one with a request signed by the node's device key before the old one expires.

Nothing depends on the TLS connection: it only protects the token and the (already encrypted)
traffic in transit, and it may end at a proxy in front of the backend. A
backend that mixed up tenants would show the proxy data it cannot decrypt or verify: the
proxy refuses it.

## 10. Key files

A control plane node holds two secrets in the agent's state directory, both as plain files
readable only by their owner (mode 0600, directory 0700):

| File | Content |
|---|---|
| `master.key` | 64 hex characters. Opens every key and value of the cluster. Identical on all control plane nodes of a cluster. |
| `device.key` | Ed25519 key (seed, base64). Identifies this node to the backend: it signs the requests for access tokens. One per node. |

The proxy reads the master key once at startup and warns if the file is
readable by group or others.

This is the same protection Kubernetes gives its own secrets: the cluster CA,
the service account signing key and the encryption-at-rest key are plain files
on the control plane nodes. Consequences:

- Whoever obtains a copy of these files (disk image, VM snapshot, backup) can
  decrypt the cluster's data as stored by the backend, and with the device key
  act as this node until it is revoked. Keep the state directory out of backups
  that are less protected than the node itself.
- Access tokens live 15 minutes; a node can be revoked at the backend at any
  time, which refuses its tokens at once.
- A copied device key used in parallel to the original writes conflicting
  checkpoint records, which the other instances detect as a fork (section 8).

## 11. Operations

### Endpoints (`proxy.opsListen`)

| Path | Meaning |
|---|---|
| `/healthz` | 200 while the process runs. Stays 200 after a detected attack, because a restart would not help. |
| `/readyz` | 200 when the replica is loaded, verified and the gRPC server is serving. 503 during startup and after a detected attack, with the reason in the body. |
| `/metrics` | Prometheus text format |
| `GET /state` | The current verified checkpoints, in the state file's format (`veil invite` puts them into invite files) |
| `POST /leave` | Deletes this instance's checkpoint record before it leaves the cluster (`veil leave`) |

Metrics:

| Metric | Type | Meaning |
|---|---|---|
| `veil_build_info{version}` | gauge | Always 1 |
| `veil_replica_failed` | gauge | 1 after a detected violation. Alert on this. |
| `veil_replica_revision` | gauge | Last verified revision |
| `veil_replica_base_revision` | gauge | Oldest revision readable from the history window |
| `veil_replica_tracked_keys` | gauge | Keys in the replica, including tombstones within the window |
| `veil_backend_floor_revision` | gauge | Highest backend revision seen |
| `veil_watch_streams` | gauge | Open watch streams from the API server |
| `veil_peer_checkpoint_age_seconds{node}` | gauge | Per other instance: time since its checkpoint record last changed |
| `veil_peers_silent` | gauge | Other instances without a new record for five minutes: down, or hidden by the backend. Alert on this. |
| `veil_grpc_requests_total{method,code}` | counter | gRPC requests by method and status code |

### Logging

The agent's log (`log/slog`, text on stderr, in the journal under systemd). Plaintext keys are
only logged with `proxy.verbose`.

### Lifecycle

When the agent stops the proxy, the gRPC server stops gracefully (at most 5 seconds, because
watches never end on their own) and a final checkpoint is written. The backend connection is
the agent's; it uses gRPC keepalive (30 s interval, 10 s timeout) so that a dead connection is
noticed and the watch is re-established.

### Running

The proxy must not run inside the Kubernetes cluster it serves: the API server cannot start
without it, and without the API server the pod would not be started. The agent runs as a
systemd service directly on the node (`packaging/veil.service`), before k3s or the kubelet.

## 12. Testing

```bash
go test ./proxy                                                        # unit tests, load test, fuzz seed corpus
E2E_ETCD_DIR=/path/to/etcd-release go test -race -v ./proxy            # + attacks against a real etcd
go test -run '^$' -fuzz '^FuzzDecKey$' -fuzztime 5m ./proxy            # fuzzing, one target at a time
```

| Area | Tests |
|---|---|
| Cryptography | Padmé values, padding round trip, determinism, prefix preservation, linkability, hidden lengths, tampering, canonical ciphertext keys, receipt format |
| Replica rules | Valid history, replayed value, forged delete, replayed receipt, lease expiry, gaps, forged metadata, receipt without delete, digest consistency, fork claims, history trimming, compare evaluation |
| Checkpoints | Persistence, checkpoint records (format, fork by a record, own record, hidden from clients), rollback rule, no checkpoint from a stopped replica |
| Against etcd (`E2E_ETCD_DIR`) | Two instances, replayed value, forged delete, new instance without and with an inviting instance's checkpoint (also after a restart), fork (other history than the invite's), silent and leaving instances, operations endpoints and shutdown |
| Scale | 100,000 keys: apply, list one namespace, count all |
| Fuzzing | `FuzzDecKey` (also checks canonical form), `FuzzOpenRecord`, `FuzzParseReceipt`, `FuzzParseRange`, `FuzzParseCheckpoint` |

The attack tests play the malicious backend by writing to etcd directly with a
plain gRPC client.

## 13. Working on the code

### Invariants

These properties are what the security rests on. A change that breaks one of
them breaks the product, even if all functional tests pass.

1. Nothing returned to a client comes from a backend answer directly. Reads,
   watches and transaction results come from the replica; backend answers are
   only compared with it.
2. The replica only changes in `apply` (verified changes) and `load` (a
   snapshot that the caller verifies against a checkpoint, or accepts under the
   explicit first-start and `trustBackend` rules).
3. Every value written carries the correct `prev`, and every write is pinned by
   a mod revision compare on the backend. Otherwise honest writes fail
   verification or replays become possible.
4. Every delete of an existing key without a lease is accompanied by a receipt
   in the same transaction.
5. Key encryption stays deterministic and canonical: one plaintext key, exactly
   one ciphertext key, identical on all instances.
6. A failed replica never recovers by itself.
7. Every backend call goes through `forward` (or applies the same freshness
   check).

### Adding support for a new request type

Every server type embeds etcd's `Unimplemented...Server`, so a method a newer etcd API adds
answers `Unimplemented` until it is written here. Decide first whether it reads or writes. Reads must be answered from the
replica. Writes must go through `txn` so that pins, `prev` and receipts are
added and the result is checked. If the request cannot be expressed that way,
return `Unimplemented` rather than forwarding it. Add a test that runs it
through two proxy instances against etcd (see
`TestAttackNormalOperationTwoInstances`) and, if it changes data, a test in
which the backend misbehaves.

### Changing a format

Key encryption, records, receipts, the digest and checkpoint records are
persisted or shared between instances. Changing any of them affects data that
already exists and instances that run an older version:

- Records carry a version byte (`valueVersion`). A new record format needs a
  new version and reading support for the old one.
- The key encryption has no version marker. Changing it means re-encrypting
  all data, which is a migration, not a code change.
- The HKDF purpose strings include a version (`veil-proxy v1`). New derived
  keys get new purpose strings; existing ones must not change.
- Digest and checkpoint changes require that all instances of a cluster are
  updated together, or they will report each other as forks.

### Where to put tests

Pure functions and replica rules: unit tests in `proxy_test.go`, building events
with the `put`, `del` and `receipt` helpers and checking rejections with
`mustReject`. Behaviour against a real backend: a `TestAttack...` test using
`startEtcd` and `startProxy`. New parsers of untrusted input get a fuzz target.

## 14. Known limitations

- Visible to the backend: the number of segments of every key (and with it the
  resource structure), the number of objects per prefix, the order of magnitude
  of large values, and when and how much is written.
- Keys attached to a lease (in Kubernetes mainly Events) can be deleted early by
  the backend, because lease expiry happens on the backend.
- A backend that forks and hides the other instances' checkpoint records is only
  reported (`veil_peers_silent`), not refused, because a stopped instance looks
  the same. A single instance has nobody to compare with.
- An instance without checkpoint accepts an empty backend. A backend that shows
  an empty state to all instances at the same time can pretend a new cluster.
- Memory: every instance holds the decrypted key space in memory, roughly what
  the API server's watch cache holds. Measured with 100,000 keys: about 20 µs
  per key to apply (including decryption), 0.5 ms to list 1,000 keys.
- Not supported (not used by kube-apiserver and k3s): range deletes, value and
  range compares in transactions, writes in the failure branch, nested
  transactions, reads before writes in the same success branch.
- Not implemented yet: rotation of the master key, Kubernetes conformance tests
  with real worker nodes, an external security audit.
