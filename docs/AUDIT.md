# Liteway project audit

Date: 2026-09-24 · Scope: whole repository at `ffe9a02` (`liteway-core`, `liteway-net`,
`litewayd`, `liteway-cert`, CI, packaging, docs).

The audit covers connection reliability, protocol and cryptographic design,
authorization, denial of service, memory safety, performance, code structure,
testing, and operations. Findings are split into **fixed in this change** and
**open**, each with a severity and a concrete recommendation.

Severity is about impact on a deployed mesh: **critical** = silent loss of
confidentiality/integrity or a network that stops working, **high** = sessions fail
or stay degraded, **medium** = exploitable by a mesh member or a real operational
risk, **low** = quality, ergonomics, or defence in depth.

---

## 1. Why peer-to-peer sessions were failing

The reported symptom — *"sometimes the P2P connection does not get built in time and
falls back to the relay"* — has three independent causes, all confirmed by
measurement.

### 1.1 A handshake was 28 datagrams that all had to arrive, once

A handshake message carries a full certificate (ML-DSA public key 1952 B, CA
signature 3309 B) serialized as JSON with hex encoding, plus an ML-KEM public key or
ciphertext and the node's own hybrid signature:

```
certificate on the wire : 10 986 bytes
handshake_1             : 15 663 bytes -> 14 UDP fragments
handshake_2             : 15 612 bytes -> 14 UDP fragments
```

Nothing retransmitted. A session therefore required 28 consecutive datagrams to
survive, so the probability of success was `(1 - loss)^28`: 57 % at 2 % loss, 24 % at
5 %, 5 % at 10 %. Every failure waited out `relay_fallback_timeout_secs` and then
pinned the session to the relay.

### 1.2 The relay fallback was terminal

`PendingHandshake.addr` was **overwritten** with the relay address when the fallback
fired, and `relay_attempted` was never cleared. After that no direct handshake was
ever attempted again, and nothing ever moved an established session off a relay.
Once relayed, always relayed — until the peer expired 300 s later.

### 1.3 A duplicated handshake silently produced two different session keys

This one is a correctness bug, not just a delay, and it was reachable by the relay
fallback itself (it re-sent the *same* `handshake_1` bytes through the relay).

* The responder processed each `handshake_1` copy independently, deriving a **new**
  session key each time and replacing its peer entry with the latest.
* The initiator removed its pending state on the **first** `handshake_2` it saw and
  dropped later ones (`no pending handshake for ...`).

If the copies arrived in different orders on the two sides — which is exactly what a
direct path racing a relayed path produces — the two ends ended up holding different
keys while both logged a completed handshake. Every packet was then dropped at the
far end with no error visible to the user, for up to 300 s.

A regression test for this is in
`liteway-core/tests/integration.rs::repeated_handshake_1_derives_a_different_session`.

### 1.4 Measured effect of the fix

Two daemons over a UDP proxy that drops a fixed fraction of datagrams in both
directions, 45 s per run, measuring whether a session is established at all:

| Packet loss | before | after |
|---|---|---|
| 5 %  | connects | connects |
| 10 % | **never connects** | connects |
| 20 % | **never connects** | connects and stays up |
| 30 % | **never connects** | connects, survives with occasional rebuilds |

End-to-end in two network namespaces with a lighthouse/relay in between
(`ping` over the tunnel, 0 % loss for both):

* direct path reachable → session is direct, first packet only pays discovery,
* direct path blocked → relay fallback, traffic flows,
* direct path unblocked mid-session → both ends punch it open and the session
  **moves onto the direct path within one probe interval, without a re-handshake**
  (`peer ... moved off the relay`).

---

## 2. Fixed in this change

| # | Severity | Finding |
|---|----------|---------|
| F1 | **critical** | Duplicate `handshake_1` derived a second session key on the responder while the initiator kept the first; both ends believed the session was up and all traffic was dropped. Responses are now cached by the hash of the request and a repeat is answered with the *same* `handshake_2`. |
| F2 | **high** | No handshake retransmission. Handshakes are now retransmitted with a 0.5 s→3 s backoff until `handshake_timeout_secs`. |
| F3 | **high** | Retransmissions used a fresh fragment message id, so copies never merged at the receiver and each attempt still needed a lossless round. Retransmissions now reuse one message id and the assembler unions them — a fragment only has to arrive in *one* attempt. |
| F4 | **high** | Relay fallback replaced the direct target permanently. The relay is now an *additional* target for the same handshake; the direct attempt keeps running and whichever answers first wins. |
| F5 | **high** | Nothing ever moved a relayed session back to a direct path. Both ends now punch the peer's direct endpoint with a small authenticated probe (5 s, doubling to 30 s) and the session switches over as soon as one gets through — no new handshake, no dropped packets. |
| F6 | **high** | Keepalives were sent to lighthouses only. Peer-to-peer NAT mappings therefore expired silently and dead sessions lingered for 300 s. All sessions are now kept alive; a session silent in *both* directions past `keepalive_timeout_secs` is torn down and rebuilt. |
| F7 | **medium** | Anyone knowing the network secret could cancel a handshake in flight: `pending` was removed *before* `handshake_2` was verified. It is now only consumed on success (`a_bogus_handshake_2_does_not_consume_the_initiator_state`). This required the initiator's X25519 secret to become reusable. |
| F8 | **medium** | The certificate in `handshake_2` was never checked against the peer we dialled, so another member could answer in place of the intended peer. Now rejected with a warning. |
| F9 | **medium** | Lighthouse addresses were resolved once at startup; a lighthouse on a dynamic address was unreachable forever after it moved. Now re-resolved while disconnected. |
| F10 | **medium** | "Is this peer a lighthouse" was guessed from addresses and names in three places, and a `HashSet<SocketAddr>` of "established" endpoints duplicated the peer table and could drift out of sync. Replaced by an explicit peer-id binding. |
| F11 | **medium** | Both the UDP and the TUN loop were non-blocking with a fixed 10 ms sleep: up to 20 ms of added latency per packet and constant CPU when idle. UDP now blocks with a receive timeout; the TUN loop polls tightly right after traffic and backs off when idle. |
| F12 | **medium** | Inbound data packets were only checked against the *source* rules. A member could push traffic for any destination into the local stack, using the node as an unrequested router. The destination must now be covered by this node's own certificate. |
| F13 | **medium** | `deserialize_packet` copied the whole payload just to read the 16-byte header — on every datagram, including junk, and two or three times per packet. The header is now read in place. |
| F14 | **medium** | `PacketBody` embedded a certificate by value: ~5.4 KiB moved for *every* decrypted packet, data packets included. Boxed. |
| F15 | **medium** | `hybrid_kem::{encapsulate, decapsulate, decapsulate_static}` panicked via `unwrap()` on malformed key or ciphertext bytes. They now return `Option`. |
| F16 | **medium** | Peer expiry used wall-clock time, so an NTP step could expire every peer at once or keep dead ones. All daemon timing is now monotonic (`Instant`). |
| F17 | **low** | Unknown config keys were silently ignored — a misspelled `am_lighthouse` left a node quietly not being a lighthouse. Unknown keys are now rejected, and values are validated (`keepalive_timeout > keepalive_interval`, `relay_fallback < handshake_timeout`, non-zero intervals, sane MTU). |
| F18 | **low** | A node with an expired certificate, or a key file belonging to a different certificate, started normally and only failed at handshake time with an opaque error. Both are checked at startup. |
| F19 | **low** | Kernel routes were only removed on an explicit `Disconnect`, so expiring peers leaked routes. Removal is now part of dropping a peer. |
| F20 | **low** | Worker threads were detached and shutdown did not wait for them; disconnect packets raced process exit. Threads are named and joined. |
| F21 | **low** | `discovery_pending` grew without bound (one entry per destination IP ever probed). Pruned. |
| F22 | **low** | README documented `gen-ca -y 10`; the flag is `-v/--validity-years`. |
| F23 | **low** | Log lines had no timestamps, which made connection problems hard to diagnose. Timestamps enabled. |

---

## 3. Open findings

### 3.1 Protocol and cryptography

**O1 — Handshake size (medium, reliability).** The certificate goes on the wire as
JSON with hex-encoded keys: 10 986 B for ~5.4 KiB of key material. A compact binary
encoding would roughly halve the handshake and cut it from 14 fragments to ~7,
squaring the loss resilience. This changes the signed transcript, so it belongs in a
`HANDSHAKE_VERSION` 3 with a negotiated fallback.

**O2 — Random packet nonces (medium).** Every packet draws a random 96-bit
ChaCha20-Poly1305 nonce under a session key that never changes. Collision
probability reaches ~2⁻³³ at 2³² packets, and a nonce repeat in
ChaCha20-Poly1305 leaks the Poly1305 key for those packets. The packet already
carries a replay-checked `seq`: deriving the nonce from `seq` (plus a direction
byte) removes the birthday bound entirely and saves 12 bytes of RNG per packet.

**O3 — No rekeying (medium).** A session key lives until the peer expires or a node
restarts. There is no rekey after N packets or N minutes, so forward secrecy is
coarse and O2's counter budget is never reset.

**O4 — 64-packet replay window (low/medium).** `REPLAY_WINDOW_BITS = 64` is small for
a multi-queue or multi-path link; legitimate reordering beyond 64 packets is dropped
and logged as a replay. 1024–8192 bits is the usual choice.

**O5 — `network_secret` is a single shared static key (medium, design).** It keys the
header mask *and* the handshake AEAD for the entire mesh. Any member — or anyone who
obtains the file — can read and forge network headers, inject fragments, address
relays, and feed the reassembler. It also cannot be rotated without a flag day.
Worth stating explicitly in the README as the membership boundary, and worth a
rotation mechanism (accept two secrets during a window).

**O6 — No certificate revocation (medium).** A leaked node key is valid until
`not_after`. There is no CRL, blocklist, or short-lived-certificate story. Nebula
solves this with a blocklist distributed in the config; the same would fit here.

**O7 — No firewall/ACL layer (medium, design gap).** `groups` are only consulted for
`route:` grants. Any valid member may send any traffic to any other member's IP and
ports. Nebula's per-node firewall rules (by port, protocol, group, CA) are the
feature this most visibly lacks for a mesh VPN.

**O8 — Relay authorization and accounting (medium).** An `am_relay` node forwards for
any `dst_peer_id` in its peer table, with no allow-list, no per-peer rate limit and
no byte accounting. Any member can use any relay as a free reflector and exhaust its
uplink.

**O9 — Handshake CPU is a member-reachable DoS (medium).** Processing a
`handshake_1` costs an ML-DSA verification plus an ML-KEM encapsulation (~ms), with
no per-source rate limit. The ±300 s timestamp window lets a member replay captured
handshakes; exact replays are now absorbed by the response cache, but distinct
captured handshakes are not. Add a per-source token bucket and remember recent
handshake nonces.

**O10 — Header mask nonce is 64 bits (low).** Two packets sharing a `mask_nonce` XOR
to reveal the header structure to a passive observer (birthday bound at ~2³²
packets). Only a metadata-masking property, and only against an observer who does
not already have the network secret, but a 96-bit nonce or a per-session counter
would close it.

**O11 — CA key handling (low).** `liteway-cert` writes key files `0600` with
`create_new` (good) but the CA key is unencrypted and the docs do not say to keep it
offline. Recommend a passphrase option and an explicit note.

### 3.2 Robustness and performance

**O11b — Roaming has no path validation (low/medium).** A session switches its send
address the moment an authenticated packet arrives from a new one. This is what
WireGuard and Nebula do, and it is what lets a relayed session go direct for free,
but it assumes reachability is symmetric. Where it is not — a firewall that passes
peer→us but drops us→peer — the switch sends traffic into a hole until the
keepalive timeout rebuilds the session (~30 s). Validating the new path first
(probe it, switch only when the matching ack comes back from it, keep the old
address meanwhile) would remove that window.

**O11c — Relay chains have no hop limit (low).** A relay forwards to
`peers[dst_peer_id].addr` with no hop count. If two relays each believe the other
is the way to the same peer — a misconfiguration or a deliberate one by a member —
a datagram can be bounced between them indefinitely. The masked header has four
reserved bytes that a TTL could use, at the cost of a protocol revision.

**O12 — Only the first resolved address of a lighthouse is used (low/medium).** If a
lighthouse name resolves to several addresses (A + AAAA, or several hosts), the rest
are never tried, so a dual-stack lighthouse whose first address is unreachable is
simply down. Try all resolved endpoints.

**O13 — Fragment assembler is O(pending) per fragment (low/medium).**
`FragmentAssembler::source_usage` scans every pending message for each arriving
fragment; with the 1024-message cap this is quadratic and is reachable by any member
against a lighthouse or relay. Index the pending map by source.

**O14 — Single receive thread (low/medium).** One thread decrypts everything, so
throughput is capped at one core and an expensive handshake delays data packets.
Hand handshake processing to a worker, or shard the receive path.

**O15 — One `send_to`/`recv_from` per packet (low).** No `sendmmsg`/`recvmmsg`
batching and no GSO; fine for a mesh, limiting for a gateway.

**O16 — Every route change spins up a Tokio runtime (low).** `liteway-net::add_route`
builds a current-thread runtime and a fresh netlink connection per call, and a peer
with many subnets pays that per route. Keep one runtime and one handle.

**O17 — No runtime visibility (low).** There is no way to ask a running daemon for
its peers, paths, or relay usage — no status socket, no signal dump, no metrics.
This is the single most useful thing to add for supporting real deployments.

**O18 — macOS cannot install routes (low).** `liteway-net` implements
`add_route`/`del_route` on Linux and Windows only; on macOS they return
`Unsupported`, so advertised subnets silently do not work. It is logged as a
warning; it should be documented or implemented.

**O19 — Windows privilege check is a heuristic (low).** Reading
`C:\Windows\System32\config\SAM` to infer admin rights is fragile; use the proper
token check.

### 3.3 Code quality and process

**O20 — `litewayd` is still one large file (low).** It went from 2 236 lines of
closure-captured `Arc`s to a `Node` type plus a testable `state` module, but
`main.rs` is still ~1 800 lines. Splitting handshake, lighthouse and relay handling
into their own modules is the natural next step.

**O21 — Dead public API in `liteway-core` (low).** `hybrid_kem::{generate_hybrid_keypair,
encapsulate, decapsulate, decapsulate_static}`, `kdf::{derive_session_key,
derive_payload_key}` and `hex_serde::size_1184` are only used by tests. Remove them
or mark them test-only; every public function is attack surface to keep correct.

**O22 — Library errors are `anyhow` (low).** `liteway-core` depends on `thiserror` but
does not use it; a library should expose typed errors so callers can distinguish
"bad signature" from "malformed packet".

**O23 — `unsafe impl Send` on the TUN types (low).** `TunDevice`/`TunReader`/`TunWriter`
assert `Send` with no justification. Check whether the `tun` crate's types are
already `Send` and delete the assertion, or document why it holds.

**O24 — MSRV is unverified (low).** The README claims Rust 1.75+, but the code uses
`io::Error::other` (1.74), `u32::div_ceil` (1.73) and `Option::is_some_and` (1.70).
Set `rust-version` in the workspace manifest and check it in CI.

**O25 — Docker image (low).** `Dockerfile` builds without `--locked`, so an image can
be built from different dependency versions than CI tested. The repo's
`docker-compose.yml` and the README's differ in mounted file names.

**O26 — No release/security process (low).** No `SECURITY.md`, no CHANGELOG, no
signed releases or checksum signing (the nightly workflow publishes `SHA256SUMS`
unsigned). For a VPN distributing binaries, signing matters.

### 3.4 Testing and CI

Before this change the repository had **no CI that built or tested the code** — only
Docker and release-binary workflows. `cargo fmt`, `cargo clippy` and `cargo test`
never ran on a pull request.

Added in `.github/workflows/ci.yml`: fmt + clippy (`-D warnings`) + tests on Linux,
plus Windows and macOS builds (the platform-specific TUN and routing code is
otherwise never compiled in CI) and `cargo-audit` for advisories.

Test coverage today is good on primitives (packet, crypto, certificates, handshake:
62 integration tests) and now covers the connection state machine (19 unit tests:
keepalive, teardown, path probing, retry backoff, relay fallback, handshake cache).
Still missing, in priority order:

1. A loopback test for two `Node`s exchanging data packets, including the
   source/destination authorization checks.
2. Lossy-link tests in CI (the proxy used for the measurements above is ~40 lines).
3. Fuzzing of `packet::decrypt_packet`, `frag::FragmentAssembler::feed` and the
   handshake parsers — all three parse attacker-influenced bytes.

---

## 4. What is solid

Worth stating, since the list above is all problems:

* **The cryptographic core is well built.** Hybrid X25519+ML-KEM-768 and
  Ed25519+ML-DSA-65 are used correctly: both signatures must verify, both KEM halves
  feed one KDF, and the session key binds the full handshake transcript, so a
  downgrade needs both primitives broken.
* **Traffic keys are directional** and derived per peer pair, so a reflected packet
  cannot be replayed back at its sender.
* **Packet headers are authenticated** as AEAD associated data, and the packet kind
  in the header is checked against the kind inside the plaintext.
* **Secrets are zeroized** on drop, across peer state, handshake results and key
  files, and `Zeroizing` is used for intermediates.
* **Certificates are verified on every use**, including certificates relayed by a
  lighthouse, and a lighthouse cannot hand out a peer for an address that peer's
  certificate does not authorize.
* **Source addresses are enforced** against the peer's certificate, which is the
  check most small mesh implementations forget.
* **Fragment reassembly is bounded** per source and in total, with a size cap and a
  cleanup sweep.

---

## 5. Recommended order of work

1. **O7 firewall rules** and **O6 revocation** — the two things a mesh VPN is
   expected to have before production use.
2. **O2 deterministic nonces** and **O3 rekeying** — cheap, and they remove the only
   structural cryptographic risk in the data path.
3. **O9 handshake rate limiting** and **O8 relay authorization** — member-reachable
   resource exhaustion.
4. **O1 compact certificate encoding** — halves the handshake and, with the
   retransmission now in place, makes lossy links essentially a non-issue.
5. **O17 runtime status output** — pays for itself the first time someone reports a
   connection problem.
6. **O12–O16, O20–O26** — steady cleanup.
