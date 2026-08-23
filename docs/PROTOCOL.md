# insnaps protocol specification

Version 0.4 (core), draft. Normative statements use MUST / SHOULD / MAY.

**Platform scope: insnaps is exclusively an Android and iOS mobile application.**
There is no desktop target and none is to be added. The JVM build exists only as
a protocol test environment and must never become a desktop application.

This document specifies what goes on the wire and how a node decides to deliver,
forward or drop. It deliberately makes the routing semantics explicit, because
"broadcast to every neighbour with duplicate suppression" and "bounded-fanout
routing" are different algorithms with different congestion and battery
behaviour, and the difference must not be an accident of implementation.

---

## 0. Security boundary

Two statements govern everything below. They are normative.

**A relay node is not a participant in the end-to-end cryptographic session.** It
MAY inspect the routing metadata necessary to forward a packet — version, flags,
packet id, hop limit, lifetime, recipient tag, payload length. It MUST NEVER
receive plaintext, session keys, or any cryptographic material belonging to an
end-to-end conversation. A node relaying traffic it is not party to holds nothing
that could open it.

**insnaps provides strong end-to-end encryption with limited metadata
protection. It does NOT provide sender or recipient anonymity, and no part of
this project may claim that it does.** Specifically:

- A relay sees that *a* conversation is occurring, its size, and its timing.
- Within one rotation period, a relay can see that several packets share a
  destination (§4).
- The bootstrap addressing mechanism (§7.6) leaks the existence of a contact
  attempt to any observer holding the recipient's public identity key.

These are acknowledged limitations, not defects to be explained away. An
adversary who needs anonymity — not just confidentiality — needs a different
system, or at minimum the onion-routed header variant §4 leaves room for.

---

## 1. Packet format

All integers are big-endian. The header is 31 bytes and is entirely cleartext.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | `version` | MUST be `1`. Receivers MUST drop other values. |
| 1 | 1 | `flags` | bit 0 = broadcast; bits 1-7 reserved, MUST be 0 |
| 2 | 16 | `packetId` | random; duplicate suppression only |
| 18 | 1 | `ttl` | hop limit, 1..64 |
| 19 | 2 | `lifetimeSeconds` | 1..3600 |
| 21 | 8 | `recipientTag` | rotating tag; all-zero = broadcast |
| 29 | 2 | `payloadLength` | 0..512 |
| 31 | n | `payload` | opaque ciphertext + auth tag |

Maximum packet size is 543 bytes. The ceiling is set by BLE, the only universal
transport, even for hops that happen to run over Wi-Fi.

**Relay visibility.** A relay reads only the header. `payload` is sealed by the
sender for the recipient; no relay holds a key that opens it, and a conforming
implementation MUST NOT parse, log or retain payload bytes.

**`packetId` MUST be random** and MUST NOT be derived from sender identity,
sequence, or time. Relays index on it, so any structure becomes a correlation
handle across hops.

**Decoding is strict.** A receiver MUST drop a frame that is short, over-long,
carries an unknown version, has `ttl` or `lifetimeSeconds` out of range, or whose
`payloadLength` does not exactly account for the remaining bytes. The last rule
prevents a peer smuggling unmetered bytes past the memory budget.

---

## 2. Routing semantics

insnaps has **no route discovery and no routing tables to destinations**. It is
opportunistic epidemic forwarding with duplicate suppression. Nodes do not know
the topology and never compute a path.

Two distinct forwarding modes:

### 2.1 Broadcast (`flags` bit 0 set, `recipientTag` all-zero)

A node receiving a new broadcast packet MUST deliver it locally, and MUST forward
it to a selection of its current neighbours, excluding the one it arrived from.

The selection is **adaptive bounded fanout**, and it is the specified default:

```
  neighbours <= 6                  -> every neighbour (full flooding)
  mean neighbour quality >= 0.65   -> 6 neighbours
  mean neighbour quality >= 0.40   -> 10 neighbours
  otherwise                        -> 16 neighbours
```

always clamped to the number of neighbours available.

*Rationale.* A fixed fanout and full flooding each fail in the other's best case.
Capping the fanout in a thin neighbourhood makes some nodes structurally
unreachable rather than merely less likely to be reached: with similarly-scored
neighbours the ranking is near-deterministic, so the same peers sit below the cut
on every node's list and never receive the packet. Retry does not fix that; it is
a property of the selection, not of luck. Flooding a dense neighbourhood, in
turn, spends traffic and battery on redundancy nobody needs. Widening the fanout
as conditions worsen — and collapsing to flooding when the neighbourhood is too
thin to restrict safely — keeps flooding's resilience without its cost.

*Measured (v0.4, docs/BENCHMARKS.md).* Against full flooding at 1,000 nodes:
identical coverage in sparse, normal and dense topologies, with 74% fewer frames
in a dense mesh and no difference at all in a sparse one.

Full flooding remains a valid policy and MAY be selected — as an emergency or
diagnostic mode, or by a deployment that prefers it. A node's policy never
appears on the wire, so nodes running different policies interoperate.

*Known gap.* Neighbour quality is derived from what the transport reports:
freshness, its reliability hint, and failed send calls. **End-to-end packet loss
is invisible to it** — a BLE write without response reports success once the link
accepts the frame, so a lossy-but-connected link looks healthy and the fanout
does not widen. Closing this needs a signal the transport can actually observe
(acknowledged writes, or a receive-side report), and is an open item for the BLE
work rather than a protocol change.

*Cost.* Traffic for one broadcast is bounded by `O(nodes x fanout)`, not by the
exponential a cyclic graph would otherwise produce, because each node forwards a
given `packetId` at most once (§3). Under the adaptive default, cost per node is
bounded by the fanout rather than by neighbour density, which is what removes
crowd size as a scaling risk.

*Measured (v0.3/v0.4, docs/BENCHMARKS.md).* Amplification is flat from 100 to
10,000 nodes. Under flooding it equals average degree (7.0x at degree 8, 22.7x at
degree 24); under the adaptive default it is capped near 6x regardless of
density. Coverage is 100% at every scale tested, and 99.3% under 50% packet loss.

### 2.2 Unicast (`recipientTag` set)

A node receiving a new unicast packet:

1. MUST deliver it locally if the tag is its own (§4), and MUST then stop — a
   delivered unicast packet is not forwarded further.
2. Otherwise MUST forward it to at most `FANOUT` neighbours, chosen highest-first
   by availability score (§5), excluding the neighbour it arrived from.

`FANOUT` is 3 by default. This is a **tunable congestion parameter, not a
protocol constant**: it does not appear on the wire and nodes with different
values interoperate.

Because forwarding is opportunistic, unicast delivery is best-effort and
probabilistic. Nodes with equal scores MUST be ordered with a random tie-break,
so a given peer is not permanently excluded from every node's top-`FANOUT`.

### 2.3 Hop limit

A forwarding node MUST decrement `ttl` and MUST drop the packet instead of
forwarding when the result would be zero. Delivery to the local recipient is NOT
gated on `ttl`: a packet arriving with `ttl = 1` is still delivered.

### 2.4 Store-and-forward

A packet with no available neighbour MUST remain buffered until it expires — it
MUST NOT be dropped merely because forwarding failed. This is what lets a moving
carrier bridge two disconnected groups.

---

## 3. Duplicate suppression

Every node keeps a bounded, expiring set of recently seen `packetId`s. A packet
whose id is already present MUST be dropped without delivery or forwarding.

Without this, any cycle in the mesh graph — and a dense mesh is almost entirely
cycles — turns one packet into a broadcast storm. **Duplicate suppression, not
fanout, is what bounds traffic in this protocol.**

The set is bounded in both entries and age because it is directly attacker-facing:
an attacker can mint unlimited fresh packet ids. When full it evicts in insertion
order, which costs correctness only for traffic older than the eviction horizon.

A node MUST record the id of packets it originates, so a copy looping back
through the mesh is not re-forwarded.

---

## 4. Addressing

`recipientTag` = first 8 bytes of `HMAC-SHA256(pairwiseSecret, "insnaps-tag-v1" || epoch)`
where `epoch = unixSeconds / rotationSeconds` (default 900).

Only the two endpoints hold `pairwiseSecret`, so only the recipient recognises the
tag. A receiver MUST accept the current epoch and its two neighbours (`epoch ± 1`):
peers have no synchronised clock and a packet may sit in a relay buffer. A tag is
therefore valid for three rotation periods.

**Known limitation.** Within one rotation period a relay can see that several
packets share a destination, and learns that *some* conversation is occurring.
This is the accepted cost of letting relays route without pure flooding. It is
confined to this one field: onion-routed per-hop headers can replace it without
changing the router, the relay buffer or the packet codec.

---

## 5. Relay availability scoring

Neighbours are ranked by a 0..1 score combining freshness (0.40), a
platform-supplied reliability hint (0.30), observed forwarding success with
Laplace smoothing (0.25), and a link-speed bonus (0.05).

The score MUST NOT contain a platform-specific term. Facts like "this peer is a
backgrounded iOS app and cannot forward" reach the core only through the
transport's `reliabilityHint`. The core does not know which radios exist.

---

## 6. Resource limits

The relay subsystem targets a **25 MB** total budget, of which 16 MB is the relay
buffer. This is configuration, not a protocol constant — nothing about it appears
on the wire — but the *eviction behaviour* it produces is observable, so it is
specified here:

1. Expired packets are dropped first.
2. A neighbour already holding its quota (default 10% of the buffer) is **refused
   admission**. It MUST NOT be served by evicting another peer's traffic. This is
   the denial-of-service bound: without it, one flooding peer evicts everyone
   else and silently partitions the mesh around itself.
3. Only then, if the buffer is still full, the packet nearest its own expiry is
   evicted.

Rule 2 deliberately precedes rule 3.

Expiry is always evaluated against the **local clock of the node holding the
packet**, never against a timestamp in the packet. Peers have no synchronised
clock and a sender-supplied absolute expiry would be attacker-controlled.

---

## 7. Session layer

The mesh carries opaque payloads; this section specifies what is inside them.

### 7.1 Envelope

Every payload begins with a one-byte type, in cleartext:

| Type | Meaning |
|---|---|
| `0x01` | handshake message 1 (`e, es, s, ss`) |
| `0x02` | handshake message 2 (`e, ee, se`) |
| `0x03` | sealed message, or an unencrypted broadcast |

The type byte tells a relay that a handshake is occurring. It does not tell it
who is party to one.

### 7.2 Handshake

**Noise IK over X25519, AES-256-GCM, SHA-256.** The initiator knows the
responder's static key in advance — that is what a contact *is* in insnaps — and
sends its own static key encrypted, so a relay watching the exchange does not
learn who is initiating. One round trip.

Implementations MUST reject a peer contribution that is a small-order point.

*Implementation status: RELEASE BLOCKER.* The primitives are platform-supplied;
the Noise pattern composition is hand-written. **Replacing it with a vetted Noise
implementation, or completing an independent audit of it, is a blocking
requirement for any release to users — not a future improvement.** No build
carrying the hand-written composition may ship, be distributed for real use, or
be described as production-ready. It is isolated behind `HandshakeResult` so the
substitution is local and does not disturb the rest of the protocol.

### 7.3 Message framing

```
  counter (8 bytes, cleartext) || AEAD ciphertext || tag
```

Nonce is `0x00000000 || counter`. Keys are directional, derived by the final
HKDF split, so the two directions never share a nonce space. The counter is
cleartext because the recipient needs it to derive the nonce before decrypting,
and it is bound into the AEAD associated data, so editing it in flight produces
an authentication failure.

### 7.4 Replay protection

A 64-bit sliding window per session, over the message counter. A counter already
seen, or older than the window, MUST be rejected.

This is separate from mesh-layer duplicate suppression (§3): that one is a
bandwidth measure over `packetId`, while this is a cryptographic guarantee that a
captured message cannot be replayed into a session later.

The window MUST advance only for messages that have already authenticated.
Advancing on receipt would let anyone burn counter slots with forgeries.

### 7.5 Session expiry

A session MUST be destroyed when any bound is reached: maximum age (default 1
hour), idle time (default 15 minutes), or messages sent (default 2^20). Expiry
bounds the value of a compromised key and keeps unused key material from sitting
in memory.

### 7.6 Handshake addressing

Handshake packets in **both** directions use a *bootstrap* tag:
`HMAC(recipientStaticPublicKey, "insnaps-init-v1" || epoch)`.

The initiator has no pairwise secret yet. The responder does by the time it
replies, but MUST NOT use it, because the initiator cannot recognise a pairwise
tag until its own handshake completes.

**Known limitation.** A bootstrap tag is keyed by a public value, so anyone
holding a peer's static public key can recognise when that peer is being
contacted. This is strictly weaker than a pairwise tag and applies only to
handshake packets; every subsequent message uses §4 addressing.

### 7.7 Confidentiality boundary

Encryption happens strictly above the mesh layer and decryption strictly above
it. The routing engine holds no key, has no reference to the session store, and
has no code path that could obtain one. A relay running the same software with no
session for the traffic passing through cannot produce plaintext for it.

**Broadcasts are not encrypted** and carry no confidentiality. They exist for
discovery and public announcements.

---

## 8. Memory

Only one value is intentionally persisted: the long-term identity private key,
in the Android Keystore or iOS Keychain. Messages, routing state, relay buffers,
session keys, peer records and conversation state are RAM-only.

Key material is wrapped so ownership is explicit and is zeroed when a session
ends. Zeroing is a best-effort reduction of exposure window, **not** an erasure
guarantee: a garbage collector may already have copied a buffer, and the OS may
have paged it out. The guarantee insnaps actually rests on is the weaker,
achievable one — key material is never written to storage and is dropped when the
session ends.

Every structure that grows with traffic is bounded, and a configuration whose own
bounds exceed its budget is rejected at construction rather than discovered under
load.

**Uninstall behaviour differs by platform and MUST be reconciled.** Android
Keystore clears on uninstall; iOS Keychain items survive it. iOS implementations
MUST store the identity `WhenUnlockedThisDeviceOnly` and clear any existing item
on first launch after install.

---

## 9. Concurrency

The protocol core is single-threaded by contract. Transport implementations MUST
deliver every callback on one thread, and callers MUST drive the node from that
same thread — one serial queue or handler per node.

This is not the default on either platform: Android's `BluetoothGattCallback`
fires on binder threads and CoreBluetooth delivers on whichever queue the central
manager was given. Both MUST be funnelled onto the node's own queue before
reaching the core.

---

## 10. What is NOT yet established

The JVM simulation validates protocol behaviour — delivery, suppression, hop
limits, expiry, quota enforcement — under a synthetic transport. It says nothing
about radio behaviour. The following are **explicitly unclaimed** and become
acceptance tests once real transports exist:

**Settled in v0.3 by simulation** (docs/BENCHMARKS.md) — protocol behaviour only,
under a synthetic transport:

| Question | Result |
|---|---|
| Scale to 10,000 nodes | coverage 100%, amplification flat at ~degree, peak node memory 2 KB |
| Broadcast cost at density | viable to degree ~24; bounded fanout 6 is strictly better and available |
| Behaviour under loss / churn / duplication | 99.3% coverage at 50% loss; 99.9% under combined faults |
| Memory under attack | held at 2.9 MB against a 25 MB ceiling under a 54 MB flood |
| Crash resistance | no peer-supplied input produced a crash across ~3.3 M hostile frames |

**Still open, and requiring physical devices:**

| Question | Acceptance test to be written |
|---|---|
| **Devices needed per unit distance** | **how many real phones are required to hold a usable route over a given geographic distance — the question any coverage claim actually rests on** |
| Multi-hop range | measured coverage vs. node density on real hardware |
| Real throughput and battery | frames/second and battery draw on a device, not a frame-count proxy |
| Discovery latency | time to first delivery after two groups come into range |
| Connection stability | delivery rate under real mobility |
| Real memory ceiling | measured RSS of the subsystem against the 25 MB target |
| Handshake cost on BLE | round-trip latency for a 1-RTT handshake over a real link |
| iOS background behaviour | relay reliability of a backgrounded app in practice |

No range figure, hop count, or scale figure is claimed by this specification.
