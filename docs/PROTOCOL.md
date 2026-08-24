# insnaps protocol specification

Version 0.8.1 (core), draft. Normative statements use MUST / SHOULD / MAY.

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

**Which neighbours are chosen is normative, not an implementation detail.** The
fanout MUST be sampled from the eligible neighbours *without replacement, with
probability proportional to their availability score* — not taken as the
highest-scoring `k`.

Deterministic top-`k` selection was measured to deliver **55%** of a fully
connected geographic mesh against flooding's 100%. The score is driven by peer
quality — platform, foreground state — which carries no directional information,
so every node selects the same favoured neighbours at every hop and the flood
front stops expanding outward. This never appeared on random graphs, where any
subset of neighbours spreads a packet everywhere; it appears immediately once
neighbours are the devices physically within radio range.

A high-quality relay MUST remain more *likely* to be selected. It MUST NOT be
selected every time.

*Rationale.* A fixed fanout and full flooding each fail in the other's best case.
Capping the fanout in a thin neighbourhood makes some nodes structurally
unreachable rather than merely less likely to be reached: with similarly-scored
neighbours the ranking is near-deterministic, so the same peers sit below the cut
on every node's list and never receive the packet. Retry does not fix that; it is
a property of the selection, not of luck. Flooding a dense neighbourhood, in
turn, spends traffic and battery on redundancy nobody needs. Widening the fanout
as conditions worsen — and collapsing to flooding when the neighbourhood is too
thin to restrict safely — keeps flooding's resilience without its cost.

*Measured (v0.7, docs/BENCHMARKS.md).* On geographic topology, 1,000 devices in
1 km²: **99.9% delivery at 6.0x amplification**, against flooding's 100% at 27.0x
and gossip's 100% at 13.6x. Across 100 seeds: mean 99.8%, p5 99.6%, worst 99.4%.
Unchanged on the original random-graph suite: 100% at 5.7x.

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
  channel (4 bytes) || counter (8 bytes) || AEAD ciphertext || tag
```

Nonce is `channel || counter`. Keys are directional, derived by the final HKDF
split, so the two directions never share a nonce space, and each channel has its
own counter space, so two channels can never collide on a nonce. Both header
fields are cleartext because the recipient needs them to derive the nonce before
decrypting, and both are bound into the AEAD associated data, so editing either
produces an authentication failure.

### 7.3.1 Channels

Channel `0` is the **message channel** and carries conversation. Any other channel
is opened for a specific purpose — currently a file transfer — and MUST be opened
before its frames will decrypt, and closed when the purpose ends.

A frame for a channel that is not open MUST be refused **before any key is used**.
That is what prevents a chunk captured from a finished transfer being replayed
into a still-live session.

Open channels MUST be bounded (16 by default), so an attacker cannot grow the
channel table by opening transfers.

### 7.4 Replay protection

**Channel 0** uses the sliding window (§7.5). **Other channels delegate replay
protection to the layer above**, which is required to have an exact mechanism of
its own.

*Why the split exists.* A window is the right instrument for conversation, where
messages are few and roughly ordered. It is the wrong instrument for a burst of
234,000 file chunks that the mesh will reorder arbitrarily: with a 64-message
window, exactly 64 of 112 chunks survived a transfer, rejected as replays,
silently. Widening the window to 1024 masked the symptom; separating the channels
removes the cause. A transfer already knows its own geometry — transfer id,
manifest, chunk index, digest, expected size — and can therefore tell chunk
#800 from a replay exactly, without inferring anything from arrival order.

### 7.5 The message-channel window

A 1024-bit sliding window per session, over the message counter. A counter already
seen, or older than the window, MUST be rejected.

This is separate from mesh-layer duplicate suppression (§3): that one is a
bandwidth measure over `packetId`, while this is a cryptographic guarantee that a
captured message cannot be replayed into a session later.

The window MUST advance only for messages that have already authenticated.
Advancing on receipt would let anyone burn counter slots with forgeries.

### 7.6 Session expiry

A session MUST be destroyed when any bound is reached: maximum age (default 1
hour), idle time (default 15 minutes), or messages sent (default 2^20). Expiry
bounds the value of a compromised key and keeps unused key material from sitting
in memory.

### 7.7 Handshake addressing

Handshake packets in **both** directions use a *bootstrap* tag:
`HMAC(recipientStaticPublicKey, "insnaps-init-v1" || epoch)`.

The initiator has no pairwise secret yet. The responder does by the time it
replies, but MUST NOT use it, because the initiator cannot recognise a pairwise
tag until its own handshake completes.

**Known limitation.** A bootstrap tag is keyed by a public value, so anyone
holding a peer's static public key can recognise when that peer is being
contacted. This is strictly weaker than a pairwise tag and applies only to
handshake packets; every subsequent message uses §4 addressing.

### 7.8 Confidentiality boundary

Encryption happens strictly above the mesh layer and decryption strictly above
it. The routing engine holds no key, has no reference to the session store, and
has no code path that could obtain one. A relay running the same software with no
session for the traffic passing through cannot produce plaintext for it.

**Broadcasts are not encrypted** and carry no confidentiality. They exist for
discovery and public announcements.

---

## 8. Application layer

Everything above the session layer travels inside the sealed payload. A relay
sees ciphertext of an opaque length and nothing else — not the message type, not
the conversation mode, not the expiry, not a file name.

### 8.1 Message format

```
  version    1     MUST be 1
  mode       1     0 = normal, 1 = private
  type       1     1 text, 2 file manifest, 3 file chunk, 4 receipt
  expiry     1     0 none, 1 view-once, 2 = 30s, 3 = 5m, 4 = 1h, 5 = 24h
  messageId  8
  body       n     up to 475 bytes
```

A private message MUST carry a non-zero expiry; a receiver MUST reject one that
does not. Unknown type or expiry codes MUST be rejected rather than guessed —
guessing an expiry wrong destroys a message early or keeps it too long.

**The mode is inside the ciphertext deliberately.** Putting it in the packet
header would have been simpler and would have leaked precisely the metadata
private mode exists to protect: which conversations are sensitive.

### 8.2 Conversation modes

Both modes use the same E2EE and the same mesh. The difference is entirely at the
**endpoints**; a relay cannot distinguish them and behaves identically for both.

| | Normal | Private |
|---|---|---|
| End-to-end encryption | required | required |
| Endpoint history | retained, encrypted at rest | RAM only |
| Expiry | optional | required |
| Relay storage | none | none |
| Relay decryption | impossible | impossible |
| Capture protection | OS default | strongest available |
| Copy / clipboard / share | permitted | blocked |
| Notification content | shown | redacted |

### 8.3 Private mode lifecycle

Private plaintext exists only in RAM, in a store with no serialization path of
any kind. It is destroyed and its buffer zeroed when: the expiry deadline passes,
a view-once message is viewed, the user deletes it, or the app shuts down.

View-once is destroyed **at the view**, not on a later sweep, so the plaintext is
gone the moment the view ends. An unviewed view-once message still expires under
a 24-hour ceiling, so it cannot live indefinitely.

As with session keys, zeroing narrows the exposure window and is not an erasure
guarantee (§10).

---

## 9. File transfer

Files travel as ordinary messages: a manifest, then chunks, each sealed
end-to-end and each carried in one packet.

### 9.1 Limits

| | |
|---|---|
| Maximum file | 100 MB (configurable; does not appear on the wire) |
| Chunk payload | 448 bytes |
| Concurrent inbound transfers | 8 (bounds attacker-opened transfers) |

**Chunk size is set by the packet, not by convenience.** A packet carries at most
512 payload bytes, and after the AEAD tag, the application header and the chunk
index there are 459 left. A 16–64 KB chunk — the usual figure for file transfer —
cannot fit and would require a fragmentation layer that duplicates what the mesh
already does.

**The practical consequence must be stated rather than buried.** 100 MB is about
234,000 packets. At realistic BLE mesh throughput — single-digit KB/s over a
multi-hop path — that is hours, not minutes. Large files are *supported*; they
are not *fast*, and nothing in this project should imply otherwise. Same-platform
Wi-Fi accelerators are the only path to practical large transfers, and they work
only between peers on the same platform.

### 9.2 Manifest

```
  transferId   8
  totalBytes   8
  chunkSize    4
  chunkCount   4
  digest      32
  channel      4     session channel the chunks will arrive on; MUST NOT be 0
  nameLength   1
  fileName     n     treated as sensitive content, not metadata
```

A manifest claiming channel 0 MUST be rejected: chunks must never be routed
through the message channel, where the replay window would reject legitimate
reordering.

A receiver MUST reject a manifest whose declared geometry is inconsistent —
`chunkCount != ceil(totalBytes / chunkSize)` — because otherwise a sender could
claim a small file and stream an unbounded number of chunks into an accepted
transfer. It MUST also reject a manifest over the configured maximum **before**
buffering any chunk, so claiming a large transfer costs the receiver nothing.

### 9.3 Integrity

`digest` is a chained hash: `h = SHA256(h || chunk)` from a domain-separated
constant. Chained rather than a plain hash of the file so it can be computed and
verified incrementally — neither endpoint ever holds the whole file, which is the
entire point of chunking.

On mismatch the receiver MUST discard the partial output rather than present it
as a file. Per-chunk authenticity is already provided by the session AEAD; the
digest additionally catches reordering and substitution across the whole file.

### 9.4 Transfer-level replay protection

The receiver holds one bit per chunk index. A chunk whose bit is set is a
duplicate and is ignored; a chunk whose bit is clear is new, however far out of
order it arrived. This is exact rather than approximate, which is precisely what
a sliding window cannot be at burst scale.

Replay across transfers is prevented by the channel: a chunk from another
transfer carries a different channel in its nonce and associated data, so it
fails authentication. Replay after a transfer ends is prevented by closing the
channel.

### 9.5 Resuming

A receiver MUST be able to report the chunk indices it still lacks, so a sender
can resend exactly those. Restarting a 100 MB transfer because one packet was
dropped is not acceptable behaviour on a lossy mesh.

*Measured cost.* At 30% loss per hop over three hops — roughly a 34% end-to-end
success rate — a 447-chunk transfer completed after **17 resend rounds** and
**2.9x** the chunk sends. The tail decays geometrically because there is no
per-chunk acknowledgement, only whole-round retries.

### 9.6 Behaviour under mesh conditions

- **Duplicate chunks** are expected — the mesh delivers by several paths — and
  MUST be ignored, not treated as an attack.
- **Out-of-order chunks** MUST be accepted; they are buffered until the gap fills,
  because the digest is chained and must be fed in order.
- **A chunk of the wrong size, or an out-of-range index,** MUST be rejected.
- **An interrupted or cancelled transfer** MUST discard its partial output.

### 9.7 Relay behaviour is unchanged

A relay sees chunk packets as ordinary packets. It cannot tell file traffic from
text, holds no transfer state, and is bounded by §6 exactly as before. **A relay
never needs 100 MB of RAM to carry a 100 MB file** — measured peak on a relay
carrying a 200 KB file is 28 KB, and the sender's peak buffer for a 100 MB file
is one chunk: 448 bytes. Measured across a four-phone geographic mesh: a full
100 MB transfer (234,058 chunks) peaked the relays at **1.22 MB**.

---

## 10. Memory and storage

### 10.1 The 25 MB ceiling applies to relays only

The ceiling bounds the **relay/forwarding subsystem**: encrypted packet buffers,
routing state, peer state, duplicate suppression, and temporary forwarding state.

It is **not** a limit on the application, the device, the sender, the recipient,
or a user's own conversation history. A user with 2 GB of Normal Mode history is
not in violation of it; that history is endpoint storage, which the ceiling does
not govern. Conflating the two would either cripple normal usage or quietly
weaken the relay guarantee.

### 10.2 Endpoint storage

| Role | Normal mode | Private mode |
|---|---|---|
| Sender | encrypted history, retained | RAM only |
| Recipient | encrypted history, retained | RAM only |
| Relay | nothing | nothing |

Normal Mode history is sealed with AES-256-GCM under a storage key held in
platform-protected storage (Android Keystore, iOS Keychain, Secure Enclave-backed
where available) before it reaches any storage API, so what lands on disk is
ciphertext. The peer identity and message id are bound in as associated data, so
a record cannot be moved between conversations or relabelled.

The storage key MUST be distinct from the identity key. Sharing one key means a
compromise of local storage also compromises the identity, and makes rotating
either impossible without breaking the other.

The persistence path MUST refuse private-mode messages outright, rather than
relying on callers to check the mode first.

### 10.3 Identity

Only one value is intentionally persisted for the protocol itself: the long-term
identity private key, in the Android Keystore or iOS Keychain. Messages, routing state, relay buffers,
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

## 11. Capture protection

Applies to Private Mode. Every claim here is bounded by what the platform
actually provides.

**Android.** `FLAG_SECURE` on the window blocks screenshots, excludes the window
from screen recording, and keeps it out of the recents snapshot. It is a genuine
block, and the app is not notified that a capture was attempted.

**iOS.** There is no equivalent block. `UIScreen.isCaptured` reports that
recording or mirroring is active, and `userDidTakeScreenshotNotification` fires
*after* a screenshot has been taken. So iOS can hide content while a recording
runs, and can react to a screenshot, but cannot prevent one.
**Implementations MUST NOT present iOS behaviour as equivalent to `FLAG_SECURE`.**

**Both platforms.** Private content MUST be hidden before the app leaves the
foreground, so it is absent from the recents snapshot and the app-switcher
preview — both are taken as the app backgrounds, so hiding afterwards is too
late. Content returns only when *every* reason to hide has cleared.

**Copy, clipboard, drag and share MUST be disabled** for private content wherever
the platform allows.

**Notifications MUST NOT carry private content** — not on the lock screen, in
notification history, or on a paired wearable. The redacted text carries no
sender name either, since knowing who is messaging is itself the metadata private
mode protects.

**Private plaintext, keys and identifiers MUST NOT be written** to logs,
analytics, telemetry, debug output, crash reports or any file.

### 11.1 The physical camera limitation

> insnaps prevents application- and OS-level capture where Android or iOS
> provides the required controls. **insnaps cannot prevent a separate physical
> camera or recording device from photographing or recording the display.**

This MUST be stated plainly in the product and never implied away.

---

## 12. Concurrency

The protocol core is single-threaded by contract. Transport implementations MUST
deliver every callback on one thread, and callers MUST drive the node from that
same thread — one serial queue or handler per node.

This is not the default on either platform: Android's `BluetoothGattCallback`
fires on binder threads and CoreBluetooth delivers on whichever queue the central
manager was given. Both MUST be funnelled onto the node's own queue before
reaching the core.

---

## 13. Coverage and the distance target

insnaps targets communication across geographic distances of **up to 10 km where
sufficient participating-device density exists to maintain a connected multi-hop
path**. Coverage depends on topology, radio range, device density, mobility and
platform availability.

It is not a radius, and it is not a property of the protocol. It is a property of
where the participants happen to be standing.

### 13.1 Why uniform area coverage is the wrong model

At a 100 m simulated range, a uniform scatter needs an average degree of roughly
4.5 before a random geometric graph stops fragmenting into islands. For a 10 km
square that works out to about **140,000 devices**. Measured: 10,000 devices over
100 km² produce a largest connected component of **1.9%** — thousands of tiny
islands, not a mesh.

### 13.2 Corridors are the realistic topology

People are not uniformly scattered. They are strung along roads, campuses, rail
routes, high streets, and packed into venues. A corridor of participants forms a
connected chain across a distance that the same population spread evenly over the
same area could never cover:

```
  ●──●──●──●──●──●──●──●        a road, a rail route, a high street
                 │
                 ●
                 │
                 ●              a branch into a venue or campus
                 │
                 ●
```

Reaching 10 km therefore means a **chain of density**, not a covered area. Any
coverage claim MUST state the density and topology it assumes; a claim expressed
purely as a radius is not meaningful and MUST NOT be made.

---

## 14. Reliability

Each stage of `handshake -> manifest -> chunks -> completion` fails differently on
a lossy path, and before v0.8.1 each failed *silently*. Every stage now ends in a
definite outcome.

### 14.1 Handshake

Handshakes MUST be retransmitted under a bounded policy: backoff, an attempt
limit, an overall deadline, and duplicate suppression so a second request for a
peer already being contacted is ignored. The exchange ends established, or failed
with a reason that MUST be reported upward — "could not reach this contact" is
useful; silence is not.

**A retransmission MUST resend the original message verbatim.** Generating a
fresh handshake per attempt looks harmless and is not: each carries a new
ephemeral key, so a reply already in flight for an earlier attempt can no longer
be decrypted, and every attempt must then complete within a single round trip.

**Sizing.** A handshake needs *two* packets to cross the whole path, so the
per-attempt success rate is the square of path survival. At 20% per-hop loss over
five hops that is ~11%. Eight attempts failed outright; sixteen succeeded at ten
hops and failed at five on the same loss. The default is 32.

### 14.2 Manifest

The manifest is a reliable control message and MUST be retransmitted until
acknowledged. It is the only message that explains what the chunks are, so losing
it means the chunks arrive and cannot be interpreted — measured at **1 of 10**
single attempts arriving at 30% loss.

### 14.3 Selective acknowledgement

Chunk repair uses **ranges of missing indices**, not per-chunk acknowledgement.
One ACK per chunk would turn a 234,058-chunk file into more return packets than
the traffic it acknowledges.

Acknowledgements MUST be **paged across several packets** rather than truncated to
one. Losses are scattered rather than contiguous, so the missing set collapses
into thousands of single-chunk ranges — far more than the 58 that fit one packet.
Reporting only the first 58 makes repair take `missing / 58` rounds: a
23,406-chunk transfer needed **160+ rounds** truncated, and **13** once paged.

Feedback MUST stay bounded (64 packets per round by default) so the repair channel
cannot itself become the traffic problem.

**The relay is not involved in any of this.** Acknowledgement is receiver-side
bookkeeping; a relay never learns a transfer exists, let alone which chunks are
missing. It forwards encrypted packets and holds nothing.

### 14.4 Measured envelope

100 KB file, per-hop loss, geographic line topology:

| Hops | 0% | 5% | 10% | 20% | 30% | 50% |
|---|---|---|---|---|---|---|
| 3 | ok 1.0x | ok 1.2x | ok 1.4x | ok 2.0x | ok 2.8x | fail |
| 5 | ok 1.0x | ok 1.3x | ok 1.7x | marginal | fail | fail |
| 10 | ok 1.0x | ok 1.7x | ok 3.1x | ok 9.4x | fail | fail |

`ok Nx` is completion at N times the minimum chunk sends. Peak relay memory never
exceeded 0.11 MB of the 25 MB ceiling anywhere in this table.

**The reliable envelope is <=10% per-hop loss at every distance tested.** Beyond
it, establishment is genuinely marginal rather than deterministic, which is why
the same loss can succeed at ten hops and fail at five. Beyond 30% on a long path
no retry budget rescues it: the path is not usable, and the exchange fails with a
reason instead of retrying forever.

10 MB over five hops at 10% loss: 23,406 chunks, 13 rounds, 1.70x overhead, peak
relay memory 1.22 MB.

Heterogeneous fleets — all-Android, 70/30 mixed with half backgrounded, and
all-iOS backgrounded — all completed at five hops and 10% loss.

---

## 15. What is NOT yet established

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
| **Devices needed per unit distance** | partially answered in simulation (§14); still needs real radios |
| Multi-hop range | measured coverage vs. node density on real hardware |
| Real throughput and battery | frames/second and battery draw on a device, not a frame-count proxy |
| Discovery latency | time to first delivery after two groups come into range |
| Connection stability | delivery rate under real mobility |
| Real memory ceiling | measured RSS of the subsystem against the 25 MB target |
| Handshake cost on BLE | round-trip latency for a 1-RTT handshake over a real link |
| iOS background behaviour | relay reliability of a backgrounded app in practice |

No range figure, hop count, or scale figure is claimed by this specification.
