# insnaps

A decentralized, end-to-end encrypted mesh messaging protocol for phones, with a
platform-independent core.

Phones running insnaps relay for each other over Bluetooth LE, so a message can
travel beyond the range of any single device. Relays forward ciphertext they hold
no key to open, and nothing about a conversation is written to storage.

## Platform scope: mobile only

insnaps targets **Android and iOS only**. There is no Windows, macOS, Linux or
other desktop application target, and none is to be added. Transport, UI,
background execution, permissions, battery management, Bluetooth and networking
are all to be designed for mobile constraints specifically.

**The JVM target is a test harness, not an application target.** It exists so the
protocol suite runs on a development machine with no device, emulator or SDK
attached, and it compiles `commonMain` only. It is not a desktop build, produces
no application, and must never acquire UI, transport or platform integration
code. If a change would make sense only for a desktop app, it does not belong in
this repository.

`androidTarget()` and `iosArm64()` compile the same `commonMain` sources and can
be added to `core/build.gradle.kts` without any core change; they are absent only
because this machine has no Android SDK or Xcode.

## Status

The protocol core is implemented, tested and stress-tested. Radios are not.

| Component | State |
|---|---|
| Packet format + codec | done, tested |
| Duplicate suppression | done, tested |
| Relay buffer, byte budget, eviction, per-peer quota | done, tested |
| Hop limit, expiry, store-and-forward | done, tested |
| Peer ranking / relay availability scoring | done, tested |
| Rotating recipient tags | done, tested |
| Multi-hop routing engine | done, tested |
| Forwarding policy: **adaptive bounded fanout** (default); flood / bounded / gossip available | done, measured |
| Noise IK handshake (X25519) | done, tested — **hand-written pattern: RELEASE BLOCKER until replaced or audited** |
| Sessions: AEAD, directional keys, replay window, expiry | done, tested |
| Session/mesh integration (`SecureMesh`) | done, tested |
| Memory budget enforcement + RAM-only checks | done, tested |
| Hostile-input and fuzz coverage | done — no peer-supplied input crashes a node |
| Deterministic scale + adversarial simulation harness | done — 100 to 10,000 nodes |
| Normal Mode: encrypted endpoint history | done, tested — core + storage contract |
| Private Mode: ephemeral messages, expiry, key destruction | done, tested |
| Capture / copy / notification protection policy | done, tested — **core policy only; Android and iOS implementations not written** |
| Chunked encrypted file transfer (≤100 MB) | done, tested |
| Sandbox: virtual phones, geography, mobility, simulated BLE | done — real core underneath, not a second implementation |
| BLE / Wi-Fi transports (Android, iOS) | **not started** |
| Platform `IdentityStore` (Keystore / Keychain) | **not started** — interface only |
| UI | **not started** |

```bash
./gradlew :core:jvmTest
```

258 tests, about 2 minutes.

- Protocol specification: [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Scale, adversarial and routing results: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

## Milestones

```
v0.2  security / crash baseline
v0.3  scalability, adversarial testing, routing-policy comparison
v0.4  adaptive bounded-fanout policy
v0.5  Normal/Private modes, file transfer, capture policy
v0.6  sandbox: virtual phones on a map, simulated BLE
v0.7  geographic routing fix: weighted-random selection
v0.8  chunk-aware file transfer protocol
v0.8.1 reliable delivery: handshake retry, manifest ack, selective ack  <- current
v0.9  Android BLE
v1.0  iOS BLE, then Android <-> iOS physical testing
```

## Communication modes

Both modes use the same E2EE and the same mesh. The difference is entirely at the
endpoints — **a relay cannot tell them apart** and behaves identically for both.
The mode travels inside the ciphertext for exactly that reason.

| | Normal | Private |
|---|---|---|
| End-to-end encryption | required | required |
| Endpoint history | retained, encrypted at rest | RAM only |
| Expiry | optional | required — view-once, 30s, 5m, 1h, 24h |
| Relay storage / decryption | none / impossible | none / impossible |
| Capture protection | OS default | strongest the platform offers |
| Copy, clipboard, share | permitted | blocked |
| Notification content | shown | redacted |
| Files | ≤100 MB, chunked | ≤100 MB, chunked |

Private plaintext lives in a store with no serialization path at all — it cannot
write anything down, which is a stronger guarantee than a policy saying it should
not. Buffers are zeroed on expiry; view-once is destroyed at the view, not on a
later sweep.

Normal Mode history is sealed before it reaches any storage API, under a key from
the Keystore or Keychain that is deliberately distinct from the identity key. The
persistence path *refuses* private messages rather than trusting callers to check.

## File transfer

Files travel as a manifest plus chunks, each sealed end-to-end and each carried in
one packet. **Chunks use their own session channel**, so the message replay window
never sees them: a window cannot distinguish legitimate reordering from replay at
burst scale, while the receiver's per-chunk bitmap can do it exactly. The channel
closes when the transfer ends, so a captured chunk cannot be replayed afterwards.

Repair uses **paged ranges of missing chunks**, not per-chunk acknowledgement —
one ACK per chunk would produce more return traffic than the file. Paging matters:
truncating to a single ACK packet made a 23,406-chunk repair take 160+ rounds;
paged, it takes 13.

Measured across a four-phone geographic mesh: a 100 MB transfer is 234,058 chunks
and peaked the relays at **1.22 MB**. Timings from the sandbox are simulator
throughput, **not** BLE predictions — no connection intervals, MTU negotiation, OS
scheduling or radio contention are modelled. **The 100 MB file limit and the 25 MB relay ceiling are independent**:
a relay carrying a 200 KB file peaked at 28 KB, and the sender's peak buffer for a
100 MB file is one chunk — 448 bytes.

Chunks are 448 bytes because a packet carries at most 512, sized for BLE. The
consequence is worth knowing before promising anything: **100 MB is about 234,000
packets, which is hours over BLE, not minutes.** Large files are supported; they
are not fast, and same-platform Wi-Fi accelerators are the only practical route.

## Architecture

```
                          insnaps
                             |
                  +----------+----------+
                  |     SecureMesh      |   plaintext in, ciphertext out
                  |  Noise IK handshake |
                  |  AEAD sessions      |
                  |  replay window      |   <-- keys live only here
                  +----------+----------+
                             |
                       opaque payloads
                             |
                  +----------+----------+
                  |      MESH CORE      |   platform-independent, RAM-only
                  |  packet format      |
                  |  routing / fanout   |
                  |  hop limit / expiry |
                  |  dedupe cache       |
                  |  relay buffer       |
                  |  recipient tags     |
                  +----------+----------+
                             |
                    Transport (6 methods)
                  +----------+----------+
                  |                     |
               Android                  iOS
            BLE + Wi-Fi Aware      BLE + Multipeer
                  |                     |
                  +----------+----------+
                             |
                cross-platform traffic is BLE only
```

The mesh core does not know BLE exists. `Transport` is
`start / stop / send / onFrame / onPeerFound / onPeerLost` over opaque bytes,
which is why a 10,000-node mesh can be exercised on the JVM with no radios.

The session layer sits strictly above the mesh, and the mesh holds no reference
to it. A relay running this same software with no session for the traffic passing
through has no code path that could produce plaintext for it.

## Results at a glance

Seeded simulation — protocol behaviour only, no radios. Detail in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md).

| | |
|---|---|
| 100 / 1,000 / 10,000 nodes | 100% coverage, amplification flat at 5.7x, peak node memory 2 KB of 25 MB |
| 50% packet loss | 99.3% coverage |
| loss + duplication + churn combined | 99.9% coverage |
| 100,000 max-size hostile packets at one node | held at 2.9 MB; 96,911 refused by per-peer quota; legitimate traffic unaffected |
| ~3.3 M malformed / hostile frames | no crash; mesh fully functional afterwards |
| adaptive vs. flooding, dense mesh | same coverage, **74% fewer frames** |
| adaptive vs. flooding, sparse mesh | identical — the policy detects a thin neighbourhood and floods |

Amplification tracks *neighbour density*, never population. Crowds are the
scaling variable; user count is not.

## Design decisions worth knowing

**BLE is the only universal link.** Wi-Fi Aware / Wi-Fi Direct (Android) and
MultipeerConnectivity (iOS) do not interoperate, so they are same-platform
accelerators. Every Android↔iOS hop is BLE. This reaches the core only as
`PeerHandle.throughputClass`.

**Not every nearby phone is a usable relay.** A backgrounded iOS app advertises
without its local name and a suspended one does not forward at all. Rather than
assume uniform availability, the router ranks neighbours by freshness, a
platform-supplied `reliabilityHint`, and observed forwarding success. No
platform-specific term appears in the core's scoring.

**Fanout adapts instead of being chosen once.** A fixed fanout isolates nodes in a
sparse mesh; flooding wastes a crowd's battery. The default widens the fanout as
neighbour quality drops (6 → 10 → 16) and floods outright below degree 6. Full
flooding stays available as a fallback and diagnostic mode. Policy never appears
on the wire, so mixed deployments interoperate.

**Addressing is the real privacy tradeoff.** A cleartext recipient lets every
relay build a social graph; a fully opaque one forces pure flooding. insnaps uses
a rotating 8-byte tag, `HMAC(pairwiseSecret, epoch)`, recognisable only by the
recipient and linkable only within one rotation period. That residual leak is
accepted and is confined behind `RecipientAddressing`, so onion routing can
replace it without touching the router, buffer or codec.

**The memory budget has an eviction rule.** A budget without one is a crash.
Expired packets go first; a neighbour at its quota is refused rather than served
by evicting others (this is the DoS bound); only then is the packet nearest its
own expiry dropped. A configuration whose own bounds exceed its budget is
rejected at construction, not discovered under load.

**Volatile except for one key.** Messages, routing state, relay buffers, session
keys, peer records and conversation state are RAM-only and are discarded on
`stop()`. The single intentional persistent value is the long-term identity key.
Note that iOS Keychain items survive app deletion, so the iOS implementation must
store it `...ThisDeviceOnly` and clear it on first launch after install, or
uninstalling will not destroy the identity as it does on Android.

**The core is single-threaded by contract.** Transports must deliver every
callback on one thread. Android's `BluetoothGattCallback` fires on binder threads
and CoreBluetooth uses its own queue, so both must be funnelled onto the node's
queue before reaching the core.

## What insnaps does not claim

- **No anonymity.** Strong end-to-end encryption with *limited* metadata
  protection. A relay sees that a conversation is occurring, its size and timing;
  bootstrap addressing leaks a contact attempt to anyone holding the recipient's
  public key. See PROTOCOL.md §0.
- **No coverage radius.** insnaps targets distances up to 10 km *where
  participating-device density sustains a connected multi-hop path*. That is a
  property of where people are standing, not of the protocol. A uniform 10 km
  square would need roughly 140,000 devices at 100 m range — 10,000 over 100 km²
  measured 1.9% connectivity. Real coverage follows **corridors** of density: a
  road, a campus, a rail route, a venue. A claim expressed as a radius is not
  meaningful and is not made.
- **No performance claim on hardware.** Throughput, battery cost, discovery
  latency and real memory footprint are unmeasured. Frame counts are a battery
  proxy, not a measurement.
- **No protection from a physical camera.** insnaps prevents application- and
  OS-level capture where Android or iOS provides the control. It cannot stop a
  separate camera photographing the screen, and never implies otherwise.
- **iOS capture protection is weaker than Android's.** `FLAG_SECURE` blocks
  capture; iOS can only *detect* recording and mirroring, and learns of a
  screenshot after it has been taken. These are not equivalent and are not
  described as such.
- **Fast large-file transfer.** 100 MB is supported and is roughly 234,000
  packets — hours over BLE, not minutes.
- **Not production-ready cryptography.** See the release blocker below.

## Known gaps

- **Reliable delivery has a measured envelope: ≤10% per-hop loss.** Beyond it,
  handshake establishment is marginal rather than deterministic — two packets must
  cross the whole path, so per-attempt success is the *square* of path survival
  (~11% at 20% loss over five hops). The same loss can succeed at ten hops and
  fail at five. Beyond 30% on a long path, no retry budget helps.
- **Repair is whole-round, not per-chunk.** A sender resends everything the
  receiver reports missing, so a lossy transfer costs ~2.9x at 30% loss/hop.
- **The Android and iOS capture protections are not implemented.** What exists is
  the decision logic in `commonMain` — when private content must be hidden, what
  a notification may say, what copy is permitted — with tests. The platform code
  that applies it (`FLAG_SECURE`, `UIScreen.isCaptured`, backgrounding hooks)
  needs an Android SDK and Xcode, neither of which is on this machine. The
  contract they must satisfy is `ScreenProtector` in `privacy/`.
- **Platform `BlobStore` and `StorageKeyProvider` are interfaces only.** Normal
  Mode history is encrypted in `commonMain`, so a platform implementation only
  ever handles ciphertext — but it still has to be written.

- **Release blocker: the Noise IK composition is hand-written.** Primitives come
  from the platform, but the pattern is not from a vetted library. It must be
  replaced or independently audited before any release to users. It is isolated
  behind `HandshakeResult` so the substitution is local.
- **The adaptive policy cannot see end-to-end packet loss.** It derives neighbour
  quality from what the transport reports — freshness, reliability hint, failed
  send calls. A BLE write without response reports success as soon as the link
  accepts the frame, so a lossy-but-connected link looks healthy and the fanout
  does not widen. Closing this needs acknowledged writes or a receive-side
  report, and belongs to the BLE milestone.

## Next steps

1. Android transport: BLE GATT via a foreground service, Wi-Fi Aware accelerator.
   Measure discovery latency, throughput, connection stability and battery draw.
2. iOS transport: CoreBluetooth central+peripheral, MultipeerConnectivity
   accelerator, background-mode handling feeding `reliabilityHint`.
3. Android ↔ iOS ↔ Android physical testing — the path that proves the mesh.
4. Platform `IdentityStore` implementations, with the iOS uninstall carve-out.
5. **Release blocker:** replace the hand-written Noise IK composition with a
   vetted implementation, or complete an independent audit of it. No release to
   users may carry it as-is.

## Repository layout

```
core/src/commonMain/    the protocol — platform-independent, no storage, no radio
  packet/               wire format and codec
  relay/                duplicate cache, relay buffer, memory config
  routing/              mesh engine, peer table, forwarding policy
  session/              Noise IK handshake, sessions, SecureMesh
  crypto/               primitive interfaces, addressing
  transport/            the six-operation transport contract
  util/                 byte codec helpers, clock abstraction
core/src/jvmMain/       JDK-backed CryptoProvider (test environment only)
core/src/commonTest/    protocol unit tests
core/src/jvmTest/       crypto, integration, hostile-input and simulation suites
  sim/                  deterministic scale + adversarial harness
docs/                   PROTOCOL.md (normative), BENCHMARKS.md (measurements)
```
