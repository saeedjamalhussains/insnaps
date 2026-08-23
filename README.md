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
| BLE / Wi-Fi transports (Android, iOS) | **not started** |
| Platform `IdentityStore` (Keystore / Keychain) | **not started** — interface only |
| UI | **not started** |

```bash
./gradlew :core:jvmTest
```

144 tests, about 55 seconds.

- Protocol specification: [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Scale, adversarial and routing results: [docs/BENCHMARKS.md](docs/BENCHMARKS.md)

## Milestones

```
v0.2  security / crash baseline
v0.3  scalability, adversarial testing, routing-policy comparison
v0.4  adaptive bounded-fanout policy      <- current
v0.5  Android BLE
v0.6  iOS BLE, then Android <-> iOS physical testing
```

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
- **No range figure.** Not 10 km, not any number. Multi-hop reach depends on
  device density, mobility and platform background limits. The open question is
  how many real phones are needed to hold a route over a given distance, and only
  device testing answers it.
- **No performance claim on hardware.** Throughput, battery cost, discovery
  latency and real memory footprint are unmeasured. Frame counts are a battery
  proxy, not a measurement.
- **Not production-ready cryptography.** See the release blocker below.

## Known gaps

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
