# insnaps

A decentralized, end-to-end encrypted mesh messaging protocol for phones, with a
platform-independent core.

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

## Status

The protocol core is implemented and tested. Transports are not.

| Component | State |
|---|---|
| Packet format + codec | done, tested |
| Duplicate suppression | done, tested |
| Relay buffer, byte budget, eviction, per-peer quota | done, tested |
| Hop limit, expiry, store-and-forward | done, tested |
| Peer ranking / relay availability scoring | done, tested |
| Rotating recipient tags | done, tested |
| Multi-hop routing engine | done, tested |
| Noise IK handshake (X25519) | done, tested — **hand-written pattern: RELEASE BLOCKER until replaced or audited** |
| Sessions: AEAD, directional keys, replay window, expiry | done, tested |
| Session/mesh integration (`SecureMesh`) | done, tested |
| Memory budget enforcement + RAM-only checks | done, tested |
| Forwarding policy: **adaptive bounded fanout** (default), flood / bounded / gossip available | done, measured |
| Deterministic scale + adversarial simulation harness | done — 100 to 10,000 nodes |
| BLE / Wi-Fi transports (Android, iOS) | **not started** |
| Platform `IdentityStore` (Keystore / Keychain) | **not started** — interface only |
| UI | **not started** |

Run the suite: `./gradlew :core:jvmTest` (144 tests, ~55s)

The protocol is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md); scale and
adversarial results are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

Only the JVM target is enabled, because it compiles `commonMain` and runs the
whole protocol suite with no Android SDK, no Xcode and no device. Adding
`androidTarget()` and `iosArm64()` to `core/build.gradle.kts` compiles the same
sources — no core changes needed.

## v0.2 acceptance baseline

What this milestone does and does not claim.

**Met:**

- 110/110 JVM tests passing
- `commonMain` protocol is platform-independent — no radio, no storage, no platform API
- the mesh handles opaque payloads only
- an E2EE session layer exists strictly above the mesh
- X25519, AES-256-GCM and SHA-256 supplied by the platform, not implemented here
- replay protection and session expiry implemented
- relay nodes hold no session keys
- communication data is RAM-only at the application level
- 25 MB relay memory ceiling enforced, and violated configurations rejected at construction
- no intentional persistent communication storage
- full-neighbour broadcast explicitly specified (PROTOCOL.md §2.1), not accidental
- hostile-input and fuzz coverage over every parser reachable from the network

**Explicitly not established:**

- routing scalability is an open acceptance criterion, not a result
- 10 km coverage is an engineering target, never a protocol guarantee
- Android and iOS transports are outside the core and not written
- the hand-written Noise IK composition is a release blocker until replaced or audited
- sender/recipient anonymity is **not** provided (PROTOCOL.md §0)

## Milestones

```
v0.2  security / crash baseline
v0.3  scalability, adversarial testing, routing-policy comparison
v0.4  adaptive bounded-fanout policy      <- current
v0.5  Android BLE
v0.6  iOS BLE, then Android <-> iOS physical testing
```

## v0.3/v0.4: scale, adversarial and routing results

Measured by seeded simulation — protocol behaviour only, no radios. Full detail
in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

- 100 / 1,000 / 10,000 nodes: **100% coverage**, amplification flat at ~7x
  (it tracks neighbour degree, not population), peak node memory 2 KB of 25 MB
- 50% packet loss: 99.3% coverage. Combined loss + duplication + churn: 99.9%
- 100,000 max-size hostile packets at one node: held at 2.9 MB, 96,911 refused
  by the per-peer quota, legitimate traffic unaffected
- ~3.3 M malformed/hostile frames: **no crash**, mesh fully functional afterwards
- **Adopted in v0.4 — adaptive bounded fanout is now the default policy**: it
  matches flooding's coverage in sparse, normal and dense topologies, saves 74%
  of frames in a crowd, and costs nothing in a sparse mesh because it detects the
  thin neighbourhood and floods. Full flooding remains available as a fallback.

## Architecture

```
                        insnaps
                           |
                  +--------+--------+
                  |    KMP CORE     |   platform-independent, RAM-only
                  |  packet format  |
                  |  routing / TTL  |
                  |  dedupe cache   |
                  |  relay buffer   |
                  |  recipient tags |
                  +--------+--------+
                           |
                    Transport (6 methods)
                  +--------+--------+
                  |                 |
               Android             iOS
            BLE + Wi-Fi        BLE + MPC
                  |                 |
                  +--------+--------+
                           |
              cross-platform traffic is BLE only
```

The core does not know BLE exists. `Transport` is `advertise/scan/connect/send/
receive/peerLost` over opaque bytes, which is why a five-node mesh can be
exercised on the JVM.

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

**Addressing is the real privacy tradeoff.** A cleartext recipient lets every
relay build a social graph; a fully opaque one forces pure flooding. insnaps uses
a rotating 8-byte tag, `HMAC(pairwiseSecret, epoch)`, recognisable only by the
recipient and linkable only within one rotation period. That residual leak is
accepted and is confined behind `RecipientAddressing`, so onion routing can
replace it without touching the router, buffer or codec.

**The memory budget has an eviction rule.** A budget without one is a crash.
Expired packets go first; a neighbour at its quota is refused rather than served
by evicting others (this is the DoS bound); only then is the packet nearest its
own expiry dropped.

**Volatile except for one key.** Messages, routing state, relay buffers, session
keys, peer records and conversation state are RAM-only and are discarded on
`stop()`. The single intentional persistent value is the long-term identity key.
Note that iOS Keychain items survive app deletion, so the iOS implementation must
store it `...ThisDeviceOnly` and clear it on first launch after install, or
uninstalling will not destroy the identity as it does on Android.

**Range is a coverage target, not a radio guarantee.** Multi-hop reach depends on
device density, mobility, and platform background limits. Nothing in the protocol
promises a distance.

## Next steps

1. Android transport: BLE GATT via a foreground service, Wi-Fi Aware accelerator.
2. iOS transport: CoreBluetooth central+peripheral, MultipeerConnectivity
   accelerator, background-mode handling.
3. Platform `IdentityStore` implementations, with the iOS uninstall carve-out.
4. **Release blocker:** replace the hand-written Noise IK composition with a
   vetted implementation, or complete an independent audit of it. No release to
   users may carry it as-is.
