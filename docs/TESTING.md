# insnaps testing strategy

Three layers, each answering a question the others cannot. None of them replaces
another.

```
  ┌──────────────────────────────┐
  │ 1. KMP sandbox               │  Does the protocol work at scale?
  │    10,000 virtual phones     │  geography, loss, churn, attack
  │    runs on any dev machine   │  258 tests, ~2 min, deterministic
  └──────────────┬───────────────┘
                 │
  ┌──────────────▼───────────────┐
  │ 2. Firebase Test Lab         │  Does the Android implementation behave
  │    real handsets, one per    │  correctly across OS versions and OEMs?
  │    test execution            │  single device — see the limit below
  └──────────────┬───────────────┘
                 │
  ┌──────────────▼───────────────┐
  │ 3. Physical fleet            │  Can real phones form and hold a
  │    A ↔ B ↔ C ↔ D in a room   │  multi-hop BLE mesh?
  └──────────────────────────────┘
```

---

## The constraint that shapes everything

**Test Lab cannot run a multi-device BLE mesh.** A test execution targets one
device. Devices are racked in a data centre; there is no way to ask for two of
them to be co-located, paired, or in radio range of each other, and no API to
coordinate a test across two devices in one matrix. Its network-condition
profiles shape IP traffic, which is not the same thing as BLE radio conditions —
no connection intervals, no MTU negotiation, no contention, no distance.

So Test Lab can answer *"does our Android BLE code behave correctly on a Samsung
running Android 14?"* It cannot answer *"can three phones relay for each other?"*
That question needs layer 3, and layer 3 is what the 10 km objective ultimately
rests on.

---

## The standing rule

**JVM-green does not mean Android-green.** Every security-critical shared API
gets both a JVM test and at least one real Test Lab test. The X25519 defect
survived 258 passing JVM tests and would have surfaced during radio integration,
where it would have looked like a BLE problem.

## What NOT to send to Test Lab

**The 258-test core suite should not be run on Test Lab devices.**

`core/src/commonMain` has zero platform dependencies — no `java.*`, no
`android.*`, nothing. That is enforced by a test (`MemoryBudgetTest.commonMain
depends on no storage API`) and it is the entire point of the architecture. Those
tests exercise packet codecs, routing, session state and file assembly: pure
Kotlin over byte arrays.

Running them on twenty handsets would execute identical logic on a different JIT
and prove nothing about insnaps, while costing device-minutes and wall-clock time
on every commit. **A device farm is for code that touches the device.** The core
deliberately does not.

---

## First run: what it found immediately

The very first Test Lab matrix — two devices, a handful of tests, before any BLE
code existed — found a defect that 258 passing JVM tests could not:

**`JvmCryptoProvider` cannot perform X25519 on Android at any API level.**

| Device | API | `XDH` registered | Result |
|---|---|---|---|
| Pixel 5 | 30 | no | `NoSuchAlgorithmException` — algorithm absent |
| Pixel 8 | 34 | yes | `InvalidAlgorithmParameterException: No AlgorithmParameterSpec classes are supported` |

Two separate problems. Below API 33 the algorithm does not exist. At API 34 it
exists but Conscrypt rejects `NamedParameterSpec`, which is how the JDK selects
the curve. A contributing detail: the JDK registers both `XDH` and `X25519` as
names while Android registers only `XDH`, so the desktop tests could not have
distinguished them even in principle.

Every handshake would have failed on the first real phone.

**Fixed in v0.9a.** `AndroidCryptoProvider` supplies X25519 from Tink, which
implements the curve directly rather than through the JCA `XDH` binding. Every
other primitive is shared with the JVM provider via `JcaCryptoSupport`, since
Test Lab verified those port cleanly.

The separation is enforced by the build, not by discipline: `androidMain` no
longer depends on `jvmMain`, so Android code **cannot reference the JDK provider
at all** — a compile error rather than a runtime surprise. The test that used to
assert this is gone, because the misuse is now unrepresentable.

**Acceptance run, Pixel 8 / API 34 — 10/10 passed:**

```
api=34 x25519KeyGen=ok
api=34 x25519Agreement=ok
api=34 e2eeSession=ok replayRejected=true
device=Google/Pixel 8 api=34 XDH=true AES-GCM=true
bluetoothLe=true
```

Covering key generation, agreement, small-order rejection, AES-256-GCM, HKDF
against its RFC vector, SHA-256, the packet codec, a full Noise IK handshake,
session establishment, encrypt/decrypt and replay rejection — all on hardware.

What *did* pass on both devices, and is therefore verified on real hardware:
AES-256-GCM, SHA-256, HKDF against its RFC 5869 vector, the packet codec on ART,
and BLE hardware presence.

This is the case for layer 2 in one experiment: the core is portable, but its
platform bindings are not, and only a device can tell you which.

## What Test Lab is actually for

Only code that cannot exist on the JVM — none of which is written yet:

| Area | What must be proven on real hardware |
|---|---|
| BLE transport | advertise/scan/connect/write behave across OEM Bluetooth stacks; MTU negotiation; GATT quirks; write-without-response semantics |
| Background execution | a foreground service keeps relaying; Doze and App Standby effects; what actually happens to `reliabilityHint` |
| `FLAG_SECURE` | screenshots and screen recording genuinely blocked; window excluded from the recents snapshot |
| Keystore | `IdentityStore` round-trips; key survives restart; **key is destroyed on uninstall** |
| Memory | measured RSS of the relay subsystem against the 25 MB ceiling on a real device |
| Lifecycle | no crash across rotation, background, process death, permission revocation |
| Permissions | `BLUETOOTH_SCAN` / `BLUETOOTH_CONNECT` / location behaviour across API levels |

**Test Lab becomes worth wiring up at v0.9, when the Android transport exists.**
Wiring it now would run a device farm against code that has no device
dependencies.

### insnaps does not embed the Firebase SDK

**Decision: the app registers no Firebase app, ships no `google-services.json`,
and links no Firebase dependency.**

Test Lab does not require any of that. It is a device farm driven from `gcloud`:
two APKs are uploaded per run and the service installs and executes them. The
console's "Add Firebase to your Android app" flow exists for apps that *use*
Firebase services at runtime — insnaps does not.

Two reasons this is a decision rather than an omission:

1. Adding the Firebase SDK brings Google Analytics with automatic event
   collection. PROTOCOL.md §11 requires that private plaintext, keys and
   identifiers never reach analytics, telemetry or crash reporting. A requirement
   enforced by *not linking the library* is stronger than one enforced by
   configuring it correctly forever.
2. insnaps is a decentralized system with no server. Compiling in a dependency on
   a Google backend contradicts the premise, whatever it is configured to do.

The instrumentation-test APK is a build artefact for the device farm, not a
shipped component. Nothing here changes what users install.

### Practical limits

| | |
|---|---|
| Firebase project | `insnaps-44c85` (Spark plan, no apps registered — correct as-is) |
| Physical-device execution cap | 45 minutes per device |
| Spark (free) plan | 5 physical + 10 virtual test runs per day |
| Blaze plan | 30 physical + 60 virtual device-minutes free per day, then **$5/hour** per physical device and $1/hour virtual |
| Billing granularity | per minute, rounded up — a 22-second test bills as one minute |
| Quota reset | midnight PST |

**On Spark today the limit is run-count, not minutes: 5 physical device runs per
day.** A four-device matrix counts as four of those, so roughly one full matrix
run per day. That is enough for v0.9 development and does not require upgrading.

Blaze only becomes necessary for CI-frequency runs. When it does, the cost shape
matters: a four-device matrix at a 10-minute timeout is up to 40 physical
device-minutes per invocation, past the 30 free daily minutes. So: a small matrix
on per-commit triggers, the full matrix on releases, and never a long soak on
Test Lab — soaks belong on the physical fleet, where the phones are already paid
for.

---

## Layer 3: the physical fleet

The only layer that can validate the mesh. Minimum useful configuration is four
phones, mixed platform, with the middle two out of range of the endpoints:

```
   A ──── B ──── C ──── D
   |      |      |      |
  send  relay  relay  receive
```

What it must establish, none of which any simulator can:

- real BLE range in the environment, and therefore devices-per-kilometre
- discovery latency when two groups come into range
- throughput and completion time for a file, against the sandbox's chunk counts
- battery draw per hour of relaying — the sandbox's frame counts are a proxy only
- whether a backgrounded iPhone relays in practice, and how the platform-supplied
  `reliabilityHint` should actually be computed
- Android ↔ iOS ↔ Android, the path that proves cross-platform BLE

Only after this does any coverage figure become sayable, and then only with the
density it assumed (PROTOCOL.md §13).

---

## Where each claim currently rests

| Claim | Established by | Status |
|---|---|---|
| protocol correctness, hostile-input safety | layer 1 | done |
| routing at 10,000 nodes, adversarial bounds | layer 1 | done |
| 25 MB relay ceiling under load | layer 1 | done in simulation; unmeasured on a device |
| reliable delivery envelope (≤10% per-hop loss) | layer 1 | done in simulation |
| `commonMain` compiles and runs on Android (ART) | layer 2 | **done** — verified API 30 + 34 |
| AES-GCM, HKDF, SHA-256, packet codec on device | layer 2 | **done** — verified API 30 + 34 |
| X25519 on Android (Tink) | layer 2 | **done** — Pixel 8 / API 34, 10/10 |
| Full E2EE handshake + session on device | layer 2 | **done** — Pixel 8 / API 34 |
| The same on API 30 and other OEMs | layer 2 | **not yet run** — daily quota |
| BLE transport constructs against the real stack | layer 2 | **done** — Pixel 8 / API 34 |
| Link fragmentation (543 B over 514/20 B links) | layer 1 | **done** — 17 tests incl. adversarial |
| Android BLE behaviour across OEMs | layer 2 | **not started** |
| **Two phones actually linking over BLE** | layer 3 | **not started — the next real experiment** |
| capture protection, Keystore, background relay | layer 2 | **not started** |
| real range, battery, cross-platform mesh | layer 3 | **not started** |
| 10 km coverage | layer 3 | **not established, and not claimed** |
