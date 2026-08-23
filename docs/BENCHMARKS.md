# insnaps Core v0.3/v0.4 — scalability, adversarial results, routing policy

Every figure here is produced by the seeded simulation suite in
`core/src/jvmTest/.../sim/` and reproduces exactly from its seed. Reproduce with:

```
./gradlew :core:jvmTest --tests '*ScaleTest*' --tests '*ResilienceTest*' \
    --tests '*AdversarialTest*' --tests '*ForwardingPolicyComparisonTest*'
```

**Platform scope.** insnaps is an Android and iOS application only. The JVM is a
protocol test environment and never a desktop target.

**What this is not.** These are simulated radios: a synthetic transport, modelled
latency and loss, and no physical layer. They establish protocol behaviour under
scale and attack. They establish nothing about range, real throughput, battery
draw, or BLE discovery on actual hardware — all of which remain open until
device testing.

---

## The v0.3 question

> Can insnaps maintain reliable, secure, memory-bounded communication as the
> number of participating users grows, without flooding, relay memory exhaustion,
> crashes, or unacceptable packet amplification?

**Answer: yes on node count, with one qualification on density.**

Traffic scales with *neighbour degree*, not with the number of nodes. Coverage,
memory and amplification per node are effectively flat from 100 to 10,000 nodes.
Density, not population, is the cost driver — and the fix for density is a
one-line policy change that is already implemented and measured below.

---

## 1. Scale

Broadcast reaching the whole mesh, average degree 8, no loss.

| Nodes | Coverage | Frames | Amplification | p50 latency | p95 latency | Peak node memory |
|---|---|---|---|---|---|---|
| 100 | 100.0% | 679 | 6.8x/node | 114 ms | 163 ms | 1 KB |
| 1,000 | 100.0% | 6,973 | 7.0x/node | 189 ms | 236 ms | 2 KB |
| 10,000 | 100.0% | 69,961 | 7.0x/node | 267 ms | 315 ms | 2 KB |

Amplification is flat at ~7x — it equals average degree, not node count. Latency
grows only logarithmically, because a small-world graph's diameter does. Peak
per-node memory is 2 KB against a 25 MB ceiling: **four orders of magnitude of
headroom** in normal operation.

By topology, at 1,000 nodes:

| Topology | Avg degree | Coverage | Amplification | p95 latency |
|---|---|---|---|---|
| sparse | 4.0 | 100.0% | 3.0x | 462 ms |
| normal | 8.0 | 100.0% | 7.0x | 236 ms |
| dense | 23.7 | 100.0% | 22.7x | 134 ms |

The tradeoff is visible in one line: density buys latency and costs traffic.

---

## 2. Resilience

1,000 nodes, average degree 8.

| Condition | Coverage |
|---|---|
| 20% packet loss | 100.0% |
| 50% packet loss | 99.3% |
| 30% duplication | 100.0% (no traffic inflation) |
| 10% of nodes vanish mid-flight | 100.0% of survivors |
| 15% loss + 15% duplication + 5% churn, 2,000 nodes | 99.9% |
| two 500-node clusters, single bridge | 100.0% |

Flooding's redundancy is what pays for loss: a node has many chances to hear a
packet, so coverage degrades far more slowly than the loss rate. Duplicates die
at the duplicate cache and do not become traffic.

---

## 3. Adversarial

| Attack | Result |
|---|---|
| 100,000 max-size packets at one node (54 MB at a 25 MB budget) | held at 2.9 MB; 96,911 refused by per-peer quota |
| Flood from one peer, legitimate broadcast during it | 99/99 nodes still reached |
| Duplicate-cache exhaustion (5x capacity in unique ids) | bounded at 1.25 MB, no crash |
| Relay-buffer exhaustion from 8 attackers at once | bounded, node still functional |
| 20,000 malformed/truncated/corrupted/oversized frames | 3.3 M frames processed, 15,040 rejected, mesh fully functional afterwards |
| Forged maximum TTL | contained by the hop limit |

**No input from any peer produced a crash.** This is asserted directly rather
than assumed — see `AdversarialTest.no remotely supplied packet can crash a node`.

Two findings worth recording:

- **The per-peer quota only engages when a node cannot forward.** With somewhere
  to offload, the buffer drains and no pressure builds. The quota protects the
  case that actually matters: a node at the edge of the mesh being buried through
  its single link.
- **The hop limit is a backstop, not the normal terminator.** In a small-world
  graph the diameter is a handful of hops and duplicate suppression ends a flood
  long before 24 hops. TTL matters only in pathological topologies — a long line,
  or a deliberately constructed chain.

---

## 4. Flooding vs gossip

Identical seeds, identical topologies, broadcast policy varied.

**1,000 nodes, average degree 24 (a crowd):**

| Policy | Coverage | Frames | Amplification | p95 latency |
|---|---|---|---|---|
| full flood | 100.0% | 22,703 | 22.7x | 134 ms |
| fanout 3 | 96.9% | 2,907 | 2.9x | 512 ms |
| fanout 6 | 99.9% | 5,994 | 6.0x | 280 ms |
| gossip p=0.3 | 99.9% | 6,776 | 6.8x | 275 ms |
| gossip p=0.5 | 100.0% | 11,303 | 11.3x | 209 ms |
| **adaptive (v0.4 default)** | **99.9%** | **5,994** | **6.0x** | **280 ms** |

**5,000 nodes, average degree 24:** the same shape holds — flood 22.9x, fanout 6
at 6.0x with 99.9% coverage.

**1,000 nodes, degree 8, 30% loss:**

| Policy | Coverage | Amplification |
|---|---|---|
| full flood | 100.0% | 7.0x |
| fanout 6 | 100.0% | 5.7x |
| gossip p=0.5 | 94.0% | 3.3x |
| fanout 3 | 90.2% | 2.7x |
| gossip p=0.3 | 73.1% | 1.7x |

**1,000 nodes, degree 4 (sparse):**

| Policy | Coverage | Amplification |
|---|---|---|
| full flood | 100.0% | 3.0x |
| fanout 6 | 100.0% | 3.0x |
| gossip p=0.5 | 89.0% | 1.5x |
| gossip p=0.3 | 55.5% | 0.7x |

### The adaptive default (v0.4)

Adaptive bounded fanout, measured against full flooding at 1,000 nodes:

| Topology | Adaptive coverage | Adaptive amp | Flood coverage | Flood amp | Frames saved |
|---|---|---|---|---|---|
| dense (deg 24) | 99.9% | 6.0x | 100.0% | 22.7x | **74%** |
| normal (deg 8) | 100.0% | 5.7x | 100.0% | 7.0x | 18% |
| sparse (deg 4) | 100.0% | 3.0x | 100.0% | 3.0x | 0% |

The sparse row is the important one: 0% saved, because the policy detects a thin
neighbourhood and floods. It costs nothing where flooding is the right answer,
and saves three quarters of the traffic where it is not.

Under 30% packet loss at degree 8, adaptive holds 100.0% coverage at 5.7x — where
fanout 3 falls to 90.2% and gossip p=0.3 to 73.1%.

**Known gap in the adaptive signal.** Neighbour quality comes from what the
transport reports: freshness, its reliability hint, and failed send calls.
End-to-end packet loss is *invisible* to it, because a BLE write without response
reports success as soon as the link accepts the frame. In these runs the policy
therefore chose its narrow fanout even at 30% loss — it worked, but it worked by
luck of the topology rather than by detecting the loss. Closing this needs a
signal the transport can observe (acknowledged writes, or a receive-side report)
and is an open item for the BLE milestone.

### Conclusion

**A bounded fanout of 6 dominates full flooding.** It matches flooding's coverage
everywhere tested — including under 30% loss, where the aggressive gossip
variants collapse — while transmitting **74% fewer frames in a dense mesh**
(6.0x vs 22.7x). In sparse topologies it degenerates to flooding automatically,
because `min(degree, 6) = degree`, so there is no sparse-network penalty to trade
against.

Probabilistic gossip is the weakest of the three. It is *worse than bounded
fanout at the same traffic cost*: gossip p=0.3 and fanout 6 both run at ~6.8x
and ~6.0x, but gossip collapses to 55.5% coverage in a sparse mesh and 73.1%
under loss, where fanout 6 holds 100%. Independent coin flips at every node
compound into dead ends exactly where the graph can least afford them.

**Adopted in v0.4:** the specified broadcast policy is now adaptive bounded
fanout, which widens as conditions worsen and collapses to full flooding in a
thin neighbourhood. Full flooding remains available as a fallback and diagnostic
mode. A node's policy never appears on the wire, so mixed deployments
interoperate.

---

## 5. Still unestablished

Unchanged by this milestone, and not to be claimed:

- **how many real phones are needed to hold a route over a given distance** —
  the question every coverage claim actually rests on, and one only device
  testing can answer
- physical range, and therefore any coverage figure in kilometres
- real BLE throughput, connection stability and discovery latency
- battery cost — the frame counts above are a proxy, not a measurement
- behaviour with real iOS background restrictions
- measured process RSS against the 25 MB target on a device
