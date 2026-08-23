package com.insnaps.core.sim

import com.insnaps.core.routing.ForwardingPolicy
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Full-neighbour flooding versus bounded and probabilistic gossip.
 *
 * This is the v0.3 question in its sharpest form: flooding is what the protocol
 * specifies, and the reason to keep it is coverage. The reason to doubt it is
 * traffic. Both are measured here under identical seeded conditions, so the
 * comparison is like-for-like rather than two anecdotes.
 */
class ForwardingPolicyComparisonTest {

    private val policies = listOf(
        "full flood" to ForwardingPolicy.FullFlood,
        "fanout 3" to ForwardingPolicy.BoundedFanout(3),
        "fanout 6" to ForwardingPolicy.BoundedFanout(6),
        "gossip p=0.3" to ForwardingPolicy.Probabilistic(0.3),
        "gossip p=0.5" to ForwardingPolicy.Probabilistic(0.5),
        "adaptive" to ForwardingPolicy.AdaptiveFanout(),
    )

    private fun run(
        policy: ForwardingPolicy,
        label: String,
        nodes: Int,
        topology: (SimNetwork, Int) -> Unit,
        lossRate: Double = 0.0,
        seed: Long = 20260824,
    ): ScenarioResult {
        val network = SimNetwork(seed, SimNetwork.SimConfig(lossRate = lossRate, broadcastPolicy = policy))
        topology(network, nodes)
        network.startAll()
        return network.runBroadcast(label)
    }

    private fun compare(
        title: String,
        nodes: Int,
        topology: (SimNetwork, Int) -> Unit,
        lossRate: Double = 0.0,
    ): Map<String, ScenarioResult> {
        println("\n=== $title ===")
        println("  %-14s %9s %9s %10s %9s".format("policy", "coverage", "frames", "amp/node", "p95 ms"))
        val results = LinkedHashMap<String, ScenarioResult>()
        for ((name, policy) in policies) {
            val r = run(policy, name, nodes, topology, lossRate)
            results[name] = r
            println("  %-14s %8.1f%% %9d %9.1fx %9d".format(
                name, r.coverage * 100, r.framesSent, r.amplification, r.p95LatencyMillis))
        }
        return results
    }

    @Test
    fun `normal density at 1000 nodes`() {
        val results = compare("1,000 nodes, average degree 8", 1_000, Topology::normal)

        // Flooding must be the coverage benchmark; anything beating it is suspect.
        assertTrue(results.getValue("full flood").coverage >= 0.99)
        // And it must cost more, or there would be nothing to discuss.
        assertTrue(
            results.getValue("fanout 3").framesSent < results.getValue("full flood").framesSent,
            "bounded fanout should transmit less than flooding",
        )
    }

    @Test
    fun `dense topology is where flooding hurts`() {
        // Degree ~24: a crowd. Flooding's cost is O(degree) per node, so this is
        // where the two strategies diverge.
        val results = compare("1,000 nodes, average degree 24", 1_000, Topology::dense)

        val flood = results.getValue("full flood")
        val bounded = results.getValue("fanout 3")

        val saving = 1.0 - bounded.framesSent.toDouble() / flood.framesSent
        println("  -> fanout 3 transmits %.0f%% fewer frames than flooding".format(saving * 100))
        assertTrue(saving > 0.5, "bounded fanout saved only ${saving * 100}% in a dense mesh")
    }

    @Test
    fun `sparse topology is where bounded fanout is safe`() {
        // With degree ~4, a fanout of 3 is barely a restriction, so the strategies
        // should converge -- a useful check that the comparison is measuring
        // density rather than something else.
        val results = compare("1,000 nodes, average degree 4", 1_000, Topology::sparse)
        assertTrue(results.getValue("fanout 3").coverage >= 0.95)
    }

    @Test
    fun `under packet loss the redundancy of flooding earns its cost`() {
        // The real argument for flooding is not a clean network. It is a lossy one.
        val results = compare("1,000 nodes, degree 8, 30% loss", 1_000, Topology::normal, lossRate = 0.30)

        val flood = results.getValue("full flood")
        val bounded = results.getValue("fanout 3")
        println("  -> under loss: flood %.1f%% vs fanout-3 %.1f%% coverage".format(
            flood.coverage * 100, bounded.coverage * 100))
        assertTrue(flood.coverage >= bounded.coverage, "flooding should be at least as robust under loss")
    }

    @Test
    fun `the adaptive default matches flooding coverage at a fraction of the cost`() {
        // The claim the v0.4 default rests on, asserted rather than assumed.
        val cases: List<Triple<String, Int, (SimNetwork, Int) -> Unit>> = listOf(
            Triple("dense", 1_000) { n, c -> Topology.dense(n, c) },
            Triple("normal", 1_000) { n, c -> Topology.normal(n, c) },
            Triple("sparse", 1_000) { n, c -> Topology.sparse(n, c) },
        )
        for ((title, nodes, topology) in cases) {
            val flood = run(ForwardingPolicy.FullFlood, "flood", nodes, topology)
            val adaptive = run(ForwardingPolicy.AdaptiveFanout(), "adaptive", nodes, topology)
            val saving = 1.0 - adaptive.framesSent.toDouble() / flood.framesSent
            println("  %-7s adaptive %.1f%% cov, %.1fx amp vs flood %.1f%% cov, %.1fx amp (%.0f%% fewer frames)".format(
                title, adaptive.coverage * 100, adaptive.amplification,
                flood.coverage * 100, flood.amplification, saving * 100))

            assertTrue(
                adaptive.coverage >= flood.coverage - 0.01,
                "$title: adaptive coverage ${adaptive.coverage} fell below flooding ${flood.coverage}",
            )
            assertTrue(adaptive.framesSent <= flood.framesSent, "$title: adaptive sent more than flooding")
        }
    }

    @Test
    fun `the adaptive default holds coverage under loss`() {
        // Where bounded fanout 3 and gossip both degrade, adaptive must not.
        val flood = run(ForwardingPolicy.FullFlood, "flood", 1_000, Topology::normal, lossRate = 0.30)
        val adaptive = run(ForwardingPolicy.AdaptiveFanout(), "adaptive", 1_000, Topology::normal, lossRate = 0.30)
        println("  under 30%% loss: adaptive %.1f%% vs flood %.1f%%".format(
            adaptive.coverage * 100, flood.coverage * 100))
        assertTrue(adaptive.coverage >= 0.99, "adaptive coverage ${adaptive.coverage} under loss")
    }

    @Test
    fun `dense topology at 5000 nodes`() {
        val results = compare("5,000 nodes, average degree 24", 5_000, Topology::dense)
        assertTrue(results.getValue("full flood").coverage >= 0.99)
    }
}
