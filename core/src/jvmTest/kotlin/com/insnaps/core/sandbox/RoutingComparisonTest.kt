package com.insnaps.core.sandbox

import com.insnaps.core.routing.ForwardingPolicy
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Routing policies under **geographic** topology.
 *
 * The v0.4 policy comparison ran on random graphs, where a node's neighbours are
 * scattered across the whole network and any subset of them spreads a packet
 * widely. Physical radio is not like that: every neighbour is within 100 m, so a
 * subset of neighbours points into much the same patch of ground. Whether the
 * adaptive default survives that change is exactly what the sandbox exists to
 * find out.
 */
class RoutingComparisonTest {

    private val policies = listOf(
        "full flood" to ForwardingPolicy.FullFlood,
        "adaptive" to ForwardingPolicy.AdaptiveFanout(),
        "fanout 6" to ForwardingPolicy.BoundedFanout(6),
        "fanout 12" to ForwardingPolicy.BoundedFanout(12),
        "gossip p=0.5" to ForwardingPolicy.Probabilistic(0.5),
    )

    private fun base(nodes: Int, areaKm: Double, loss: Double = 0.0) = SandboxConfig(
        seed = 4242,
        nodes = nodes,
        areaMetres = areaKm * 1000.0,
        bleRangeMetres = 100.0,
        packetLoss = loss,
    )

    private fun compare(title: String, base: SandboxConfig) {
        println("\n=== $title ===")
        println("  %-14s %-9s %-8s %-8s %-9s %s".format("policy", "delivery", "hops", "maxhop", "amp", "relayRAM"))
        for ((name, policy) in policies) {
            val network = sandbox(base.copy(broadcastPolicy = policy))
            val r = network.runBroadcastScenario(name)
            println("  %-14s %-8.1f%% %-8.1f %-8d %-8.1fx %.2f MB".format(
                name, r.deliveryRate * 100, r.averageHops, r.maxHops, r.amplification,
                r.peakRelayMemoryBytes / 1024.0 / 1024.0))
        }
    }

    @Test
    fun `geographic topology, 1000 devices in one square kilometre`() {
        compare("1,000 devices, 1 km², degree ~29", base(1_000, 1.0))
    }

    @Test
    fun `geographic topology under packet loss`() {
        compare("1,000 devices, 1 km², 10% loss", base(1_000, 1.0, loss = 0.10))
    }

    @Test
    fun `flooding sets the coverage benchmark under geography`() {
        val flood = sandbox(base(1_000, 1.0).copy(broadcastPolicy = ForwardingPolicy.FullFlood))
            .runBroadcastScenario("flood")
        assertTrue(flood.deliveryRate > 0.95,
            "flooding should reach nearly everyone in a connected graph, got ${flood.deliveryRate}")
    }
}

/**
 * Why bounded fanout collapses under geography.
 *
 * Hypothesis: the ranking is dominated by peer *quality* -- platform and
 * foreground state -- which has nothing to do with direction. A node therefore
 * picks the same high-scoring neighbours every time, and in a geographic graph
 * those neighbours sit in much the same patch of ground, so the flood front stops
 * expanding outward.
 *
 * If that is right, making every device identical in quality should let the
 * tie-break jitter randomise the choice and restore coverage.
 */
class FanoutDirectionalityTest {

    private fun run(label: String, androidRatio: Double, foregroundRatio: Double): Double {
        val config = SandboxConfig(
            seed = 4242, nodes = 1_000, areaMetres = 1_000.0, bleRangeMetres = 100.0,
            androidRatio = androidRatio, foregroundRatio = foregroundRatio,
            broadcastPolicy = com.insnaps.core.routing.ForwardingPolicy.BoundedFanout(6),
        )
        val r = sandbox(config).runBroadcastScenario(label)
        println("  %-38s delivery %.1f%%".format(label, r.deliveryRate * 100))
        return r.deliveryRate
    }

    @kotlin.test.Test
    fun `heterogeneous peer quality is what breaks bounded fanout`() {
        println("\n=== fanout 6, 1,000 devices, 1 km² ===")
        val mixed = run("mixed platforms + background (varied)", 0.7, 0.5)
        val uniform = run("all Android, all foreground (uniform)", 1.0, 1.0)

        println("  -> uniform quality lets the tie-break randomise the choice;")
        println("     varied quality pins it to the same neighbours every hop.")

        kotlin.test.assertTrue(
            uniform > mixed,
            "expected uniform quality to improve coverage: uniform=$uniform mixed=$mixed",
        )
    }
}
