package com.insnaps.core.sandbox

import com.insnaps.core.routing.ForwardingPolicy
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Validation of the v0.7 weighted-random selection across the conditions that
 * matter: seeds, densities, fleet composition, churn and loss.
 *
 * A single scenario was enough to *find* the deterministic-selection defect. It
 * is not enough to accept the fix, because the failure was topology-dependent and
 * only appeared once geography was modelled.
 */
class RoutingValidationTest {

    private fun base(
        nodes: Int = 1_000,
        areaKm: Double = 1.0,
        loss: Double = 0.0,
        android: Double = 0.7,
        foreground: Double = 0.5,
        policy: ForwardingPolicy = ForwardingPolicy.AdaptiveFanout(),
    ) = SandboxConfig(
        seed = 900, nodes = nodes, areaMetres = areaKm * 1000.0, bleRangeMetres = 100.0,
        packetLoss = loss, androidRatio = android, foregroundRatio = foreground,
        broadcastPolicy = policy,
    )

    @Test
    fun `100 seeds of the geographic scenario`() {
        val result = monteCarlo("adaptive, 1,000 devices, 1 km²", runs = 100, base = base())
        print("\n" + result.render())
        assertTrue(result.percentile(5) > 0.95, "the unlucky 5% of arrangements: ${result.percentile(5)}")
        assertTrue(result.min > 0.90, "worst arrangement delivered ${result.min}")
    }

    @Test
    fun `heterogeneous fleets do not degrade delivery`() {
        // The defect was caused by quality *variation*, so fleet mix is the axis
        // most likely to reproduce it.
        println("\n=== fleet composition, 1,000 devices, 1 km² ===")
        for ((label, android, foreground) in listOf(
            Triple("all Android, foreground", 1.0, 1.0),
            Triple("70/30 mix, half backgrounded", 0.7, 0.5),
            Triple("all iOS, all backgrounded", 0.0, 0.0),
            Triple("50/50 mix, mostly backgrounded", 0.5, 0.2),
        )) {
            val r = monteCarlo(label, runs = 20, base = base(android = android, foreground = foreground))
            println("  %-32s mean %.1f%%  p5 %.1f%%  min %.1f%%".format(
                label, r.mean * 100, r.percentile(5) * 100, r.min * 100))
            assertTrue(r.percentile(5) > 0.90, "$label degraded to ${r.percentile(5)}")
        }
    }

    @Test
    fun `density sweep with the fixed policy`() {
        println("\n=== density, adaptive, 20 seeds each ===")
        for ((nodes, areaKm) in listOf(100 to 0.35, 500 to 0.7, 1_000 to 1.0, 3_000 to 1.7)) {
            val r = monteCarlo("$nodes in ${areaKm}km", runs = 20, base = base(nodes, areaKm))
            println("  %-16s mean %.1f%%  min %.1f%%".format("$nodes/${areaKm}km²", r.mean * 100, r.min * 100))
            assertTrue(r.mean > 0.95, "$nodes devices delivered ${r.mean}")
        }
    }

    @Test
    fun `packet loss sweep with the fixed policy`() {
        println("\n=== loss, adaptive, 20 seeds each ===")
        for (loss in listOf(0.0, 0.05, 0.10, 0.20, 0.30, 0.50)) {
            val r = monteCarlo("loss $loss", runs = 20, base = base(loss = loss))
            println("  loss %-5s mean %.1f%%  p5 %.1f%%  min %.1f%%".format(
                "${(loss * 100).toInt()}%", r.mean * 100, r.percentile(5) * 100, r.min * 100))
            if (loss <= 0.30) assertTrue(r.mean > 0.95, "loss $loss delivered ${r.mean}")
        }
    }

    @Test
    fun `delivery holds while a fifth of the mesh churns`() {
        val net = sandbox(base())
        net.node(0).engine.broadcast(net.node(0).payload(1))
        net.run()

        // A fifth of the devices leave, then return.
        val leaving = (1 until 1_000 step 5).toList()
        leaving.forEach { net.setOnline(it, false) }
        net.node(0).engine.broadcast(net.node(0).payload(2))
        net.run()

        val survivors = net.reachableFrom(0).filter { it !in leaving && it != 0 }
        val reached = survivors.count { net.node(it).deliveries.containsKey(2) }
        val rate = reached.toDouble() / survivors.size.coerceAtLeast(1)
        println("\n  churn: %.1f%% of surviving devices reached after 20%% left".format(rate * 100))
        assertTrue(rate > 0.95, "delivery among survivors was $rate")

        leaving.forEach { net.setOnline(it, true) }
        net.node(0).engine.broadcast(net.node(0).payload(3))
        net.run()
        val returned = leaving.count { net.node(it).deliveries.containsKey(3) }
        println("  ${returned}/${leaving.size} returning devices received the next broadcast")
        assertTrue(returned > leaving.size * 0.9, "returning devices did not rejoin")
    }

    @Test
    fun `relay memory stays inside the ceiling across every scenario`() {
        // The sandbox throws if any relay breaches 25 MB, so reaching the end is
        // the assertion; the peak is reported for the record.
        for ((nodes, areaKm) in listOf(500 to 0.7, 1_000 to 1.0, 3_000 to 1.7)) {
            val net = sandbox(base(nodes, areaKm, loss = 0.10))
            net.runBroadcastScenario("mem $nodes")
            println("  %-12s peak relay RAM %.3f MB".format(
                "$nodes devices", net.metrics.peakRelayMemoryBytes / 1024.0 / 1024.0))
            assertTrue(net.metrics.peakRelayMemoryBytes <= 25L * 1024 * 1024)
        }
    }
}
