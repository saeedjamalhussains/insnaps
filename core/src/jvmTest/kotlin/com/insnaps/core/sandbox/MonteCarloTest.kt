package com.insnaps.core.sandbox

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Repeated runs across seeds.
 *
 * A geographic scatter is random: one arrangement can island a corner of the map
 * and another can be unusually well connected. A single run is an anecdote, so
 * these report the distribution and quote percentiles rather than a mean.
 */
class MonteCarloTest {

    private fun base(nodes: Int, areaKm: Double, loss: Double) = SandboxConfig(
        seed = 1000, nodes = nodes, areaMetres = areaKm * 1000.0,
        bleRangeMetres = 100.0, packetLoss = loss,
        broadcastPolicy = com.insnaps.core.routing.ForwardingPolicy.FullFlood,
    )

    @Test
    fun `delivery distribution over 50 arrangements`() {
        val result = monteCarlo("1,000 devices, 1 km², 10% loss", runs = 50, base = base(1_000, 1.0, 0.10))
        print("\n" + result.render())
        assertTrue(result.percentile(5) > 0.90, "the unlucky 5% still needs to work: ${result.percentile(5)}")
    }

    @Test
    fun `connectivity distribution is what varies, not delivery`() {
        // Delivery within the connected component is stable; whether the map is
        // connected at all is the thing that swings.
        val connectivity = monteCarlo(
            "connectivity, 1,000 devices, 2 km²", runs = 30,
            base = base(1_000, 2.0, 0.0),
        ) { it.connectedFraction }
        print("\n" + connectivity.render())
    }

    @Test
    fun `packet loss sweep`() {
        println("\n=== loss sweep, 1,000 devices, 1 km², 20 runs each ===")
        for (loss in listOf(0.0, 0.05, 0.10, 0.20, 0.30, 0.50)) {
            val r = monteCarlo("loss ${(loss * 100).toInt()}%", runs = 20, base = base(1_000, 1.0, loss))
            println("  loss %-5s mean %.1f%%  p5 %.1f%%  min %.1f%%".format(
                "${(loss * 100).toInt()}%", r.mean * 100, r.percentile(5) * 100, r.min * 100))
        }
    }
}
