package com.insnaps.core.sandbox

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * How many phones does a 10 km mesh actually need?
 *
 * This is the question every coverage claim rests on, and geography is what
 * answers it. Earlier graph-based runs assumed connectivity; here connectivity
 * has to be *earned* by having enough devices within radio range of each other.
 *
 * Simulation parameters, not handset measurements: 100 m is a plausible open-air
 * BLE range and real environments with walls and bodies will be worse.
 */
class DensityScenarioTest {

    private fun scenario(nodes: Int, areaKm: Double, seed: Long = 42) = SandboxConfig(
        seed = seed,
        nodes = nodes,
        areaMetres = areaKm * 1000.0,
        bleRangeMetres = 100.0,
        packetLoss = 0.05,
        duplicationRate = 0.01,
    )

    @Test
    fun `density sweep across a 10 km square`() {
        println("\n=== 10 km x 10 km, 100 m BLE range ===")
        println("  %-8s %-9s %-8s %-10s %-10s %s".format("nodes", "density", "degree", "connected", "delivery", "expected deg"))

        for (nodes in listOf(10, 100, 500, 1_000, 5_000, 10_000)) {
            val config = scenario(nodes, 10.0)
            val network = sandbox(config)
            val result = network.runBroadcastScenario("$nodes in 10km")
            println("  %-8d %-9.1f %-8.1f %-10.1f %-10.1f %.2f".format(
                nodes, config.densityPerKm2, result.averageDegree,
                result.connectedFraction * 100, result.deliveryRate * 100, config.expectedDegree))
        }
        println("  (expected degree = n*pi*r^2/A; below ~4.5 the graph fragments)")
    }

    @Test
    fun `a 10 km mesh needs far more devices than a small area`() {
        // The headline finding, asserted so it cannot silently stop being true.
        val sparse = sandbox(scenario(1_000, 10.0)).runBroadcastScenario("1k in 10km")
        val dense = sandbox(scenario(1_000, 1.0)).runBroadcastScenario("1k in 1km")

        println("\n  1,000 devices in 10 km²: degree %.1f, connected %.1f%%".format(
            sparse.averageDegree, sparse.connectedFraction * 100))
        println("  1,000 devices in 1 km²:  degree %.1f, connected %.1f%%".format(
            dense.averageDegree, dense.connectedFraction * 100))

        assertTrue(dense.connectedFraction > sparse.connectedFraction,
            "the same population in a smaller area must be better connected")
    }

    @Test
    fun `a well connected area delivers to everyone under flooding`() {
        // 1 km² with 1,000 devices gives a degree well above the percolation
        // threshold, which is the regime insnaps is actually designed for.
        // Flooding is used here as the coverage benchmark; see the next test for
        // what the current default does under the same conditions.
        val network = sandbox(
            scenario(1_000, 1.0).copy(broadcastPolicy = com.insnaps.core.routing.ForwardingPolicy.FullFlood),
        )
        val result = network.runBroadcastScenario("1,000 devices in 1 km², flooding")
        print(result.render())

        assertTrue(result.connectedFraction > 0.99, "connectivity ${result.connectedFraction}")
        assertTrue(result.deliveryRate > 0.98, "delivery ${result.deliveryRate}")
        assertTrue(result.peakRelayMemoryBytes <= 25L * 1024 * 1024)
    }

    @Test
    fun `the adaptive default now delivers on geographic topology`() {
        // Regression guard for the v0.7 fix.
        //
        // Deterministic top-k selection delivered 55% here: the score is driven by
        // peer quality -- platform, foreground state -- which carries no
        // directional information, so every node picked the same favoured
        // neighbours at every hop and the flood front stopped expanding. Weighted
        // random sampling keeps the quality preference while restoring directional
        // diversity. `BoundedFanout` still selects deterministically and still
        // shows the old behaviour, which is what makes the comparison meaningful.
        val result = sandbox(scenario(1_000, 1.0)).runBroadcastScenario("adaptive, geographic")
        println("  adaptive on geography: %.1f%% delivery at %.1fx amplification on a %.1f%%-connected map"
            .format(result.deliveryRate * 100, result.amplification, result.connectedFraction * 100))

        assertTrue(result.connectedFraction > 0.99, "the map itself should be connected")
        assertTrue(result.deliveryRate > 0.98, "adaptive delivered only ${result.deliveryRate}")
        assertTrue(result.amplification < 12.0, "adaptive should stay far below flooding's cost")
    }

    @Test
    fun `standard scenario sizes all run`() {
        // Scenarios A-D from the plan, at a density that keeps them connected.
        for ((label, nodes, areaKm) in listOf(
            Triple("A tiny", 10, 0.2),
            Triple("B small", 100, 0.35),
            Triple("C medium", 1_000, 1.0),
            Triple("D large", 10_000, 3.0),
        )) {
            val result = sandbox(scenario(nodes, areaKm)).runBroadcastScenario(label)
            println("  " + result.row())
            assertTrue(result.peakRelayMemoryBytes <= 25L * 1024 * 1024, "$label breached the relay ceiling")
        }
    }
}
