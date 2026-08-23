package com.insnaps.core.sim

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Does insnaps still work as the number of participants grows?
 *
 * These runs answer the v0.3 question directly: coverage, traffic amplification,
 * latency and memory across 100 / 1,000 / 10,000 nodes and across sparse, normal
 * and dense topologies. Every run is seeded, so any failure replays exactly.
 */
class ScaleTest {

    private fun broadcastScenario(
        label: String,
        nodes: Int,
        topology: (SimNetwork, Int) -> Unit,
        seed: Long = 20260824,
    ): ScenarioResult {
        val network = SimNetwork(seed)
        topology(network, nodes)
        network.startAll()
        return network.runBroadcast(label).also { print(it.table()) }
    }

    @Test
    fun `broadcast across 100 nodes`() {
        val result = broadcastScenario("100 nodes, normal density", 100, Topology::normal)
        assertTrue(result.coverage >= 0.99, "coverage ${result.coverage}")
        assertTrue(result.amplification < 30, "amplification ${result.amplification}")
    }

    @Test
    fun `broadcast across 1000 nodes`() {
        val result = broadcastScenario("1,000 nodes, normal density", 1_000, Topology::normal)
        assertTrue(result.coverage >= 0.99, "coverage ${result.coverage}")
        assertTrue(result.amplification < 30, "amplification ${result.amplification}")
    }

    @Test
    fun `broadcast across 10000 nodes`() {
        val result = broadcastScenario("10,000 nodes, normal density", 10_000, Topology::normal)
        assertTrue(result.coverage >= 0.99, "coverage ${result.coverage}")
        assertTrue(result.amplification < 30, "amplification ${result.amplification}")
    }

    @Test
    fun `sparse topology at 1000 nodes`() {
        val result = broadcastScenario("1,000 nodes, sparse", 1_000, Topology::sparse)
        assertTrue(result.coverage >= 0.95, "coverage ${result.coverage}")
    }

    @Test
    fun `dense topology at 1000 nodes`() {
        val result = broadcastScenario("1,000 nodes, dense", 1_000, Topology::dense)
        assertTrue(result.coverage >= 0.99, "coverage ${result.coverage}")
    }

    @Test
    fun `memory stays under the ceiling at every scale`() {
        for (n in listOf(100, 1_000, 10_000)) {
            val network = SimNetwork(99)
            Topology.normal(network, n)
            network.startAll()
            network.runBroadcast("mem-$n")
            val ceiling = network.config.meshConfig.totalBudgetBytes
            assertTrue(
                network.peakNodeMemory() <= ceiling,
                "at $n nodes the peak node held ${network.peakNodeMemory()} against a $ceiling ceiling",
            )
        }
    }

    @Test
    fun `unicast reaches a distant node across 1000 relays`() {
        val network = SimNetwork(7)
        Topology.normal(network, 1_000)
        network.startAll()

        val target = network.node(500)
        network.node(0).engine.send(target.identity, network.node(0).payload(42))
        network.run()

        assertTrue(target.deliveries.containsKey(42), "unicast never arrived")
    }
}
