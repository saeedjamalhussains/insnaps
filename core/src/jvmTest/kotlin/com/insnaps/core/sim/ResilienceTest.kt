package com.insnaps.core.sim

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Does the mesh still deliver when the radio environment misbehaves?
 *
 * Loss, duplication and nodes vanishing mid-flight are the normal condition on
 * BLE between moving phones, not exceptional ones, so these are correctness
 * tests rather than stress tests.
 */
class ResilienceTest {

    @Test
    fun `delivers through 20 percent packet loss`() {
        val network = SimNetwork(1234, SimNetwork.SimConfig(lossRate = 0.20))
        Topology.normal(network, 1_000)
        network.startAll()

        val result = network.runBroadcast("1,000 nodes, 20% loss")
        print(result.table())

        // Flooding's redundancy is what pays for loss: a node has many chances to
        // hear a packet, so coverage degrades far more slowly than the loss rate.
        assertTrue(result.coverage >= 0.95, "coverage collapsed to ${result.coverage} under 20% loss")
        assertTrue(result.framesLost > 0, "the loss model did not engage")
    }

    @Test
    fun `survives 50 percent packet loss with degraded coverage`() {
        val network = SimNetwork(555, SimNetwork.SimConfig(lossRate = 0.50))
        Topology.normal(network, 1_000)
        network.startAll()

        val result = network.runBroadcast("1,000 nodes, 50% loss")
        print(result.table())
        assertTrue(result.coverage >= 0.80, "coverage ${result.coverage} at 50% loss")
    }

    @Test
    fun `duplicated frames are absorbed without amplifying traffic`() {
        val network = SimNetwork(77, SimNetwork.SimConfig(duplicateRate = 0.30))
        Topology.normal(network, 1_000)
        network.startAll()

        val result = network.runBroadcast("1,000 nodes, 30% duplication")
        print(result.table())

        // Every duplicate must die at the duplicate cache rather than being
        // forwarded again, or a lossy radio becomes a traffic multiplier.
        assertTrue(result.coverage >= 0.99)
        assertTrue(network.metrics.framesDuplicated > 0)
        assertTrue(result.amplification < 30, "duplication inflated traffic to ${result.amplification}x")
    }

    @Test
    fun `delivers while ten percent of nodes disappear mid-flight`() {
        val network = SimNetwork(31337)
        Topology.normal(network, 1_000)
        network.startAll()

        network.node(0).engine.broadcast(network.node(0).payload(1))
        network.runSteps(800) // let the wave start

        // A tenth of the mesh walks out of range at once.
        val casualties = (1 until 1_000 step 10).toList()
        casualties.forEach { network.disconnect(it) }
        network.run()

        val survivors = (1 until 1_000).filter { it !in casualties }
        val reached = survivors.count { network.node(it).deliveries.containsKey(1) }
        val coverage = reached.toDouble() / survivors.size
        println("  churn: ${"%.1f".format(coverage * 100)}% of surviving nodes reached")

        assertTrue(coverage >= 0.90, "coverage among survivors was $coverage")
    }

    @Test
    fun `a node that reconnects can receive again`() {
        val network = SimNetwork(4242)
        Topology.normal(network, 200)
        network.startAll()

        network.disconnect(50)
        network.node(0).engine.broadcast(network.node(0).payload(1))
        network.run()
        assertTrue(network.node(50).deliveries.isEmpty(), "a disconnected node should hear nothing")

        network.reconnect(50)
        network.node(0).engine.broadcast(network.node(0).payload(2))
        network.run()
        assertTrue(network.node(50).deliveries.containsKey(2), "a reconnected node should hear again")
    }

    @Test
    fun `traffic crosses a single bridge between two clusters`() {
        val network = SimNetwork(8080)
        Topology.bridgedClusters(network, perCluster = 500)
        network.startAll()

        val result = network.runBroadcast("two 500-node clusters, one bridge")
        print(result.table())
        assertTrue(result.coverage >= 0.99, "the bridge did not carry the broadcast: ${result.coverage}")
    }

    @Test
    fun `combined loss duplication and churn still delivers`() {
        // Everything wrong at once, which is closer to a real crowd than any single fault.
        val network = SimNetwork(2026, SimNetwork.SimConfig(lossRate = 0.15, duplicateRate = 0.15))
        Topology.normal(network, 2_000)
        network.startAll()

        network.node(0).engine.broadcast(network.node(0).payload(1))
        network.runSteps(2_000)
        (1 until 2_000 step 20).forEach { network.disconnect(it) }
        network.runSteps(2_000)
        (1 until 2_000 step 20).forEach { network.reconnect(it) }
        network.run()

        val alive = (1 until 2_000).filter { !network.isDown(it) }
        val coverage = alive.count { network.node(it).deliveries.containsKey(1) }.toDouble() / alive.size
        println("  combined faults: ${"%.1f".format(coverage * 100)}% coverage")
        assertTrue(coverage >= 0.85, "coverage $coverage under combined faults")
    }
}
