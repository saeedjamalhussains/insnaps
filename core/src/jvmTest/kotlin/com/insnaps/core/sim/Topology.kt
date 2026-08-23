package com.insnaps.core.sim

import kotlin.random.Random

/**
 * Topology generators for stress runs.
 *
 * Every generator starts from a ring, which guarantees the graph is connected --
 * a disconnected graph would make a low delivery rate look like a protocol
 * failure when it is really a generator artefact -- and then adds random chords.
 *
 * The chords matter more than they look. A pure ring of 10,000 nodes has a
 * diameter of 5,000 hops, which no packet can cross under a 24-hop limit, so a
 * ring-only topology measures the hop limit rather than the routing. Random
 * chords collapse the diameter to roughly `log(n)` -- the small-world effect --
 * which is also a fair model of real device placement, where people are clustered
 * but occasionally near a stranger who bridges two groups.
 */
object Topology {

    /** Average degree ~3. Models a thin chain of participants. */
    fun sparse(network: SimNetwork, nodes: Int, seed: Long = network.seed) =
        build(network, nodes, chordsPerNode = 1, seed = seed)

    /** Average degree ~8. Models an ordinary busy public space. */
    fun normal(network: SimNetwork, nodes: Int, seed: Long = network.seed) =
        build(network, nodes, chordsPerNode = 3, seed = seed)

    /** Average degree ~24. Models a crowd: a concert, a protest, a transit hub. */
    fun dense(network: SimNetwork, nodes: Int, seed: Long = network.seed) =
        build(network, nodes, chordsPerNode = 11, seed = seed)

    /**
     * Two dense clusters joined by a single link.
     *
     * The bridge node is the interesting part: it is a single point of failure for
     * inter-cluster delivery and the place where relay-buffer pressure concentrates.
     */
    fun bridgedClusters(network: SimNetwork, perCluster: Int, seed: Long = network.seed) {
        network.addNodes(perCluster * 2)
        val random = Random(seed)
        for (base in listOf(0, perCluster)) {
            for (i in 0 until perCluster) {
                val a = base + i
                val b = base + (i + 1) % perCluster
                network.link(a, b)
                repeat(4) { network.link(a, base + random.nextInt(perCluster)) }
            }
        }
        network.link(perCluster - 1, perCluster) // the only bridge
    }

    /**
     * One centre surrounded by [spokes] leaves, with no edges between leaves.
     *
     * Used for attacks on a single node: forwarding cannot escape past the leaves,
     * so injected traffic accumulates at the centre instead of flooding outward.
     * That keeps the measurement on the victim rather than on the simulator.
     */
    fun star(network: SimNetwork, spokes: Int) {
        network.addNodes(spokes + 1)
        for (i in 1..spokes) network.link(0, i)
    }

    /** A line of nodes: 0 - 1 - 2 - ... Forwarding is bounded to one path. */
    fun line(network: SimNetwork, nodes: Int) {
        network.addNodes(nodes)
        for (i in 0 until nodes - 1) network.link(i, i + 1)
    }

    private fun build(network: SimNetwork, nodes: Int, chordsPerNode: Int, seed: Long) {
        require(nodes >= 2) { "need at least two nodes" }
        network.addNodes(nodes)
        val random = Random(seed)

        for (i in 0 until nodes) network.link(i, (i + 1) % nodes)

        repeat(chordsPerNode) {
            for (i in 0 until nodes) {
                val other = random.nextInt(nodes)
                if (other != i) network.link(i, other)
            }
        }
    }
}

/** Result of one broadcast or unicast scenario, with everything needed to judge it. */
data class ScenarioResult(
    val label: String,
    val nodes: Int,
    val averageDegree: Double,
    val coverage: Double,
    val framesSent: Long,
    val framesLost: Long,
    val amplification: Double,
    val medianLatencyMillis: Long,
    val p95LatencyMillis: Long,
    val peakNodeMemoryBytes: Long,
    val duplicatesDropped: Long,
    val hopLimitDropped: Long,
    val quotaDropped: Long,
) {
    fun table(): String = buildString {
        appendLine("  $label")
        appendLine("    nodes=$nodes  avgDegree=${"%.1f".format(averageDegree)}")
        appendLine("    coverage=${"%.1f".format(coverage * 100)}%  " +
            "latency p50=${medianLatencyMillis}ms p95=${p95LatencyMillis}ms")
        appendLine("    frames=$framesSent  amplification=${"%.1f".format(amplification)}x/node  lost=$framesLost")
        appendLine("    peakNodeMem=${peakNodeMemoryBytes / 1024}KB  " +
            "dupDropped=$duplicatesDropped  hopLimit=$hopLimitDropped  quota=$quotaDropped")
    }
}

/** Runs one broadcast from [origin] and measures what happened. */
fun SimNetwork.runBroadcast(label: String, origin: Int = 0, messageId: Int = 1): ScenarioResult {
    val startTime = clock.now
    node(origin).engine.broadcast(node(origin).payload(messageId))
    run()

    val reached = (0 until nodeCount).count { it != origin && node(it).deliveries.containsKey(messageId) }
    val latencies = (0 until nodeCount)
        .mapNotNull { node(it).deliveries[messageId] }
        .map { it - startTime }
        .sorted()

    val stats = aggregateStats()
    return ScenarioResult(
        label = label,
        nodes = nodeCount,
        averageDegree = averageDegree(),
        coverage = if (nodeCount <= 1) 1.0 else reached.toDouble() / (nodeCount - 1),
        framesSent = metrics.framesSent,
        framesLost = metrics.framesLost,
        amplification = metrics.framesSent.toDouble() / nodeCount,
        medianLatencyMillis = latencies.getOrElse(latencies.size / 2) { 0 },
        p95LatencyMillis = latencies.getOrElse((latencies.size * 95) / 100) { 0 },
        peakNodeMemoryBytes = peakNodeMemory(),
        duplicatesDropped = stats.duplicatesDropped,
        hopLimitDropped = stats.hopLimitDropped,
        quotaDropped = stats.quotaDropped,
    )
}

/** Starts every node. Call after the topology is built. */
fun SimNetwork.startAll() {
    for (i in 0 until nodeCount) node(i).start()
}
