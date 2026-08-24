package com.insnaps.core.sandbox

import com.insnaps.core.crypto.JvmCryptoProvider

/** Builds a populated, started sandbox from a scenario. */
fun sandbox(config: SandboxConfig): SandboxNetwork =
    SandboxNetwork(config, JvmCryptoProvider()).apply {
        populate(config.nodes)
        startAll()
    }

/**
 * Runs one broadcast across the map and measures what happened.
 *
 * Delivery is reported against the **connected component the sender is in**, not
 * against every device on the map. In a sparse geographic scatter the graph
 * fragments into islands, and counting unreachable islands as delivery failures
 * would blame the protocol for the map. The connected fraction is reported
 * alongside so the two are never confused.
 */
fun SandboxNetwork.runBroadcastScenario(label: String, origin: Int = 0, messageId: Int = 1): SandboxResult {
    val start = clock.now
    node(origin).engine.broadcast(node(origin).payload(messageId))
    run()

    val reachableIds = reachableFrom(origin)
    val reached = reachableIds.count { it != origin && node(it).deliveries.containsKey(messageId) }
    val expected = (reachableIds.size - 1).coerceAtLeast(1)

    val latencies = reachableIds.mapNotNull { node(it).deliveries[messageId] }.map { it - start }.sorted()
    val hopCounts = reachableIds.mapNotNull { hopsAtDelivery[it to messageId] }

    return SandboxResult(
        label = label,
        nodes = deviceCount,
        areaKm = config.areaKm,
        densityPerKm2 = config.densityPerKm2,
        averageDegree = averageDegree(),
        connectedFraction = largestComponentFraction(),
        deliveryRate = reached.toDouble() / expected,
        averageHops = if (hopCounts.isEmpty()) 0.0 else hopCounts.average(),
        maxHops = hopCounts.maxOrNull() ?: 0,
        medianLatencyMillis = latencies.getOrElse(latencies.size / 2) { 0 },
        maxLatencyMillis = latencies.maxOrNull() ?: 0,
        framesSent = metrics.framesSent,
        amplification = metrics.framesSent.toDouble() / deviceCount,
        peakRelayMemoryBytes = metrics.peakRelayMemoryBytes,
        packetLoss = config.packetLoss,
        framesLost = metrics.framesLost,
        batteryProxyFramesPerDevice = allDevices().map { it.framesSent }.average(),
    )
}

/** Device ids reachable from [origin] over current radio links. */
fun SandboxNetwork.reachableFrom(origin: Int): Set<Int> {
    val seen = HashSet<Int>()
    val stack = ArrayDeque(listOf(origin))
    seen.add(origin)
    while (stack.isNotEmpty()) {
        for (n in neighbours(stack.removeLast())) if (seen.add(n)) stack.addLast(n)
    }
    return seen
}

/**
 * Repeats a scenario across seeds and reports the spread.
 *
 * A geographic scatter is random, so one run is an anecdote. [runs] separate
 * seeds give a distribution, and the percentiles are what should be quoted --
 * a mean alone hides the unlucky arrangements that matter most.
 */
fun monteCarlo(
    label: String,
    runs: Int,
    base: SandboxConfig,
    measure: (SandboxResult) -> Double = { it.deliveryRate },
): MonteCarloResult {
    val samples = (0 until runs).map { i ->
        val network = sandbox(base.copy(seed = base.seed + i))
        measure(network.runBroadcastScenario("$label #$i"))
    }
    return MonteCarloResult(label, runs, samples)
}
