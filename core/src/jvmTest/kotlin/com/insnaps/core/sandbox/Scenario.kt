package com.insnaps.core.sandbox

import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.ForwardingPolicy

/**
 * One sandbox experiment, expressed as data.
 *
 * Scenarios are configuration rather than code so a sweep -- density, loss,
 * routing policy, seed -- is a loop over values instead of a recompiled
 * simulator. [parse] reads the same fields from a `key=value` text block.
 *
 * **These are simulation parameters, not handset measurements.** A 100 m BLE
 * range is a plausible open-air figure, not something measured on a phone in a
 * street with walls and bodies in the way.
 */
data class SandboxConfig(
    val seed: Long = 1,
    val nodes: Int = 100,
    /** Side length of the square area, in metres. 10_000 gives a 10 km x 10 km map. */
    val areaMetres: Double = 1_000.0,
    val bleRangeMetres: Double = 100.0,

    val packetLoss: Double = 0.0,
    val duplicationRate: Double = 0.0,
    val connectionFailureRate: Double = 0.0,
    val minLatencyMillis: Long = 20,
    val maxLatencyMillis: Long = 60,
    /** Effective link throughput. 0 disables serialization delay. */
    val bandwidthBytesPerSecond: Long = 4_000,
    val discoveryDelayMillis: Long = 1_000,

    val androidRatio: Double = 0.7,
    val foregroundRatio: Double = 0.5,
    val mobility: Mobility = Mobility.Stationary,

    val broadcastPolicy: ForwardingPolicy = ForwardingPolicy.AdaptiveFanout(),
    val unicastPolicy: ForwardingPolicy = ForwardingPolicy.BoundedFanout(3),
    val meshConfig: MeshConfig = MeshConfig(),

    /** Whether devices run the real session layer. Off for large routing runs. */
    val useRealE2EE: Boolean = false,

    /** How often mobility and re-linking are applied, in virtual milliseconds. */
    val tickMillis: Long = 1_000,

    /** Hard ceiling per relay. Breaching it fails the run. */
    val maxRelayMemoryBytes: Long = 25L * 1024 * 1024,

    val maxQueuedEvents: Int = 4_000_000,
) {
    val areaKm: Double get() = areaMetres / 1000.0

    /** Devices per square kilometre. The variable that actually decides connectivity. */
    val densityPerKm2: Double get() = nodes / (areaKm * areaKm)

    /**
     * Expected neighbours per device for a uniform scatter: `n * pi * r^2 / A`.
     *
     * Worth computing ahead of a run: below roughly 4.5 the graph percolates into
     * islands and no routing policy can help, so a low delivery rate would be a
     * property of the map rather than of insnaps.
     */
    val expectedDegree: Double
        get() = nodes * Math.PI * bleRangeMetres * bleRangeMetres / (areaMetres * areaMetres)

    companion object {
        /**
         * Reads a `key=value` scenario block, ignoring blanks and `#` comments.
         *
         * Unknown keys throw rather than being skipped: a typo in a sweep would
         * otherwise silently run the default and be reported as a result.
         */
        fun parse(text: String, base: SandboxConfig = SandboxConfig()): SandboxConfig {
            var config = base
            for (raw in text.lines()) {
                val line = raw.substringBefore('#').trim()
                if (line.isEmpty()) continue
                val key = line.substringBefore('=').trim()
                val value = line.substringAfter('=').trim()
                config = when (key) {
                    "seed" -> config.copy(seed = value.toLong())
                    "nodes" -> config.copy(nodes = value.toInt())
                    "area_km" -> config.copy(areaMetres = value.toDouble() * 1000.0)
                    "ble_range_m" -> config.copy(bleRangeMetres = value.toDouble())
                    "packet_loss" -> config.copy(packetLoss = value.toDouble())
                    "duplication" -> config.copy(duplicationRate = value.toDouble())
                    "connection_failure" -> config.copy(connectionFailureRate = value.toDouble())
                    "latency_min_ms" -> config.copy(minLatencyMillis = value.toLong())
                    "latency_max_ms" -> config.copy(maxLatencyMillis = value.toLong())
                    "bandwidth_bps" -> config.copy(bandwidthBytesPerSecond = value.toLong())
                    "android_ratio" -> config.copy(androidRatio = value.toDouble())
                    "ios_ratio" -> config.copy(androidRatio = 1.0 - value.toDouble())
                    "foreground_ratio" -> config.copy(foregroundRatio = value.toDouble())
                    "mobility" -> config.copy(mobility = parseMobility(value))
                    "routing" -> config.copy(broadcastPolicy = parseRouting(value))
                    "e2ee" -> config.copy(useRealE2EE = value.toBoolean())
                    "tick_ms" -> config.copy(tickMillis = value.toLong())
                    else -> throw IllegalArgumentException("unknown scenario key: $key")
                }
            }
            return config
        }

        private fun parseMobility(value: String): Mobility = when (value.lowercase()) {
            "false", "none", "stationary" -> Mobility.Stationary
            "true", "walking" -> Mobility.Walking()
            "random" -> Mobility.RandomWalk()
            "vehicle" -> Mobility.Vehicle()
            else -> throw IllegalArgumentException("unknown mobility: $value")
        }

        private fun parseRouting(value: String): ForwardingPolicy = when (value.lowercase()) {
            "adaptive" -> ForwardingPolicy.AdaptiveFanout()
            "flood" -> ForwardingPolicy.FullFlood
            "fanout3" -> ForwardingPolicy.BoundedFanout(3)
            "fanout6" -> ForwardingPolicy.BoundedFanout(6)
            "gossip" -> ForwardingPolicy.Probabilistic(0.5)
            else -> throw IllegalArgumentException("unknown routing policy: $value")
        }
    }
}

/** Everything one run produced. */
data class SandboxResult(
    val label: String,
    val nodes: Int,
    val areaKm: Double,
    val densityPerKm2: Double,
    val averageDegree: Double,
    val connectedFraction: Double,
    val deliveryRate: Double,
    val averageHops: Double,
    val maxHops: Int,
    val medianLatencyMillis: Long,
    val maxLatencyMillis: Long,
    val framesSent: Long,
    val amplification: Double,
    val peakRelayMemoryBytes: Long,
    val packetLoss: Double,
    val framesLost: Long,
    val failedTransfers: Int = 0,
    val batteryProxyFramesPerDevice: Double = 0.0,
) {
    fun render(): String = buildString {
        appendLine("────────────────────────────────────────────")
        appendLine("insnaps Sandbox Result — $label")
        appendLine("────────────────────────────────────────────")
        appendLine("Nodes:              %,d".format(nodes))
        appendLine("Area:               %.1f km x %.1f km".format(areaKm, areaKm))
        appendLine("Density:            %,.1f /km²".format(densityPerKm2))
        appendLine("Avg degree:         %.1f".format(averageDegree))
        appendLine("Connected:          %.1f%% (largest component)".format(connectedFraction * 100))
        appendLine("Delivery:           %.1f%%".format(deliveryRate * 100))
        appendLine("Avg hops:           %.1f".format(averageHops))
        appendLine("Max hops:           %d".format(maxHops))
        appendLine("Latency p50 / max:  %,d ms / %,d ms".format(medianLatencyMillis, maxLatencyMillis))
        appendLine("Packets:            %,d".format(framesSent))
        appendLine("Amplification:      %.1fx".format(amplification))
        appendLine("Peak relay RAM:     %.2f MB".format(peakRelayMemoryBytes / 1024.0 / 1024.0))
        appendLine("Packet loss:        %.0f%% (%,d dropped)".format(packetLoss * 100, framesLost))
        appendLine("Battery proxy:      %.1f frames/device".format(batteryProxyFramesPerDevice))
        if (failedTransfers > 0) appendLine("Failed transfers:   $failedTransfers")
        appendLine("────────────────────────────────────────────")
    }

    /** One line, for sweeps. */
    fun row(): String = "%-22s n=%-6d deg=%-5.1f conn=%-6.1f%% deliv=%-6.1f%% hops=%-5.1f amp=%-5.1fx relayRAM=%.2fMB"
        .format(label, nodes, averageDegree, connectedFraction * 100, deliveryRate * 100,
            averageHops, amplification, peakRelayMemoryBytes / 1024.0 / 1024.0)
}

/**
 * Aggregates repeated runs of one scenario.
 *
 * A single seeded run of a random geographic scatter says very little: one
 * unlucky arrangement can island a corner of the map. Repeating across seeds and
 * reporting the spread is the difference between a measurement and an anecdote.
 */
data class MonteCarloResult(
    val label: String,
    val runs: Int,
    val samples: List<Double>,
) {
    val mean: Double get() = samples.average()
    val median: Double get() = sorted()[runs / 2]
    val min: Double get() = samples.min()
    val max: Double get() = samples.max()

    fun percentile(p: Int): Double = sorted()[((runs - 1) * p / 100).coerceIn(0, runs - 1)]

    private fun sorted() = samples.sorted()

    fun render(): String = buildString {
        appendLine("$label over $runs runs:")
        appendLine("  mean %.1f%%  median %.1f%%  p5 %.1f%%  p95 %.1f%%  min %.1f%%  max %.1f%%"
            .format(mean * 100, median * 100, percentile(5) * 100, percentile(95) * 100, min * 100, max * 100))
    }
}
