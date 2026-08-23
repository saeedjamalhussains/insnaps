package com.insnaps.core.routing

import com.insnaps.core.crypto.RandomSource
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.ThroughputClass
import com.insnaps.core.util.Clock

/**
 * Volatile table of currently reachable neighbours and how much they can be relied on.
 *
 * The mesh cannot assume every nearby phone is a continuously available relay --
 * on iOS in particular a neighbour may be advertising while being unable to
 * forward anything. Rather than treat all neighbours equally and lose traffic to
 * the unreliable ones, the router ranks them by [PeerRecord.availabilityScore].
 *
 * The score deliberately contains no platform-specific term. Whether a peer is
 * backgrounded, battery-saving or on a slow radio reaches this table only through
 * [PeerHandle.reliabilityHint] and [PeerHandle.throughputClass], which the
 * platform layer computes. The core stays radio-agnostic.
 */
class PeerTable(
    private val maxEntries: Int,
    private val clock: Clock,
    private val stalenessMillis: Long = DEFAULT_STALENESS_MILLIS,
    /**
     * Used only to break ties between equally-scoring neighbours.
     *
     * Without it the ranking is a stable sort over equal scores, so the same
     * neighbours sit at the bottom of every node's list and never get chosen --
     * in a uniform mesh that leaves specific peers permanently unreachable by
     * unicast. The default is deterministic (no jitter) so tests of the scoring
     * itself stay reproducible.
     */
    private val random: RandomSource = RandomSource { ByteArray(it) },
) {
    class PeerRecord internal constructor(
        val handle: PeerHandle,
        var lastSeenMillis: Long,
        var forwardSuccesses: Int = 0,
        var forwardFailures: Int = 0,
    ) {
        /** Observed reliability of this neighbour, smoothed so one failure is not fatal. */
        internal fun deliveryRatio(): Double {
            val attempts = forwardSuccesses + forwardFailures
            if (attempts == 0) return NEUTRAL_DELIVERY_RATIO
            // Laplace smoothing: a peer with 1/1 should not outrank one with 40/41.
            return (forwardSuccesses + 1.0) / (attempts + 2.0)
        }
    }

    private val peers = LinkedHashMap<String, PeerRecord>()

    val size: Int get() = peers.size

    fun onPeerFound(handle: PeerHandle) {
        val now = clock.nowMillis()
        val existing = peers[handle.id]
        if (existing != null) {
            existing.lastSeenMillis = now
            return
        }
        if (peers.size >= maxEntries) evictStalest()
        peers[handle.id] = PeerRecord(handle, now)
    }

    fun onPeerLost(handle: PeerHandle) {
        peers.remove(handle.id)
    }

    fun touch(peerId: String) {
        peers[peerId]?.lastSeenMillis = clock.nowMillis()
    }

    fun recordForwardResult(peerId: String, succeeded: Boolean) {
        val record = peers[peerId] ?: return
        if (succeeded) record.forwardSuccesses++ else record.forwardFailures++
        if (succeeded) record.lastSeenMillis = clock.nowMillis()
    }

    /**
     * Neighbours worth forwarding to, best first, excluding [excluding].
     *
     * [excluding] is normally the peer the packet arrived from: sending it straight
     * back is guaranteed waste, since that neighbour has it already.
     */
    fun rankedPeers(excluding: String? = null): List<PeerRecord> =
        peers.values
            .filter { it.handle.id != excluding }
            .map { it to availabilityScore(it) + tieBreakJitter() }
            .sortedByDescending { it.second }
            .map { it.first }

    /**
     * Small random nudge, smaller than any meaningful score difference, so genuine
     * ranking always dominates and only exact ties are shuffled.
     */
    private fun tieBreakJitter(): Double {
        val b = random.nextBytes(1)
        if (b.isEmpty()) return 0.0
        return (b[0].toInt() and 0xFF) / 255.0 * TIE_BREAK_JITTER
    }

    /**
     * 0.0..1.0 estimate of whether forwarding to this peer will actually work.
     *
     * Three terms, each of which has been observed to matter independently:
     * how recently the peer was seen, how reliable the platform reports it to be,
     * and how well it has actually forwarded for us so far. A fast link is worth
     * a small bonus but never outweighs reachability.
     */
    fun availabilityScore(record: PeerRecord): Double {
        val age = (clock.nowMillis() - record.lastSeenMillis).coerceAtLeast(0L)
        val freshness = if (age >= stalenessMillis) 0.0 else 1.0 - age.toDouble() / stalenessMillis
        val throughputBonus = if (record.handle.throughputClass == ThroughputClass.HIGH) 1.0 else 0.0

        val score = FRESHNESS_WEIGHT * freshness +
            HINT_WEIGHT * record.handle.reliabilityHint +
            DELIVERY_WEIGHT * record.deliveryRatio() +
            THROUGHPUT_WEIGHT * throughputBonus
        return score.coerceIn(0.0, 1.0)
    }

    /** Drops neighbours not heard from within the staleness window. */
    fun purgeStale(): Int {
        val cutoff = clock.nowMillis() - stalenessMillis
        val before = peers.size
        peers.entries.removeAll { it.value.lastSeenMillis < cutoff }
        return before - peers.size
    }

    fun clear() = peers.clear()

    /**
     * Summarises a candidate set for a forwarding decision.
     *
     * The quality term is the mean availability score, so everything the table
     * already knows -- freshness, the platform's reliability hint, observed
     * forwarding success -- feeds the fanout decision without a policy ever
     * learning what a radio is.
     */
    fun linkConditions(candidates: List<PeerRecord>): LinkConditions {
        if (candidates.isEmpty()) return LinkConditions.NONE
        val mean = candidates.sumOf { availabilityScore(it) } / candidates.size
        return LinkConditions(candidates.size, mean.coerceIn(0.0, 1.0))
    }

    /** Approximate retained bytes, for budget accounting. */
    fun estimatedBytes(): Long = peers.size.toLong() * ENTRY_BYTES

    private fun evictStalest() {
        val stalest = peers.values.minByOrNull { it.lastSeenMillis } ?: return
        peers.remove(stalest.handle.id)
    }

    companion object {
        const val DEFAULT_STALENESS_MILLIS = 120_000L

        private const val FRESHNESS_WEIGHT = 0.40
        private const val HINT_WEIGHT = 0.30
        private const val DELIVERY_WEIGHT = 0.25
        private const val THROUGHPUT_WEIGHT = 0.05

        private const val NEUTRAL_DELIVERY_RATIO = 0.5

        /** Must stay below the smallest score gap the weights above can produce. */
        private const val TIE_BREAK_JITTER = 0.02

        /** Handle, id string, timestamps and counters, rounded up. */
        private const val ENTRY_BYTES = 128L
    }
}
