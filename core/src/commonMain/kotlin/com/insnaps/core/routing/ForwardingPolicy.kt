package com.insnaps.core.routing

import com.insnaps.core.crypto.RandomSource

/**
 * How many neighbours a packet is forwarded to, and which.
 *
 * This exists so the flooding question can be *measured* rather than argued.
 * Full-neighbour flooding is what the protocol specifies today (PROTOCOL.md
 * §2.1); whether it stays viable as neighbour density grows is an open
 * acceptance criterion, and the alternatives have to be runnable side by side
 * under identical conditions to settle it.
 *
 * A policy never appears on the wire. Nodes running different policies
 * interoperate — only the traffic they generate differs.
 */
sealed interface ForwardingPolicy {

    /**
     * Forward to every neighbour except the sender.
     *
     * Maximum delivery probability, maximum traffic. Cost per packet is
     * `O(degree)` at every node, so total frames scale with `nodes x degree`.
     */
    data object FullFlood : ForwardingPolicy

    /**
     * Forward to the [k] highest-scoring neighbours.
     *
     * Bounded cost per node regardless of density. The risk is coverage: with
     * similarly-scored neighbours the selection is near-deterministic, so the
     * same peers can sit below the cut on every node's list. `PeerTable` breaks
     * exact ties randomly for this reason, but the risk does not vanish.
     */
    data class BoundedFanout(val k: Int) : ForwardingPolicy {
        init { require(k >= 1) { "fanout must be at least 1" } }
    }

    /**
     * Fanout chosen from the conditions the node is actually in.
     *
     * The default policy, and the one the protocol specifies. It exists because
     * the v0.3 measurements showed the right fanout is not a constant: a bounded
     * fanout matches flooding's coverage in a dense mesh for a fraction of the
     * traffic, while in a sparse or lossy one the redundancy of flooding is what
     * carries delivery.
     *
     * Rather than pick one and lose the other, this widens the fanout as
     * conditions worsen and collapses to full flooding when the neighbourhood is
     * too thin for any restriction to be safe:
     *
     * ```
     *   degree <= floodBelowDegree            -> every neighbour (flooding)
     *   quality >= goodQuality                -> goodFanout      (dense, healthy)
     *   quality >= moderateQuality            -> moderateFanout  (some loss)
     *   otherwise                             -> poorFanout      (struggling)
     * ```
     *
     * [LinkConditions.meanQuality] is the average neighbour availability score,
     * which already folds in freshness, the platform's reliability hint, and
     * observed forwarding success — so a mesh full of backgrounded iOS relays
     * automatically widens its fanout without the core knowing what iOS is.
     *
     * The fanout is always clamped to the number of neighbours, so in a sparse
     * mesh this degenerates to flooding on its own.
     */
    data class AdaptiveFanout(
        val goodFanout: Int = 6,
        val moderateFanout: Int = 10,
        val poorFanout: Int = 16,
        /** At or below this degree, restricting the fanout risks isolating nodes. */
        val floodBelowDegree: Int = 6,
        val goodQuality: Double = 0.65,
        val moderateQuality: Double = 0.40,
    ) : ForwardingPolicy {
        init {
            require(goodFanout in 1..moderateFanout) { "goodFanout must be >=1 and <= moderateFanout" }
            require(moderateFanout <= poorFanout) { "moderateFanout must be <= poorFanout" }
            require(floodBelowDegree >= 0)
            require(moderateQuality in 0.0..goodQuality) { "moderateQuality must be <= goodQuality" }
            require(goodQuality <= 1.0)
        }

        fun fanoutFor(conditions: LinkConditions): Int = when {
            conditions.neighbourCount <= floodBelowDegree -> conditions.neighbourCount
            conditions.meanQuality >= goodQuality -> goodFanout
            conditions.meanQuality >= moderateQuality -> moderateFanout
            else -> poorFanout
        }
    }

    /**
     * Forward to each neighbour independently with probability [p], but never to
     * fewer than [minTargets].
     *
     * Classic gossip: cost grows with density like flooding but with a constant
     * factor below 1, while coverage stays probabilistic rather than structurally
     * excluding anyone. [minTargets] keeps a sparse node from silently becoming a
     * dead end when every coin flip comes up tails.
     */
    data class Probabilistic(val p: Double, val minTargets: Int = 1) : ForwardingPolicy {
        init {
            require(p > 0.0 && p <= 1.0) { "gossip probability must be in (0.0, 1.0]" }
            require(minTargets >= 1) { "minTargets must be at least 1" }
        }
    }

    companion object {
        /**
         * Applies a policy to a ranked candidate list.
         *
         * [candidates] must already be ordered best-first; every policy preserves
         * that ordering in what it returns. [conditions] describes the
         * neighbourhood the decision is being made in, and only [AdaptiveFanout]
         * consults it.
         */
        fun <T> select(
            policy: ForwardingPolicy,
            candidates: List<T>,
            conditions: LinkConditions,
            random: RandomSource,
        ): List<T> {
            if (candidates.isEmpty()) return emptyList()
            return when (policy) {
                is FullFlood -> candidates
                is BoundedFanout -> candidates.take(policy.k)
                is AdaptiveFanout -> candidates.take(policy.fanoutFor(conditions))
                is Probabilistic -> {
                    val chosen = candidates.filter { coinFlip(random) < policy.p }
                    // Falling back to the best-ranked neighbours rather than random
                    // ones: if the coins fail us, use the links most likely to work.
                    if (chosen.size >= policy.minTargets) chosen
                    else candidates.take(policy.minTargets)
                }
            }
        }

        private fun coinFlip(random: RandomSource): Double {
            val b = random.nextBytes(2)
            if (b.size < 2) return 0.0
            val value = ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF)
            return value / 65535.0
        }
    }
}

/**
 * The state of a node's neighbourhood at the moment a forwarding decision is made.
 *
 * Deliberately abstract: no radio, no platform, no packet. A policy sees how many
 * neighbours there are and how good they are, and nothing else.
 */
data class LinkConditions(
    val neighbourCount: Int,
    /** Mean neighbour availability, 0.0..1.0. */
    val meanQuality: Double,
) {
    init {
        require(neighbourCount >= 0)
        require(meanQuality in 0.0..1.0) { "meanQuality must be in 0.0..1.0" }
    }

    companion object {
        val NONE = LinkConditions(0, 0.0)
    }
}
