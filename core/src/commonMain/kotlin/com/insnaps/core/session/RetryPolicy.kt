package com.insnaps.core.session

/**
 * Bounded retransmission schedule for a control message.
 *
 * Every field is a bound. A mesh has no congestion control and no central
 * scheduler, so an unbounded retry is an attack on the network by its own
 * participants: a node that retries forever at a fixed interval will keep
 * transmitting long after the peer has gone, spending everyone's battery.
 */
data class RetryPolicy(
    val initialDelayMillis: Long = 2_000,
    /** Each attempt waits longer, so a peer that is simply absent stops being chased. */
    val backoffMultiplier: Double = 1.8,
    /**
     * Ceiling on the gap between attempts.
     *
     * Kept low enough that [maxAttempts] actually fits inside
     * [overallTimeoutMillis]. With a 30 s ceiling the schedule reached the overall
     * deadline after 14 of 16 attempts, so the attempt budget was fiction and the
     * exchange reported a timeout rather than exhaustion.
     */
    val maxDelayMillis: Long = 10_000,
    /**
     * Attempts before giving up.
     *
     * Sized for multi-hop, not for a single link.
     *
     * Loss compounds with distance, and a handshake needs *two* packets to
     * survive, so the per-attempt success rate is the square of path survival:
     * 20% per-hop loss over five hops leaves about a third of packets arriving
     * and therefore only ~11% of attempts succeeding. Eight attempts failed
     * outright at that distance; sixteen was marginal enough to succeed at ten
     * hops and fail at five on the same loss.
     *
     * 32 attempts covers the intended envelope — up to 20% per-hop loss across
     * ten hops — at about 97% per exchange. Beyond that envelope (30%+ loss on a
     * long path) no retry budget rescues it; the path is simply not usable, and
     * the exchange fails with a reason rather than retrying forever.
     */
    val maxAttempts: Int = 32,
    /** Hard ceiling on the whole exchange, regardless of attempts. */
    val overallTimeoutMillis: Long = 420_000,
) {
    init {
        require(initialDelayMillis > 0)
        require(backoffMultiplier >= 1.0)
        require(maxDelayMillis >= initialDelayMillis)
        require(maxAttempts >= 1)
        require(overallTimeoutMillis >= initialDelayMillis)
    }

    /**
     * Total time the full attempt schedule occupies.
     *
     * Worth checking against [overallTimeoutMillis] when tuning: if the schedule
     * is longer, the attempt budget is fiction and exchanges will report a timeout
     * rather than exhaustion. Deliberately *not* enforced, because a short deadline
     * with a generous attempt count is a legitimate "fail fast" configuration.
     */
    fun totalScheduleMillis(): Long = (1..maxAttempts).sumOf { delayForAttempt(it) }

    /** Delay before attempt [attempt], counting the first send as attempt 1. */
    fun delayForAttempt(attempt: Int): Long {
        var delay = initialDelayMillis.toDouble()
        repeat((attempt - 1).coerceAtLeast(0)) { delay *= backoffMultiplier }
        return delay.toLong().coerceAtMost(maxDelayMillis)
    }
}

/** Why a bounded exchange stopped. */
enum class FailureReason {
    /** Every attempt was made and none was answered. */
    ATTEMPTS_EXHAUSTED,

    /** The overall deadline passed. */
    TIMED_OUT,

    /** Abandoned locally -- the user cancelled, or the session went away. */
    CANCELLED,
}
