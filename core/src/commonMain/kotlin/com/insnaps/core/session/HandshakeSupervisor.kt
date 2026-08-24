package com.insnaps.core.session

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.util.Clock

/**
 * Drives handshakes to a definite outcome.
 *
 * Without this, a lost handshake packet is indistinguishable from an absent peer:
 * the caller sends, nothing happens, and every later send returns `NoSession`
 * with no indication of why. Measured over three hops at 30% loss, establishing a
 * session took **nine attempts** — so a single unacknowledged attempt is not a
 * reasonable design on a real radio.
 *
 * This turns that into a bounded exchange that ends in exactly one of two states:
 * established, or failed with a reason.
 *
 * It holds no key material and does no cryptography. It only decides *when* to
 * try again and *when* to stop.
 */
class HandshakeSupervisor(
    private val clock: Clock,
    private val policy: RetryPolicy = RetryPolicy(),
    /** Bounds concurrent attempts, so a peer list cannot become a transmission storm. */
    private val maxConcurrent: Int = 16,
) {

    sealed interface State {
        data object Idle : State
        data class InProgress(val attempt: Int, val nextAttemptAtMillis: Long) : State
        data object Established : State
        data class Failed(val reason: FailureReason, val attempts: Int) : State
    }

    private class Attempt(
        var attempt: Int,
        var nextAttemptAtMillis: Long,
        val deadlineMillis: Long,
    )

    private val pending = LinkedHashMap<PeerIdentity, Attempt>()
    private val failed = LinkedHashMap<PeerIdentity, State.Failed>()

    val inProgressCount: Int get() = pending.size

    /**
     * Registers a new handshake attempt.
     *
     * Returns false if one is already running for this peer — **duplicate
     * suppression**. Without it, a UI that retries on every user tap would open a
     * fresh exchange each time, and the peer would answer whichever it liked.
     */
    fun begin(peer: PeerIdentity): Boolean {
        if (pending.containsKey(peer)) return false
        if (pending.size >= maxConcurrent) return false
        failed.remove(peer)

        val now = clock.nowMillis()
        pending[peer] = Attempt(
            attempt = 1,
            nextAttemptAtMillis = now + policy.delayForAttempt(1),
            deadlineMillis = now + policy.overallTimeoutMillis,
        )
        return true
    }

    /** Records success. The exchange is over and no further attempts are made. */
    fun onEstablished(peer: PeerIdentity) {
        pending.remove(peer)
        failed.remove(peer)
    }

    fun cancel(peer: PeerIdentity) {
        if (pending.remove(peer) != null) {
            failed[peer] = State.Failed(FailureReason.CANCELLED, 0)
        }
    }

    /**
     * Peers whose handshake should be retransmitted now.
     *
     * Calling this records the attempt, so a caller must actually send for each
     * peer returned.
     */
    fun dueForRetry(): List<PeerIdentity> {
        val now = clock.nowMillis()
        val due = ArrayList<PeerIdentity>()
        for ((peer, attempt) in pending) {
            if (now < attempt.nextAttemptAtMillis) continue
            if (attempt.attempt >= policy.maxAttempts) continue
            attempt.attempt++
            attempt.nextAttemptAtMillis = now + policy.delayForAttempt(attempt.attempt)
            due += peer
        }
        return due
    }

    /**
     * Peers whose handshake has definitively failed, removing them from tracking.
     *
     * A caller should report these upward: "could not reach this contact" is a
     * useful thing to tell someone, and silence is not.
     */
    fun collectFailures(): List<Pair<PeerIdentity, State.Failed>> {
        val now = clock.nowMillis()
        val out = ArrayList<Pair<PeerIdentity, State.Failed>>()
        val iterator = pending.entries.iterator()
        while (iterator.hasNext()) {
            val (peer, attempt) = iterator.next()
            val timedOut = now >= attempt.deadlineMillis
            val exhausted = attempt.attempt >= policy.maxAttempts && now >= attempt.nextAttemptAtMillis
            if (!timedOut && !exhausted) continue

            val state = State.Failed(
                reason = if (timedOut) FailureReason.TIMED_OUT else FailureReason.ATTEMPTS_EXHAUSTED,
                attempts = attempt.attempt,
            )
            iterator.remove()
            failed[peer] = state
            out += peer to state
        }
        return out
    }

    fun state(peer: PeerIdentity): State {
        pending[peer]?.let { return State.InProgress(it.attempt, it.nextAttemptAtMillis) }
        failed[peer]?.let { return it }
        return State.Idle
    }

    fun clear() {
        pending.clear()
        failed.clear()
    }
}
