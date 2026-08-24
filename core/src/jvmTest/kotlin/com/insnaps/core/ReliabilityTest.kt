package com.insnaps.core

import com.insnaps.core.file.TransferAck
import com.insnaps.core.session.FailureReason
import com.insnaps.core.session.HandshakeSupervisor
import com.insnaps.core.session.RetryPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * v0.8.1 reliability primitives: bounded handshake retransmission and selective
 * acknowledgement.
 *
 * These exist because the sandbox showed each stage of
 * `handshake -> manifest -> chunks -> completion` failing differently on a lossy
 * path, and each failing silently.
 */
class ReliabilityTest {

    private val clock = TestClock()
    private val alice = identity("alice")
    private val bob = identity("bob")

    // ---- handshake supervision ---------------------------------------------

    @Test
    fun `a second attempt for the same peer is suppressed`() {
        // A user tapping "connect" twice must not open two exchanges.
        val supervisor = HandshakeSupervisor(clock)
        assertTrue(supervisor.begin(bob))
        assertFalse(supervisor.begin(bob), "a duplicate handshake was allowed")
        assertEquals(1, supervisor.inProgressCount)
    }

    @Test
    fun `retries are spaced by backoff, not fired every tick`() {
        val policy = RetryPolicy(initialDelayMillis = 1_000, backoffMultiplier = 2.0, maxAttempts = 5)
        val supervisor = HandshakeSupervisor(clock, policy)
        supervisor.begin(bob)

        assertTrue(supervisor.dueForRetry().isEmpty(), "nothing is due before the first delay elapses")

        val gaps = mutableListOf<Long>()
        var last = clock.nowMillis()
        repeat(4) {
            // Advance until exactly one retry comes due.
            while (supervisor.dueForRetry().isEmpty()) clock.advance(250)
            gaps += clock.nowMillis() - last
            last = clock.nowMillis()
        }

        assertTrue(gaps.zipWithNext().all { (a, b) -> b >= a }, "backoff should not shrink: $gaps")
        assertTrue(gaps.last() > gaps.first(), "backoff never widened: $gaps")
    }

    @Test
    fun `a handshake that is never answered fails with a reason`() {
        val policy = RetryPolicy(initialDelayMillis = 1_000, maxAttempts = 3, overallTimeoutMillis = 60_000)
        val supervisor = HandshakeSupervisor(clock, policy)
        supervisor.begin(bob)

        // Collected on each tick, as a caller would: waiting until long after the
        // attempts ran out would also trip the overall deadline and report that
        // instead, which says nothing about attempt exhaustion.
        var failures = emptyList<Pair<com.insnaps.core.crypto.PeerIdentity, HandshakeSupervisor.State.Failed>>()
        repeat(200) {
            clock.advance(1_000)
            supervisor.dueForRetry()
            if (failures.isEmpty()) failures = supervisor.collectFailures()
        }

        assertEquals(1, failures.size)
        assertEquals(FailureReason.ATTEMPTS_EXHAUSTED, failures.single().second.reason)
        assertTrue(supervisor.state(bob) is HandshakeSupervisor.State.Failed)
        assertEquals(0, supervisor.inProgressCount)
    }

    @Test
    fun `the overall deadline stops an exchange even with attempts left`() {
        val policy = RetryPolicy(
            initialDelayMillis = 1_000, maxAttempts = 1_000, overallTimeoutMillis = 10_000,
        )
        val supervisor = HandshakeSupervisor(clock, policy)
        supervisor.begin(bob)

        repeat(20) { clock.advance(1_000); supervisor.dueForRetry() }
        val failures = supervisor.collectFailures()
        assertEquals(FailureReason.TIMED_OUT, failures.single().second.reason)
    }

    @Test
    fun `success stops retransmission immediately`() {
        val supervisor = HandshakeSupervisor(clock, RetryPolicy(initialDelayMillis = 1_000))
        supervisor.begin(bob)
        supervisor.onEstablished(bob)

        clock.advance(600_000)
        assertTrue(supervisor.dueForRetry().isEmpty(), "an established peer must not be retried")
        assertTrue(supervisor.collectFailures().isEmpty())
        assertEquals(HandshakeSupervisor.State.Idle, supervisor.state(bob))
    }

    @Test
    fun `concurrent handshakes are bounded`() {
        val supervisor = HandshakeSupervisor(clock, maxConcurrent = 4)
        val started = (1..50).count { supervisor.begin(identity("peer-$it")) }
        assertEquals(4, started, "an unbounded peer list would become a transmission storm")
    }

    @Test
    fun `cancelling reports a reason rather than vanishing`() {
        val supervisor = HandshakeSupervisor(clock)
        supervisor.begin(bob)
        supervisor.cancel(bob)
        val state = supervisor.state(bob)
        assertTrue(state is HandshakeSupervisor.State.Failed && state.reason == FailureReason.CANCELLED)
    }

    // ---- selective acknowledgement -----------------------------------------

    @Test
    fun `an acknowledgement round trips`() {
        val ack = TransferAck(42, listOf(18..18, 4_001..4_003), complete = false)
        assertEquals(ack, TransferAck.decode(ack.encode()))
    }

    @Test
    fun `ranges collapse a scattered missing set`() {
        // The point of ranges: the ACK size tracks the number of gaps, not the
        // size of the file.
        val missing = listOf(1, 2, 3, 10, 11, 500)
        assertEquals(listOf(1..3, 10..11, 500..500), TransferAck.toRanges(missing))
    }

    @Test
    fun `a huge contiguous gap is one small acknowledgement`() {
        // 200,000 missing chunks described in eight bytes.
        val ranges = TransferAck.toRanges((0 until 200_000).toList())
        assertEquals(1, ranges.size)
        val ack = TransferAck(1, ranges, complete = false)
        assertTrue(ack.encode().size < 32, "a whole-file gap should not need a large packet")
    }

    @Test
    fun `an acknowledgement always fits inside one packet`() {
        val ranges = (0 until TransferAck.MAX_RANGES).map { (it * 4)..(it * 4 + 1) }
        val encoded = TransferAck(1, ranges, complete = false).encode()
        assertTrue(
            encoded.size <= com.insnaps.core.app.AppMessage.MAX_BODY_SIZE,
            "acknowledgement of ${encoded.size} bytes does not fit a packet",
        )
    }

    @Test
    fun `malformed acknowledgements decode to null`() {
        assertNull(TransferAck.decode(ByteArray(0)))
        assertNull(TransferAck.decode(ByteArray(5)))
        val valid = TransferAck(1, listOf(1..2), complete = false).encode()
        assertNull(TransferAck.decode(valid.copyOf(valid.size - 1)), "a truncated ack must be rejected")
        assertNull(TransferAck.decode(valid + ByteArray(3)), "trailing bytes must be rejected")
        for (size in 0..64) TransferAck.decode(ByteArray(size) { (it * 29).toByte() })
    }

    @Test
    fun `a reversed range is rejected`() {
        // Would otherwise be nonsense for a sender to act on.
        val bytes = TransferAck(1, listOf(5..5), complete = false).encode()
        bytes[bytes.size - 1] = 0  // make last < first
        assertNull(TransferAck.decode(bytes))
    }

    @Test
    fun `the complete flag survives encoding`() {
        val ack = TransferAck(7, emptyList(), complete = true)
        assertTrue(TransferAck.decode(ack.encode())!!.complete)
    }
}
