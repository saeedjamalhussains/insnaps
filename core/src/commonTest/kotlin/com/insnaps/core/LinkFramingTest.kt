package com.insnaps.core

import com.insnaps.core.link.LinkFraming
import com.insnaps.core.link.LinkReassembler
import com.insnaps.core.packet.Packet
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Fragmentation across links too small for a whole packet.
 *
 * The sizes here are BLE's, not arbitrary: 514 is the largest ATT write possible,
 * 20 is what a link carries before MTU negotiation, and 543 is a full insnaps
 * packet — which fits neither.
 */
class LinkFramingTest {

    private val clock = TestClock()
    private fun reassembler() = LinkReassembler(clock)

    private fun roundTrip(packet: ByteArray, frameSize: Int, sequence: Int = 1): ByteArray? {
        val reassembler = reassembler()
        var out: ByteArray? = null
        for (frame in LinkFraming.fragment(packet, frameSize, sequence)) {
            out = reassembler.offer("peer", frame) ?: out
        }
        return out
    }

    @Test
    fun `a full packet crosses the largest possible BLE write`() {
        // 543 bytes over a 514-byte link: the case that motivated this layer.
        val packet = Random(1).nextBytes(Packet.MAX_PACKET_SIZE)
        val frames = LinkFraming.fragment(packet, 514, sequence = 7)
        assertEquals(2, frames.size, "543 bytes should need exactly two 514-byte frames")
        assertTrue(frames.all { it.size <= 514 })
        assertContentEquals(packet, roundTrip(packet, 514))
    }

    @Test
    fun `a full packet crosses an unnegotiated 20-byte BLE link`() {
        // The worst case a real phone presents before MTU negotiation.
        val packet = Random(2).nextBytes(Packet.MAX_PACKET_SIZE)
        val frames = LinkFraming.fragment(packet, 20, sequence = 3)
        assertTrue(frames.all { it.size <= 20 })
        // 543 bytes over 16-byte bodies (20 minus the 4-byte header).
        assertEquals(34, frames.size)
        assertContentEquals(packet, roundTrip(packet, 20))
    }

    @Test
    fun `packets of every size round trip over every plausible link`() {
        for (frameSize in listOf(20, 23, 64, 185, 244, 512, 514)) {
            for (size in listOf(1, 31, 100, 512, Packet.MAX_PACKET_SIZE)) {
                val packet = Random(size * frameSize).nextBytes(size)
                assertContentEquals(packet, roundTrip(packet, frameSize), "size=$size frame=$frameSize")
            }
        }
    }

    @Test
    fun `a single-fragment message needs no reassembly state`() {
        val packet = Random(3).nextBytes(100)
        val frames = LinkFraming.fragment(packet, 514, sequence = 1)
        assertEquals(1, frames.size)

        val reassembler = reassembler()
        assertContentEquals(packet, reassembler.offer("peer", frames.single()))
        assertEquals(0, reassembler.trackedPeers, "a whole packet should leave nothing buffered")
    }

    @Test
    fun `fragments arriving out of order still reassemble`() {
        // Ordering is not guaranteed once retries and multiple characteristics are
        // in play, so this cannot be assumed.
        val packet = Random(4).nextBytes(Packet.MAX_PACKET_SIZE)
        val frames = LinkFraming.fragment(packet, 64, sequence = 9).shuffled(Random(5))

        val reassembler = reassembler()
        var out: ByteArray? = null
        for (frame in frames) out = reassembler.offer("peer", frame) ?: out
        assertContentEquals(packet, out)
    }

    @Test
    fun `duplicate fragments are ignored`() {
        val packet = Random(6).nextBytes(300)
        val frames = LinkFraming.fragment(packet, 64, sequence = 2)
        val reassembler = reassembler()

        var out: ByteArray? = null
        for (frame in frames) {
            repeat(3) { out = reassembler.offer("peer", frame) ?: out }
        }
        assertContentEquals(packet, out)
    }

    @Test
    fun `interleaved messages from one peer do not corrupt each other`() {
        val first = Random(7).nextBytes(400)
        val second = Random(8).nextBytes(400)
        val a = LinkFraming.fragment(first, 64, sequence = 1)
        val b = LinkFraming.fragment(second, 64, sequence = 2)

        val reassembler = reassembler()
        val results = mutableListOf<ByteArray>()
        for (i in 0 until maxOf(a.size, b.size)) {
            a.getOrNull(i)?.let { reassembler.offer("peer", it)?.let(results::add) }
            b.getOrNull(i)?.let { reassembler.offer("peer", it)?.let(results::add) }
        }
        assertEquals(2, results.size)
        assertTrue(results.any { it.contentEquals(first) })
        assertTrue(results.any { it.contentEquals(second) })
    }

    @Test
    fun `messages from different peers are kept apart`() {
        val first = Random(9).nextBytes(300)
        val second = Random(10).nextBytes(300)
        // Same sequence number from two peers: a collision only peer scoping prevents.
        val a = LinkFraming.fragment(first, 64, sequence = 1)
        val b = LinkFraming.fragment(second, 64, sequence = 1)

        val reassembler = reassembler()
        val results = mutableListOf<ByteArray>()
        for (i in a.indices) {
            reassembler.offer("A", a[i])?.let(results::add)
            reassembler.offer("B", b[i])?.let(results::add)
        }
        assertTrue(results.any { it.contentEquals(first) })
        assertTrue(results.any { it.contentEquals(second) })
    }

    // ---- adversarial --------------------------------------------------------

    @Test
    fun `a peer cannot grow a buffer beyond one packet`() {
        // Claims 64 fragments and sends oversized bodies: the attack this bounds.
        val reassembler = reassembler()
        var accepted = 0
        repeat(64) { index ->
            val frame = ByteArray(LinkFraming.HEADER_SIZE + 500).also {
                it[0] = 1; it[1] = 5; it[2] = index.toByte(); it[3] = 64
            }
            if (reassembler.offer("attacker", frame) != null) accepted++
        }
        assertEquals(0, accepted, "an over-long message must never complete")
        assertTrue(
            reassembler.estimatedBytes() <= Packet.MAX_PACKET_SIZE.toLong(),
            "buffer grew to ${reassembler.estimatedBytes()}",
        )
        assertTrue(reassembler.droppedFragments > 0)
    }

    @Test
    fun `abandoned partial messages are bounded per peer`() {
        val reassembler = LinkReassembler(clock, maxPerPeer = 4)
        // 500 messages started and never finished.
        repeat(500) { sequence ->
            val frame = ByteArray(LinkFraming.HEADER_SIZE + 10).also {
                it[0] = 1; it[1] = (sequence and 0xFF).toByte(); it[2] = 0; it[3] = 8
            }
            reassembler.offer("attacker", frame)
        }
        assertTrue(reassembler.estimatedBytes() < 1000, "held ${reassembler.estimatedBytes()} bytes")
    }

    @Test
    fun `peers are bounded so a crowd cannot exhaust memory`() {
        val reassembler = LinkReassembler(clock, maxPeers = 8)
        repeat(1_000) { peer ->
            val frame = ByteArray(LinkFraming.HEADER_SIZE + 10).also {
                it[0] = 1; it[1] = 1; it[2] = 0; it[3] = 4
            }
            reassembler.offer("peer-$peer", frame)
        }
        assertTrue(reassembler.trackedPeers <= 8, "tracked ${reassembler.trackedPeers} peers")
    }

    @Test
    fun `partial messages expire`() {
        val reassembler = LinkReassembler(clock, timeoutMillis = 5_000)
        val frames = LinkFraming.fragment(Random(11).nextBytes(300), 64, sequence = 1)
        reassembler.offer("peer", frames.first())
        assertEquals(1, reassembler.trackedPeers)

        clock.advance(5_001)
        // Any offer triggers the sweep; a late fragment must not complete the message.
        assertNull(reassembler.offer("peer", frames.last()))
        assertTrue(reassembler.estimatedBytes() < 300)
    }

    @Test
    fun `a sender changing the fragment count mid-message is rejected`() {
        val reassembler = reassembler()
        val a = ByteArray(LinkFraming.HEADER_SIZE + 10).also { it[0] = 1; it[1] = 1; it[2] = 0; it[3] = 4 }
        val b = ByteArray(LinkFraming.HEADER_SIZE + 10).also { it[0] = 1; it[1] = 1; it[2] = 1; it[3] = 9 }
        reassembler.offer("peer", a)
        assertNull(reassembler.offer("peer", b))
        assertTrue(reassembler.droppedFragments > 0)
    }

    @Test
    fun `fuzzing the reassembler never throws`() {
        val reassembler = reassembler()
        val random = Random(20260824)
        repeat(50_000) {
            reassembler.offer("fuzz-${random.nextInt(6)}", random.nextBytes(random.nextInt(0, 80)))
        }
        assertTrue(reassembler.estimatedBytes() < 100_000)
    }

    @Test
    fun `forgetting a peer releases its buffers`() {
        val reassembler = reassembler()
        reassembler.offer("peer", LinkFraming.fragment(Random(12).nextBytes(300), 64, 1).first())
        reassembler.forget("peer")
        assertEquals(0, reassembler.trackedPeers)
        assertEquals(0L, reassembler.estimatedBytes())
    }

    @Test
    fun `a link too small to be usable is rejected at the call site`() {
        assertFailsWith<IllegalArgumentException> {
            LinkFraming.fragment(ByteArray(100), LinkFraming.MIN_FRAME_SIZE - 1, 1)
        }
        assertFalse(LinkFraming.fits(Packet.MAX_PACKET_SIZE, 8))
        assertTrue(LinkFraming.fits(Packet.MAX_PACKET_SIZE, 20))
    }

    @Test
    fun `sequence numbers wrap without collision in practice`() {
        val packet = Random(13).nextBytes(200)
        for (sequence in listOf(0, 1, 255, 256, 511)) {
            assertNotNull(roundTrip(packet, 64, sequence), "sequence $sequence failed")
        }
    }
}
