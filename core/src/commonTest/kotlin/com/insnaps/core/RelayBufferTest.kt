package com.insnaps.core

import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.relay.RelayBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RelayBufferTest {

    private val clock = TestClock()
    private var nextId = 0

    private val config = MeshConfig(
        totalBudgetBytes = 64 * 1024,
        relayBufferBytes = 8192,
        // Scaled down with the buffer: MeshConfig rejects a configuration whose own
        // bounds cannot fit its budget, and the defaults are sized for 25 MB.
        duplicateCacheEntries = 200,
        peerTableEntries = 32,
        perPeerQuotaFraction = 0.25, // 2048 bytes per neighbour
    )

    private fun buffer() = RelayBuffer(config, clock)

    private fun packet(lifetime: Int = 300, payloadSize: Int = 469): Packet {
        // 469 + 31-byte header = 500 bytes, so four packets fill a 2048-byte quota.
        val id = nextId++
        return Packet(
            header = Packet.Header(
                packetId = PacketId(ByteArray(PacketId.SIZE) { (id * 7 + it).toByte() }),
                ttl = 8,
                lifetimeSeconds = lifetime,
                recipientTag = RecipientTag.BROADCAST,
                broadcast = true,
            ),
            payload = ByteArray(payloadSize),
        )
    }

    @Test
    fun `accepts a packet and accounts for its bytes`() {
        val buffer = buffer()
        val p = packet()
        assertEquals(RelayBuffer.Admission.ACCEPTED, buffer.offer(p, "peer-a"))
        assertEquals(p.encodedSize.toLong(), buffer.usedBytes)
        assertEquals(1, buffer.size)
    }

    @Test
    fun `refuses a packet already buffered`() {
        val buffer = buffer()
        val p = packet()
        buffer.offer(p, "peer-a")
        assertEquals(RelayBuffer.Admission.DUPLICATE, buffer.offer(p, "peer-a"))
        assertEquals(1, buffer.size)
    }

    @Test
    fun `a flooding neighbour is capped at its quota instead of evicting others`() {
        val buffer = buffer()
        buffer.offer(packet(), "victim")
        val victimBytes = buffer.bytesHeldFor("victim")

        // The attacker pushes far more than the whole buffer could hold.
        var refusals = 0
        repeat(60) {
            if (buffer.offer(packet(), "attacker") == RelayBuffer.Admission.PEER_QUOTA_EXCEEDED) refusals++
        }

        assertTrue(refusals > 0, "attacker should have been refused once over quota")
        assertTrue(
            buffer.bytesHeldFor("attacker") <= config.perPeerQuotaBytes,
            "attacker held ${buffer.bytesHeldFor("attacker")} over quota ${config.perPeerQuotaBytes}",
        )
        assertEquals(victimBytes, buffer.bytesHeldFor("victim"), "victim traffic must survive the flood")
    }

    @Test
    fun `when full it evicts the packet closest to expiry`() {
        val buffer = buffer()
        val shortLived = packet(lifetime = 10)
        buffer.offer(shortLived, "peer-a")
        // 500 bytes each into an 8192-byte buffer: 16 fit, so 20 forces eviction.
        repeat(20) { buffer.offer(packet(lifetime = 3000), "peer-${it % 8}") }

        assertTrue(buffer.usedBytes <= config.relayBufferBytes, "budget must never be exceeded")
        assertTrue(
            buffer.pending().none { it.packetId == shortLived.packetId },
            "the nearest-to-expiry packet should have been evicted first",
        )
    }

    @Test
    fun `expired packets are dropped and their bytes released`() {
        val buffer = buffer()
        buffer.offer(packet(lifetime = 10), "peer-a")
        buffer.offer(packet(lifetime = 600), "peer-a")

        clock.advanceSeconds(11)
        assertEquals(1, buffer.purgeExpired())
        assertEquals(1, buffer.size)
        assertEquals(buffer.pending().single().encodedSize.toLong(), buffer.usedBytes)
    }

    @Test
    fun `clear discards everything so nothing outlives the session`() {
        val buffer = buffer()
        repeat(5) { buffer.offer(packet(), "peer-a") }
        buffer.clear()
        assertEquals(0, buffer.size)
        assertEquals(0L, buffer.usedBytes)
        assertEquals(0L, buffer.bytesHeldFor("peer-a"))
    }

    @Test
    fun `locally originated packets are not subject to a peer quota`() {
        val buffer = buffer()
        var accepted = 0
        repeat(12) {
            if (buffer.offer(packet(), RelayBuffer.LOCAL_SOURCE) == RelayBuffer.Admission.ACCEPTED) accepted++
        }
        assertTrue(
            buffer.bytesHeldFor(RelayBuffer.LOCAL_SOURCE) > config.perPeerQuotaBytes,
            "our own traffic should not be limited to a neighbour's share",
        )
        assertEquals(12, accepted)
    }
}
