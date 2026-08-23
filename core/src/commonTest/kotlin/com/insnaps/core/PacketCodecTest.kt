package com.insnaps.core

import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class PacketCodecTest {

    /** version(1) + flags(1) + packetId(16) */
    private val TTL_OFFSET = 1 + 1 + PacketId.SIZE

    private fun packet(
        ttl: Int = 8,
        lifetime: Int = 300,
        payload: ByteArray = "hello".encodeToByteArray(),
        broadcast: Boolean = false,
    ) = Packet(
        header = Packet.Header(
            packetId = PacketId(ByteArray(PacketId.SIZE) { it.toByte() }),
            ttl = ttl,
            lifetimeSeconds = lifetime,
            recipientTag = RecipientTag(ByteArray(RecipientTag.SIZE) { (it + 1).toByte() }),
            broadcast = broadcast,
        ),
        payload = payload,
    )

    @Test
    fun `round trips through the wire format`() {
        val original = packet()
        val decoded = Packet.decode(original.encode())
        assertEquals(original, decoded)
    }

    @Test
    fun `header size matches the encoded length of an empty payload`() {
        val encoded = packet(payload = ByteArray(0)).encode()
        assertEquals(Packet.HEADER_SIZE, encoded.size)
    }

    @Test
    fun `preserves the broadcast flag`() {
        val decoded = Packet.decode(packet(broadcast = true).encode())
        assertTrue(decoded!!.header.broadcast)
    }

    @Test
    fun `rejects an unknown protocol version`() {
        val bytes = packet().encode()
        bytes[0] = 99
        assertNull(Packet.decode(bytes))
    }

    @Test
    fun `rejects a truncated frame`() {
        val bytes = packet().encode()
        assertNull(Packet.decode(bytes.copyOf(bytes.size - 1)))
    }

    @Test
    fun `rejects trailing bytes beyond the declared payload length`() {
        // A peer must not be able to append unmetered data that the budget never sees.
        val bytes = packet().encode()
        assertNull(Packet.decode(bytes + ByteArray(4)))
    }

    @Test
    fun `rejects a zero hop limit`() {
        val bytes = packet().encode()
        bytes[TTL_OFFSET] = 0
        assertNull(Packet.decode(bytes))
    }

    @Test
    fun `rejects a payload over the maximum size`() {
        assertFailsWith<IllegalArgumentException> {
            packet(payload = ByteArray(Packet.MAX_PAYLOAD_SIZE + 1)).encode()
        }
    }

    @Test
    fun `decrementing the hop limit stops at the last hop`() {
        assertEquals(7, packet(ttl = 8).decrementTtl()!!.ttl)
        assertNull(packet(ttl = 1).decrementTtl())
    }

    @Test
    fun `an all zero recipient tag is broadcast`() {
        assertTrue(RecipientTag.BROADCAST.isBroadcast)
        assertTrue(!packet().header.recipientTag.isBroadcast)
    }

    @Test
    fun `garbage of every plausible length decodes to null rather than throwing`() {
        for (size in 0..Packet.MAX_PACKET_SIZE step 7) {
            Packet.decode(ByteArray(size) { (it * 37).toByte() })
        }
    }
}
