package com.insnaps.core.packet

import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter
import com.insnaps.core.util.toHex

/**
 * The insnaps wire packet.
 *
 * ## What a relay can and cannot see
 *
 * Everything in [Header] is cleartext, because a relay must be able to act on it
 * without holding any key: it needs [ttl] to enforce the hop limit, [packetId] to
 * suppress duplicates, [lifetimeSeconds] to expire the packet, and [recipientTag]
 * to decide whether the packet is addressed to itself.
 *
 * [payload] is opaque. It is the sender's AEAD ciphertext, including its
 * authentication tag, and no relay holds a key that can open it. The core never
 * inspects, parses or logs payload bytes.
 *
 * ## Addressing and the metadata tradeoff
 *
 * [recipientTag] is deliberately *not* a stable identity. It is a short rotating
 * tag that only the intended recipient can recognise (see `RecipientAddressing`).
 * This is the middle point of a real tradeoff:
 *
 *  - A cleartext recipient identity would let every relay build a social graph.
 *  - A fully opaque destination would force pure flooding, which does not hold a
 *    bounded memory budget at any useful density.
 *
 * A rotating tag leaks a pseudonym that is linkable only within one rotation
 * period. That residual leak is the accepted cost, and it is confined to this
 * one field so an onion-routed header can replace it without touching the rest
 * of the protocol.
 */
data class Packet(
    val header: Header,
    val payload: ByteArray,
) {
    data class Header(
        val packetId: PacketId,
        val ttl: Int,
        val lifetimeSeconds: Int,
        val recipientTag: RecipientTag,
        val broadcast: Boolean,
    )

    val packetId: PacketId get() = header.packetId
    val ttl: Int get() = header.ttl

    /** Total encoded size. This is the figure charged against the relay memory budget. */
    val encodedSize: Int get() = HEADER_SIZE + payload.size

    /** Returns a copy with the hop limit decremented, or null if it must not be forwarded further. */
    fun decrementTtl(): Packet? =
        if (header.ttl <= 1) null else copy(header = header.copy(ttl = header.ttl - 1))

    fun encode(): ByteArray {
        require(payload.size <= MAX_PAYLOAD_SIZE) {
            "payload ${payload.size} exceeds MAX_PAYLOAD_SIZE $MAX_PAYLOAD_SIZE"
        }
        require(header.ttl in 1..MAX_TTL) { "ttl ${header.ttl} out of range 1..$MAX_TTL" }
        require(header.lifetimeSeconds in 1..MAX_LIFETIME_SECONDS) {
            "lifetimeSeconds ${header.lifetimeSeconds} out of range 1..$MAX_LIFETIME_SECONDS"
        }
        return ByteWriter(encodedSize)
            .u8(PROTOCOL_VERSION)
            .u8(if (header.broadcast) FLAG_BROADCAST else 0)
            .bytes(header.packetId.bytes)
            .u8(header.ttl)
            .u16(header.lifetimeSeconds)
            .bytes(header.recipientTag.bytes)
            .u16(payload.size)
            .bytes(payload)
            .finish()
    }

    // Value semantics over the payload array, which `data class` would compare by identity.
    override fun equals(other: Any?): Boolean =
        this === other || (other is Packet && header == other.header && payload.contentEquals(other.payload))

    override fun hashCode(): Int = 31 * header.hashCode() + payload.contentHashCode()

    override fun toString(): String =
        "Packet(id=${header.packetId}, ttl=${header.ttl}, tag=${header.recipientTag}, payload=${payload.size}B)"

    companion object {
        const val PROTOCOL_VERSION = 1
        const val FLAG_BROADCAST = 0x01

        /** version + flags + packetId + ttl + lifetime + recipientTag + payloadLength */
        const val HEADER_SIZE = 1 + 1 + PacketId.SIZE + 1 + 2 + RecipientTag.SIZE + 2

        /**
         * Sized so a whole packet clears a conservative BLE connection in a small number
         * of writes. BLE is the universal transport, so the ceiling is set by BLE even
         * when a given hop happens to run over Wi-Fi.
         */
        const val MAX_PAYLOAD_SIZE = 512
        const val MAX_PACKET_SIZE = HEADER_SIZE + MAX_PAYLOAD_SIZE

        const val MAX_TTL = 64
        const val MAX_LIFETIME_SECONDS = 3600

        /**
         * Decodes a packet received from an untrusted peer.
         *
         * Returns null rather than throwing for every malformed input: a peer that
         * sends garbage is an expected condition on an open mesh, not an error the
         * caller should have to handle as an exception.
         */
        fun decode(bytes: ByteArray): Packet? {
            if (bytes.size < HEADER_SIZE || bytes.size > MAX_PACKET_SIZE) return null
            return try {
                val r = ByteReader(bytes)
                if (r.u8() != PROTOCOL_VERSION) return null
                val flags = r.u8()
                val packetId = PacketId(r.bytes(PacketId.SIZE))
                val ttl = r.u8()
                val lifetime = r.u16()
                val tag = RecipientTag(r.bytes(RecipientTag.SIZE))
                val payloadLength = r.u16()

                if (ttl !in 1..MAX_TTL) return null
                if (lifetime !in 1..MAX_LIFETIME_SECONDS) return null
                if (payloadLength > MAX_PAYLOAD_SIZE) return null
                // Reject trailing bytes: the declared length must account for the remainder
                // exactly, so a peer cannot smuggle unmetered data past the budget.
                if (r.remaining != payloadLength) return null

                Packet(
                    header = Header(
                        packetId = packetId,
                        ttl = ttl,
                        lifetimeSeconds = lifetime,
                        recipientTag = tag,
                        broadcast = (flags and FLAG_BROADCAST) != 0,
                    ),
                    payload = r.bytes(payloadLength),
                )
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}

/**
 * Random per-packet identifier, used only for duplicate suppression.
 *
 * It must carry no derivable relationship to the sender: relays index on it, so
 * any structure here would become a correlation handle across hops.
 */
class PacketId(val bytes: ByteArray) {
    init { require(bytes.size == SIZE) { "packet id must be $SIZE bytes" } }

    override fun equals(other: Any?): Boolean =
        this === other || (other is PacketId && bytes.contentEquals(other.bytes))

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = bytes.toHex().take(8)

    companion object { const val SIZE = 16 }
}

/**
 * Short rotating tag identifying the intended recipient of a packet.
 *
 * [BROADCAST] (all zero) marks a packet every node should deliver locally as well
 * as forward.
 */
class RecipientTag(val bytes: ByteArray) {
    init { require(bytes.size == SIZE) { "recipient tag must be $SIZE bytes" } }

    val isBroadcast: Boolean get() = bytes.all { it == 0.toByte() }

    override fun equals(other: Any?): Boolean =
        this === other || (other is RecipientTag && bytes.contentEquals(other.bytes))

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = if (isBroadcast) "broadcast" else bytes.toHex()

    companion object {
        const val SIZE = 8
        val BROADCAST = RecipientTag(ByteArray(SIZE))
    }
}
