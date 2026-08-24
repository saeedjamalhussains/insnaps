package com.insnaps.core.link

import com.insnaps.core.packet.Packet
import com.insnaps.core.util.Clock

/**
 * Splits packets across links that cannot carry them whole, and puts them back.
 *
 * ## Why this exists
 *
 * A full insnaps packet is 543 bytes. The largest ATT write BLE permits is 514
 * (MTU 517 minus the 3-byte header), and before MTU negotiation a link carries
 * **20**. So a packet does not fit even the best case, and on a freshly connected
 * device it is nowhere close.
 *
 * The protocol is not changed to accommodate that. Fragmentation is a link
 * concern, and keeping it here means `MeshEngine` still deals in whole packets
 * and the same code serves BLE, a future iOS link, and the sandbox.
 *
 * ## Adversarial by default
 *
 * Reassembly buffers hold attacker-supplied bytes: anyone in radio range can send
 * fragments that never complete, claim implausible sizes, or interleave thousands
 * of half-messages. Every buffer is therefore bounded in count, in size and in
 * age, and a message that would exceed [Packet.MAX_PACKET_SIZE] is refused before
 * anything is allocated for it.
 */
object LinkFraming {

    /** `version | sequence | index | total` */
    const val HEADER_SIZE = 4

    private const val VERSION = 1

    /** A message may be split into at most this many fragments. */
    const val MAX_FRAGMENTS = 64

    /** Smallest link this can work over: BLE's pre-negotiation 20-byte payload. */
    const val MIN_FRAME_SIZE = HEADER_SIZE + 8

    /**
     * Splits [packet] into fragments no larger than [maxFrameBytes].
     *
     * [sequence] distinguishes messages in flight from the same sender and wraps
     * at 256, which is ample: a link carries a handful of messages at once, not
     * hundreds.
     */
    fun fragment(packet: ByteArray, maxFrameBytes: Int, sequence: Int): List<ByteArray> {
        require(maxFrameBytes >= MIN_FRAME_SIZE) { "link frame $maxFrameBytes is too small to carry anything" }
        require(packet.isNotEmpty()) { "cannot fragment an empty packet" }

        val perFragment = maxFrameBytes - HEADER_SIZE
        val total = (packet.size + perFragment - 1) / perFragment
        require(total <= MAX_FRAGMENTS) {
            "packet of ${packet.size} bytes needs $total fragments over a $maxFrameBytes-byte link, " +
                "more than the $MAX_FRAGMENTS limit"
        }

        return (0 until total).map { index ->
            val start = index * perFragment
            val end = minOf(start + perFragment, packet.size)
            ByteArray(HEADER_SIZE + (end - start)).also { frame ->
                frame[0] = VERSION.toByte()
                frame[1] = (sequence and 0xFF).toByte()
                frame[2] = index.toByte()
                frame[3] = total.toByte()
                packet.copyInto(frame, HEADER_SIZE, start, end)
            }
        }
    }

    /** True if a packet of [packetBytes] can cross a link of [maxFrameBytes]. */
    fun fits(packetBytes: Int, maxFrameBytes: Int): Boolean {
        if (maxFrameBytes < MIN_FRAME_SIZE) return false
        val perFragment = maxFrameBytes - HEADER_SIZE
        return (packetBytes + perFragment - 1) / perFragment <= MAX_FRAGMENTS
    }
}

/**
 * Reassembles fragments back into packets, one instance per node.
 *
 * State is per (peer, sequence). Everything about it is bounded, because it is
 * fed directly from the radio by whoever is nearby.
 */
class LinkReassembler(
    private val clock: Clock,
    /** In-flight messages tracked per peer. */
    private val maxPerPeer: Int = 4,
    /** Peers tracked at once. */
    private val maxPeers: Int = 64,
    /** A partial message older than this is abandoned. */
    private val timeoutMillis: Long = 10_000,
) {

    private class Partial(
        val total: Int,
        val fragments: Array<ByteArray?>,
        val startedAtMillis: Long,
    ) {
        var received = 0
        var bytes = 0
    }

    private val partials = LinkedHashMap<String, LinkedHashMap<Int, Partial>>()

    /** Fragments discarded as malformed or over-limit. Diagnostics only. */
    var droppedFragments: Long = 0
        private set

    val trackedPeers: Int get() = partials.size

    /**
     * Offers one received frame.
     *
     * Returns the completed packet, or null if more fragments are needed or the
     * frame was rejected. Rejection is silent and routine: on an open radio,
     * malformed frames are ordinary traffic.
     */
    fun offer(peerId: String, frame: ByteArray): ByteArray? {
        purgeExpired()

        if (frame.size <= LinkFraming.HEADER_SIZE) return reject()
        if (frame[0].toInt() != 1) return reject()

        val sequence = frame[1].toInt() and 0xFF
        val index = frame[2].toInt() and 0xFF
        val total = frame[3].toInt() and 0xFF
        if (total == 0 || total > LinkFraming.MAX_FRAGMENTS) return reject()
        if (index >= total) return reject()

        val body = frame.copyOfRange(LinkFraming.HEADER_SIZE, frame.size)

        // A single fragment is the common case on a well-negotiated link; skip all
        // the bookkeeping for it.
        if (total == 1) return if (body.size <= Packet.MAX_PACKET_SIZE) body else reject()

        val forPeer = partials.getOrPut(peerId) {
            if (partials.size >= maxPeers) evictOldestPeer()
            LinkedHashMap()
        }

        val partial = forPeer.getOrPut(sequence) {
            if (forPeer.size >= maxPerPeer) {
                // Drop the oldest half-finished message rather than growing.
                forPeer.keys.firstOrNull()?.let { forPeer.remove(it) }
            }
            Partial(total, arrayOfNulls(total), clock.nowMillis())
        }

        // A sender changing its mind about the size mid-message is malformed.
        if (partial.total != total) return reject()
        if (partial.fragments[index] != null) return null // duplicate fragment, expected on a mesh

        // Refuse before allocating: never let a peer grow a buffer past one packet.
        if (partial.bytes + body.size > Packet.MAX_PACKET_SIZE) {
            forPeer.remove(sequence)
            return reject()
        }

        partial.fragments[index] = body
        partial.received++
        partial.bytes += body.size
        if (partial.received < partial.total) return null

        forPeer.remove(sequence)
        if (forPeer.isEmpty()) partials.remove(peerId)

        val out = ByteArray(partial.bytes)
        var offset = 0
        for (piece in partial.fragments) {
            val chunk = piece ?: return reject()
            chunk.copyInto(out, offset)
            offset += chunk.size
        }
        return out
    }

    /** Forgets everything for a peer that has gone away. */
    fun forget(peerId: String) {
        partials.remove(peerId)
    }

    fun clear() = partials.clear()

    /** Approximate retained bytes, so this counts toward the relay budget. */
    fun estimatedBytes(): Long =
        partials.values.sumOf { peer -> peer.values.sumOf { it.bytes.toLong() } }

    private fun purgeExpired() {
        if (partials.isEmpty()) return
        val cutoff = clock.nowMillis() - timeoutMillis
        val peerIterator = partials.entries.iterator()
        while (peerIterator.hasNext()) {
            val peer = peerIterator.next().value
            peer.entries.removeAll { it.value.startedAtMillis < cutoff }
            if (peer.isEmpty()) peerIterator.remove()
        }
    }

    private fun evictOldestPeer() {
        partials.keys.firstOrNull()?.let { partials.remove(it) }
    }

    private fun reject(): ByteArray? {
        droppedFragments++
        return null
    }
}
