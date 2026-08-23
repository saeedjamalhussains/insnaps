package com.insnaps.core.relay

import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.util.Clock

/**
 * Volatile, byte-budgeted queue of packets awaiting forwarding.
 *
 * Everything here lives in RAM for as long as the packet is in flight and is
 * dropped on forward, on expiry, or on [clear]. Nothing is written to storage.
 *
 * ## Overflow is protocol behaviour, not an implementation detail
 *
 * A budget without an eviction rule is just a crash waiting for enough traffic.
 * The rule is:
 *
 *  1. Expired packets are dropped first -- they were never going to be delivered.
 *  2. A neighbour that already holds its quota ([MeshConfig.perPeerQuotaBytes]) is
 *     refused admission. It cannot evict anyone else's traffic, which is what
 *     bounds a flooding attacker to a slice of the buffer instead of all of it.
 *  3. Only then, if the buffer is still full, the packet closest to its own expiry
 *     is evicted -- it has the least remaining chance of delivery.
 *
 * Rule 2 is the security-relevant one and deliberately precedes rule 3.
 */
class RelayBuffer(
    private val config: MeshConfig,
    private val clock: Clock,
) {
    private class Entry(
        val packet: Packet,
        val sourcePeerId: String,
        val deadlineMillis: Long,
    ) {
        val bytes: Int get() = packet.encodedSize
    }

    private val entries = LinkedHashMap<PacketId, Entry>()
    private val bytesPerPeer = HashMap<String, Long>()

    var usedBytes: Long = 0L
        private set

    val size: Int get() = entries.size

    /** Outcome of an admission attempt, so callers and tests can assert on *why*. */
    enum class Admission { ACCEPTED, DUPLICATE, TOO_LARGE, PEER_QUOTA_EXCEEDED, EXPIRED }

    /**
     * Offers a packet for forwarding.
     *
     * [sourcePeerId] is the neighbour it arrived from, and is what the quota is
     * charged against; locally originated packets pass [LOCAL_SOURCE].
     */
    fun offer(packet: Packet, sourcePeerId: String): Admission {
        val now = clock.nowMillis()
        purgeExpired(now)

        if (packet.encodedSize > Packet.MAX_PACKET_SIZE) return Admission.TOO_LARGE
        if (entries.containsKey(packet.packetId)) return Admission.DUPLICATE

        val incoming = packet.encodedSize.toLong()
        val peerUsage = bytesPerPeer[sourcePeerId] ?: 0L

        // Rule 2: a neighbour over quota is refused, never served by evicting others.
        if (sourcePeerId != LOCAL_SOURCE && peerUsage + incoming > config.perPeerQuotaBytes) {
            return Admission.PEER_QUOTA_EXCEEDED
        }

        // Rule 3: make room by dropping whatever is nearest to expiring.
        while (usedBytes + incoming > config.relayBufferBytes) {
            if (!evictNearestDeadline(protecting = packet.packetId)) return Admission.TOO_LARGE
        }

        entries[packet.packetId] = Entry(
            packet = packet,
            sourcePeerId = sourcePeerId,
            deadlineMillis = now + packet.header.lifetimeSeconds * 1000L,
        )
        usedBytes += incoming
        bytesPerPeer[sourcePeerId] = peerUsage + incoming
        return Admission.ACCEPTED
    }

    /** A buffered packet together with the neighbour it arrived from. */
    class Pending(val packet: Packet, val sourcePeerId: String)

    /** Packets still awaiting forwarding, oldest first. Expired entries are purged first. */
    fun pending(): List<Packet> = pendingEntries().map { it.packet }

    /**
     * Buffered packets with their source, oldest first.
     *
     * The source travels with the packet so the router can avoid forwarding it back
     * to the neighbour that supplied it.
     */
    fun pendingEntries(): List<Pending> {
        purgeExpired(clock.nowMillis())
        return entries.values.map { Pending(it.packet, it.sourcePeerId) }
    }

    /** Drops a packet once it has been forwarded, or once forwarding has been abandoned. */
    fun remove(id: PacketId): Boolean {
        val entry = entries.remove(id) ?: return false
        release(entry)
        return true
    }

    /** Drops every expired packet. Safe to call on a timer; also called on every offer. */
    fun purgeExpired(now: Long = clock.nowMillis()): Int {
        if (entries.isEmpty()) return 0
        var dropped = 0
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next().value
            if (entry.deadlineMillis <= now) {
                iterator.remove()
                release(entry)
                dropped++
            }
        }
        return dropped
    }

    /** Discards all buffered traffic. Called on shutdown, so nothing outlives the session. */
    fun clear() {
        entries.clear()
        bytesPerPeer.clear()
        usedBytes = 0L
    }

    fun bytesHeldFor(sourcePeerId: String): Long = bytesPerPeer[sourcePeerId] ?: 0L

    private fun evictNearestDeadline(protecting: PacketId): Boolean {
        val victim = entries.values
            .filter { it.packet.packetId != protecting }
            .minByOrNull { it.deadlineMillis }
            ?: return false
        entries.remove(victim.packet.packetId)
        release(victim)
        return true
    }

    private fun release(entry: Entry) {
        usedBytes -= entry.bytes
        val remaining = (bytesPerPeer[entry.sourcePeerId] ?: 0L) - entry.bytes
        if (remaining <= 0L) bytesPerPeer.remove(entry.sourcePeerId) else bytesPerPeer[entry.sourcePeerId] = remaining
    }

    companion object {
        /** Source id for locally originated packets, which are not subject to a peer quota. */
        const val LOCAL_SOURCE = "@local"
    }
}
