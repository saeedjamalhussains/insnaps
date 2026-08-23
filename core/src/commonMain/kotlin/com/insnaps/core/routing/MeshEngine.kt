package com.insnaps.core.routing

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RandomSource
import com.insnaps.core.crypto.RecipientAddressing
import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.relay.DuplicateCache
import com.insnaps.core.relay.RelayBuffer
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.Transport
import com.insnaps.core.transport.TransportListener
import com.insnaps.core.util.Clock

/**
 * The insnaps relay node: everything that decides whether a packet is delivered,
 * forwarded or dropped.
 *
 * This class is entirely platform-independent and holds all of its state in
 * memory. It is the component the whole design exists to make testable -- a full
 * multi-hop mesh can be exercised on the JVM by wiring several engines together
 * with a simulated transport and no radios.
 *
 * It never inspects [Packet.payload]. Payload bytes are ciphertext the sender
 * produced for the recipient; a relay holds no key that opens them and this class
 * has no code path that tries.
 */
class MeshEngine(
    private val config: MeshConfig,
    private val clock: Clock,
    private val random: RandomSource,
    private val addressing: RecipientAddressing,
    private val transport: Transport,
    private val listener: MeshListener,
    /**
     * How broadcast traffic is spread.
     *
     * Defaults to the specified behaviour: adaptive bounded fanout, widening as
     * conditions worsen and collapsing to full flooding in a thin neighbourhood
     * (PROTOCOL.md §2.1). Swappable so alternatives can be measured under
     * identical conditions, and so a deployment can force flooding if it must.
     */
    private val broadcastPolicy: ForwardingPolicy = ForwardingPolicy.AdaptiveFanout(),
    /**
     * How unicast traffic is spread.
     *
     * Bounded by default: a unicast packet has one destination, so flooding every
     * neighbour buys little and costs a lot.
     */
    private val unicastPolicy: ForwardingPolicy = ForwardingPolicy.BoundedFanout(DEFAULT_FANOUT),
) : TransportListener {

    interface MeshListener {
        /**
         * A packet addressed to this device arrived.
         *
         * [ciphertext] is still encrypted: decryption is the session layer's job,
         * above the mesh. The mesh's responsibility ends at delivery.
         */
        fun onMessageDelivered(ciphertext: ByteArray, broadcast: Boolean)
    }

    /** Counters for diagnostics and tests. Deliberately carries no packet content. */
    data class Stats(
        var framesReceived: Long = 0,
        var malformedDropped: Long = 0,
        var duplicatesDropped: Long = 0,
        var expiredDropped: Long = 0,
        var hopLimitDropped: Long = 0,
        var quotaDropped: Long = 0,
        var delivered: Long = 0,
        var forwarded: Long = 0,
        var originated: Long = 0,
    )

    private val duplicates = DuplicateCache(
        maxEntries = config.duplicateCacheEntries,
        retentionMillis = config.duplicateRetentionSeconds * 1000L,
        clock = clock,
    )
    private val buffer = RelayBuffer(config, clock)
    private val peers = PeerTable(config.peerTableEntries, clock, random = random)

    val stats = Stats()

    /**
     * Guards against re-entering [flush].
     *
     * A transport that delivers synchronously -- a loopback, a test harness, or a
     * platform that calls back on the sending thread -- turns `flush -> send ->
     * onFrame -> flush` into unbounded recursion, which overflows the stack in a
     * dense mesh and double-counts forwards on the way.
     *
     * A re-entrant call therefore does not recurse -- but it must not simply be
     * discarded either. Work queued during a nested call (a handshake reply, a
     * packet to relay onward) would sit in the buffer with nothing scheduled to
     * move it, stalling delivery until some unrelated event happened to flush.
     * Instead the nested call raises [flushRequested] and the outer loop runs
     * again, draining the new work iteratively rather than recursively.
     */
    private var flushing = false
    private var flushRequested = false
    val pendingCount: Int get() = buffer.size
    val bufferedBytes: Long get() = buffer.usedBytes
    val peerCount: Int get() = peers.size

    /**
     * Approximate bytes retained by the relay subsystem right now.
     *
     * Every structure that grows with traffic is counted, so the 25 MB target is
     * an enforced accounting rather than an aspiration.
     */
    fun estimatedMemoryBytes(): Long =
        buffer.usedBytes + duplicates.estimatedBytes() + peers.estimatedBytes()

    fun start() = transport.start(this)

    /**
     * Stops the node and discards all volatile state.
     *
     * This is the point at which the RAM-only guarantee is honoured: buffered
     * traffic, remembered packet ids and the peer table all cease to exist, and
     * none of them were ever written anywhere else.
     */
    fun stop() {
        transport.stop()
        buffer.clear()
        duplicates.clear()
        peers.clear()
    }

    // ---- origination -------------------------------------------------------

    /**
     * Queues a message addressed to [recipient].
     *
     * [ciphertext] must already be sealed for the recipient. The engine will not
     * encrypt for the caller, precisely so there is no code path in which the mesh
     * layer holds a message key.
     */
    fun send(recipient: PeerIdentity, ciphertext: ByteArray): PacketId =
        originate(ciphertext, addressing.tagFor(recipient), broadcast = false)

    /**
     * Queues handshake traffic to [recipient], addressed by bootstrap tag.
     *
     * Separate from [send] because handshake packets must be addressable before a
     * session exists in either direction.
     */
    fun sendHandshake(recipient: PeerIdentity, payload: ByteArray): PacketId =
        originate(payload, addressing.handshakeTagFor(recipient), broadcast = false)

    /** Queues a message every reachable node should receive. */
    fun broadcast(ciphertext: ByteArray): PacketId =
        originate(ciphertext, RecipientTag.BROADCAST, broadcast = true)

    private fun originate(ciphertext: ByteArray, tag: RecipientTag, broadcast: Boolean): PacketId {
        require(ciphertext.size <= Packet.MAX_PAYLOAD_SIZE) {
            "payload ${ciphertext.size} exceeds MAX_PAYLOAD_SIZE ${Packet.MAX_PAYLOAD_SIZE}"
        }
        val packet = Packet(
            header = Packet.Header(
                packetId = PacketId(random.nextBytes(PacketId.SIZE)),
                ttl = config.defaultTtl,
                lifetimeSeconds = config.defaultLifetimeSeconds,
                recipientTag = tag,
                broadcast = broadcast,
            ),
            payload = ciphertext,
        )
        // Remember our own id so a copy looping back through the mesh is not re-forwarded.
        duplicates.offer(packet.packetId)
        buffer.offer(packet, RelayBuffer.LOCAL_SOURCE)
        stats.originated++
        flush()
        return packet.packetId
    }

    // ---- transport callbacks ----------------------------------------------

    override fun onPeerFound(peer: PeerHandle) {
        peers.onPeerFound(peer)
        // A new neighbour may be the first route out for traffic already waiting.
        flush()
    }

    override fun onPeerLost(peer: PeerHandle) {
        peers.onPeerLost(peer)
    }

    override fun onFrame(peer: PeerHandle, bytes: ByteArray) {
        stats.framesReceived++
        peers.touch(peer.id)

        val packet = Packet.decode(bytes)
        if (packet == null) {
            stats.malformedDropped++
            return
        }

        if (!duplicates.offer(packet.packetId)) {
            stats.duplicatesDropped++
            return
        }

        val mine = packet.header.recipientTag.isBroadcast || addressing.isForMe(packet.header.recipientTag)
        if (mine) {
            stats.delivered++
            listener.onMessageDelivered(packet.payload, packet.header.broadcast)
            // A unicast packet that reached its recipient stops here. A broadcast
            // keeps travelling, because other nodes still need it.
            if (!packet.header.broadcast) return
        }

        val forwarded = packet.decrementTtl()
        if (forwarded == null) {
            stats.hopLimitDropped++
            return
        }

        when (buffer.offer(forwarded, peer.id)) {
            RelayBuffer.Admission.PEER_QUOTA_EXCEEDED -> stats.quotaDropped++
            RelayBuffer.Admission.EXPIRED -> stats.expiredDropped++
            else -> Unit
        }
        flush()
    }

    // ---- forwarding --------------------------------------------------------

    /**
     * Attempts to forward everything currently buffered.
     *
     * A packet with no available neighbour stays buffered rather than being
     * dropped: the carrier may simply be walking toward one. It is released by
     * expiry, not by a failed send, which is what makes the mesh tolerate mobility.
     */
    fun flush() {
        if (flushing) {
            flushRequested = true
            return
        }
        flushing = true
        try {
            var passes = 0
            do {
                flushRequested = false
                flushInternal()
                passes++
                // Bound the drain so a pathological topology cannot livelock the
                // caller. Anything left over stays buffered for the next flush or
                // tick; nothing is dropped.
            } while (flushRequested && passes < MAX_FLUSH_PASSES)
        } finally {
            flushing = false
        }
    }

    private fun flushInternal() {
        stats.expiredDropped += buffer.purgeExpired()

        for (entry in buffer.pendingEntries()) {
            val ranked = peers.rankedPeers(excluding = entry.sourcePeerId)
            // Under the default policy a broadcast goes to every neighbour: capping
            // it means some node in a dense mesh is structurally unreachable, which
            // is not what broadcast means. The storm is bounded by duplicate
            // suppression -- each node forwards a given packet at most once -- not
            // by narrowing the fanout.
            val policy = if (entry.packet.header.broadcast) broadcastPolicy else unicastPolicy
            val targets = ForwardingPolicy.select(policy, ranked, peers.linkConditions(ranked), random)
            if (targets.isEmpty()) continue

            val encoded = entry.packet.encode()
            var anyDelivered = false
            for (target in targets) {
                val ok = transport.send(target.handle, encoded)
                peers.recordForwardResult(target.handle.id, ok)
                if (ok) anyDelivered = true
            }
            if (anyDelivered) {
                buffer.remove(entry.packet.packetId)
                stats.forwarded++
            }
        }
    }

    /** Housekeeping: drops expired packets and unreachable neighbours. Safe to call on a timer. */
    fun tick() {
        stats.expiredDropped += buffer.purgeExpired()
        peers.purgeStale()
        flush()
    }

    private companion object {
        const val DEFAULT_FANOUT = 3

        /** Iterative drain limit for one flush call. */
        const val MAX_FLUSH_PASSES = 64
    }
}
