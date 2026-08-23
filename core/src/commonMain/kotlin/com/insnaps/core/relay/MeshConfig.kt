package com.insnaps.core.relay

import com.insnaps.core.packet.Packet

/**
 * Resource and policy limits for the relay subsystem.
 *
 * The 25 MB figure is a *budget for the communication subsystem*, enforced here
 * as an explicit byte accounting rather than left as an aspiration. It is split
 * across the three structures that grow with traffic; the remainder is headroom
 * for transport buffers and per-connection state owned by the platform layer.
 *
 * Note that this is a design target expressed in configuration, not a protocol
 * constant: a peer running with a different budget still interoperates, because
 * nothing about the budget appears on the wire. Only the *eviction behaviour* it
 * produces is observable, and that is defined in [RelayBuffer].
 */
data class MeshConfig(
    val totalBudgetBytes: Long = 25L * 1024 * 1024,
    val relayBufferBytes: Long = 16L * 1024 * 1024,
    val duplicateCacheEntries: Int = 20_000,
    val peerTableEntries: Int = 512,

    /**
     * Share of the relay buffer any single neighbour may occupy.
     *
     * This is the DoS bound. Without it, one peer flooding traffic evicts every
     * other peer's packets and silently partitions the mesh around itself.
     */
    val perPeerQuotaFraction: Double = 0.10,

    /** Hop limit stamped on locally originated packets. */
    val defaultTtl: Int = 24,

    /** Lifetime stamped on locally originated packets. */
    val defaultLifetimeSeconds: Int = 300,

    /** How long a packet id is remembered for duplicate suppression. */
    val duplicateRetentionSeconds: Int = 600,
) {
    val perPeerQuotaBytes: Long = (relayBufferBytes * perPeerQuotaFraction).toLong()

    /**
     * Worst-case bytes the relay subsystem can retain, with every bounded
     * structure simultaneously full.
     *
     * This is the number the 25 MB claim actually rests on: not a measurement of
     * a typical run, but a ceiling that follows from the bounds themselves.
     * Session key material is accounted separately by `SessionManager`.
     */
    fun worstCaseRelayBytes(): Long =
        relayBufferBytes +
            duplicateCacheEntries.toLong() * DUPLICATE_ENTRY_BYTES +
            peerTableEntries.toLong() * PEER_ENTRY_BYTES

    init {
        require(relayBufferBytes in 1..totalBudgetBytes) {
            "relay buffer must be positive and fit inside the total budget"
        }
        require(perPeerQuotaFraction > 0.0 && perPeerQuotaFraction <= 1.0) {
            "perPeerQuotaFraction must be in (0.0, 1.0]"
        }
        require(perPeerQuotaBytes >= Packet.MAX_PACKET_SIZE) {
            "per-peer quota must admit at least one maximum-size packet"
        }
        require(defaultTtl in 1..Packet.MAX_TTL) { "defaultTtl out of range" }
        require(defaultLifetimeSeconds in 1..Packet.MAX_LIFETIME_SECONDS) {
            "defaultLifetimeSeconds out of range"
        }
        // A configuration whose own bounds exceed its budget is a misconfiguration,
        // and one that would only be discovered under load. Fail at construction.
        require(worstCaseRelayBytes() <= totalBudgetBytes) {
            "worst-case relay footprint ${worstCaseRelayBytes()} exceeds the budget $totalBudgetBytes"
        }
    }

    companion object {
        /** Must match DuplicateCache's per-entry estimate. */
        const val DUPLICATE_ENTRY_BYTES = 64L

        /** Must match PeerTable's per-entry estimate. */
        const val PEER_ENTRY_BYTES = 128L
    }
}
