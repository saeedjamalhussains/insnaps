package com.insnaps.core.session

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.util.Clock

/**
 * The application-facing node: plaintext in, plaintext out, ciphertext on the mesh.
 *
 * This is where the two layers meet, and the meeting is deliberately one-way.
 * [MeshEngine] is constructed with this object as its listener and receives only
 * sealed frames; it has no reference to [SessionManager], no access to a key, and
 * no code path that could obtain one. Encryption happens strictly above it and
 * decryption strictly above it, so a relaying node -- which runs this same class
 * with no session for the traffic passing through -- physically cannot produce
 * plaintext for packets that are not its own.
 *
 * ## Envelope
 *
 * Every mesh payload carries a one-byte type so the receiver knows what it holds
 * before trying any key:
 *
 * ```
 *   [type: 1][body: n]
 *      0x01  handshake message 1   (Noise IK: e, es, s, ss)
 *      0x02  handshake message 2   (Noise IK: e, ee, se)
 *      0x03  sealed message        (counter || ciphertext || tag)
 * ```
 *
 * The type byte is cleartext and visible to relays. It reveals that a handshake
 * is occurring, not who is party to it.
 */
class SecureMesh(
    private val sessions: SessionManager,
    private val clock: Clock,
    private val listener: Listener,
) : MeshEngine.MeshListener {

    interface Listener {
        /** A decrypted message from an authenticated peer. */
        fun onMessage(from: PeerIdentity, plaintext: ByteArray)

        /** A session was established, by either side. */
        fun onSessionEstablished(peer: PeerIdentity)

        /**
         * A broadcast arrived. Broadcasts are not encrypted to any recipient and
         * are therefore readable by every node -- they carry no confidentiality
         * and the caller MUST NOT treat them as private.
         */
        fun onBroadcast(plaintext: ByteArray) {}
    }

    /** Set once, immediately after construction; the two objects are mutually referential. */
    var engine: MeshEngine? = null

    /**
     * The outcome of an attempt to queue a message.
     *
     * A sealed result rather than a nullable packet id: "no session yet" and
     * "message too big for one packet" are different problems needing different
     * responses from the caller, and neither is a programming error worth
     * throwing over -- both are ordinary runtime conditions driven by user input.
     */
    sealed interface SendOutcome {
        data class Queued(val packetId: PacketId) : SendOutcome
        data object NoSession : SendOutcome
        data class TooLarge(val actualBytes: Int, val maxBytes: Int) : SendOutcome
    }

    /** Counters for diagnostics. Carries no key material and no plaintext. */
    data class Stats(
        var handshakesInitiated: Long = 0,
        var handshakesCompleted: Long = 0,
        var handshakesRejected: Long = 0,
        var messagesDecrypted: Long = 0,
        var undecryptable: Long = 0,
        var malformedEnvelopes: Long = 0,
    )

    val stats = Stats()

    // ---- outbound ----------------------------------------------------------

    /** Begins a handshake with [peer], whose static public key must already be known. */
    fun connect(peer: PeerIdentity): PacketId {
        val message = sessions.beginHandshake(peer)
        stats.handshakesInitiated++
        return requireEngine().sendHandshake(peer, envelope(TYPE_HANDSHAKE_1, message))
    }

    /**
     * Encrypts and sends [plaintext] to [peer].
     *
     * Returns [SendOutcome.NoSession] if no session exists; the caller should
     * [connect] first. This is deliberately not automatic: silently establishing a
     * session on send would hide from the caller that the first message is delayed
     * by a round trip.
     *
     * insnaps has no fragmentation, so a message larger than [MAX_PLAINTEXT_SIZE]
     * cannot be sent at all and is reported rather than thrown -- message length
     * is user input, and user input must not be able to crash the node.
     */
    fun send(peer: PeerIdentity, plaintext: ByteArray): SendOutcome {
        if (plaintext.size > MAX_PLAINTEXT_SIZE) {
            return SendOutcome.TooLarge(plaintext.size, MAX_PLAINTEXT_SIZE)
        }
        val session = sessions.sessionFor(peer) ?: return SendOutcome.NoSession
        val sealed = session.seal(plaintext, clock.nowMillis())
        return SendOutcome.Queued(requireEngine().send(peer, envelope(TYPE_MESSAGE, sealed)))
    }

    /**
     * Sends an unencrypted broadcast readable by every node in range.
     *
     * There is no recipient to encrypt to, so this carries no confidentiality.
     * It exists for discovery and public announcements only.
     */
    fun broadcast(plaintext: ByteArray): SendOutcome {
        if (plaintext.size > MAX_BROADCAST_SIZE) {
            return SendOutcome.TooLarge(plaintext.size, MAX_BROADCAST_SIZE)
        }
        return SendOutcome.Queued(requireEngine().broadcast(envelope(TYPE_MESSAGE, plaintext)))
    }

    // ---- inbound -----------------------------------------------------------

    override fun onMessageDelivered(ciphertext: ByteArray, broadcast: Boolean) {
        if (ciphertext.isEmpty()) {
            stats.malformedEnvelopes++
            return
        }
        val type = ciphertext[0].toInt() and 0xFF
        val body = ciphertext.copyOfRange(1, ciphertext.size)

        when {
            broadcast && type == TYPE_MESSAGE -> listener.onBroadcast(body)
            type == TYPE_HANDSHAKE_1 -> handleHandshake1(body)
            type == TYPE_HANDSHAKE_2 -> handleHandshake2(body)
            type == TYPE_MESSAGE -> handleMessage(body)
            else -> stats.malformedEnvelopes++
        }
    }

    private fun handleHandshake1(body: ByteArray) {
        val (reply, session) = try {
            sessions.acceptHandshake(body)
        } catch (_: HandshakeFailure) {
            // Expected on an open mesh: this handshake was addressed to someone else.
            stats.handshakesRejected++
            return
        }
        stats.handshakesCompleted++
        requireEngine().sendHandshake(session.peer, envelope(TYPE_HANDSHAKE_2, reply))
        listener.onSessionEstablished(session.peer)
    }

    private fun handleHandshake2(body: ByteArray) {
        val session = sessions.completeHandshake(body)
        if (session == null) {
            stats.handshakesRejected++
            return
        }
        stats.handshakesCompleted++
        listener.onSessionEstablished(session.peer)
    }

    /**
     * Opens a sealed message.
     *
     * A recipient tag is only a hint -- tags rotate and can collide -- so the real
     * test of who a message is for is whether a session key opens it. Every live
     * session is tried, and failure is silent and routine.
     */
    private fun handleMessage(body: ByteArray) {
        val now = clock.nowMillis()
        for (session in sessions.activeSessions()) {
            val plaintext = session.open(body, now)
            if (plaintext != null) {
                stats.messagesDecrypted++
                listener.onMessage(session.peer, plaintext)
                return
            }
        }
        stats.undecryptable++
    }

    private fun envelope(type: Int, body: ByteArray): ByteArray {
        val out = ByteArray(body.size + 1)
        out[0] = type.toByte()
        body.copyInto(out, 1)
        return out
    }

    private fun requireEngine(): MeshEngine =
        engine ?: throw IllegalStateException("SecureMesh.engine must be set before use")

    companion object {
        private const val TYPE_HANDSHAKE_1 = 0x01
        private const val TYPE_HANDSHAKE_2 = 0x02
        private const val TYPE_MESSAGE = 0x03

        /** Envelope type byte. */
        private const val ENVELOPE_OVERHEAD = 1

        /** Sealed frame overhead: the cleartext counter plus the AEAD tag. */
        private const val SEAL_OVERHEAD = 8 + 16

        /** Largest encryptable message that fits one packet. There is no fragmentation. */
        const val MAX_PLAINTEXT_SIZE = Packet.MAX_PAYLOAD_SIZE - ENVELOPE_OVERHEAD - SEAL_OVERHEAD

        /** Largest broadcast body. Broadcasts are unencrypted, so they carry no seal overhead. */
        const val MAX_BROADCAST_SIZE = Packet.MAX_PAYLOAD_SIZE - ENVELOPE_OVERHEAD
    }
}
