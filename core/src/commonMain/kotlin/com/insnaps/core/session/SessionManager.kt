package com.insnaps.core.session

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.SharedSecretProvider
import com.insnaps.core.crypto.X25519KeyPair
import com.insnaps.core.util.Clock

/**
 * Owns every live session, and every byte of key material in the process.
 *
 * ## Memory ownership
 *
 * This class is the sole owner of [Session] objects. Nothing else may retain one,
 * because nothing else can know when it expires. Sessions leave only through
 * [purgeExpired] or [destroyAll], and both destroy their keys on the way out.
 *
 * It is also bounded: [maxSessions] caps how many can exist, so an attacker
 * cannot grow memory without limit by initiating handshakes. When full, the
 * least recently established session is evicted.
 *
 * It doubles as the [SharedSecretProvider] for mesh addressing, which is what
 * ties the two layers together: a recipient tag is derivable exactly when a
 * session exists.
 */
class SessionManager(
    private val crypto: CryptoProvider,
    private val clock: Clock,
    private val staticKeys: X25519KeyPair,
    private val policy: SessionPolicy = SessionPolicy(),
    private val maxSessions: Int = DEFAULT_MAX_SESSIONS,
    private val maxPendingHandshakes: Int = DEFAULT_MAX_PENDING,
) : SharedSecretProvider {

    private val sessions = LinkedHashMap<PeerIdentity, Session>()
    private val pending = LinkedHashMap<PeerIdentity, HandshakeInitiator>()

    val identity: PeerIdentity get() = PeerIdentity(staticKeys.publicKey)
    val sessionCount: Int get() = sessions.size
    val pendingCount: Int get() = pending.size

    // ---- handshake ---------------------------------------------------------

    /**
     * Starts a handshake with [peer], returning the message to put on the mesh.
     *
     * Throws [HandshakeFailure] if [peer]'s public key is unusable -- a contact
     * record can be corrupt or attacker-supplied just as a network message can.
     */
    fun beginHandshake(peer: PeerIdentity): ByteArray {
        if (pending.size >= maxPendingHandshakes) {
            pending.keys.firstOrNull()?.let { pending.remove(it) }
        }
        val initiator = HandshakeInitiator(crypto, staticKeys, peer.publicKey)
        pending[peer] = initiator
        return initiator.writeMessage1()
    }

    /**
     * Handles an inbound handshake message 1, returning the reply and the session.
     *
     * Throws [HandshakeFailure] for anything malformed or unauthenticated. On an
     * open mesh most inbound handshake bytes are other people's traffic, so the
     * caller should treat a failure as routine and drop it.
     */
    fun acceptHandshake(message: ByteArray): Pair<ByteArray, Session> {
        val responder = HandshakeResponder(crypto, staticKeys)
        responder.readMessage1(message)
        val (reply, result) = responder.writeMessage2()
        return reply to store(result)
    }

    /**
     * Handles an inbound handshake message 2 against our pending attempts.
     *
     * The message carries no cleartext identity -- that is the point of IK -- so
     * each pending handshake is tried. [maxPendingHandshakes] bounds that work.
     */
    fun completeHandshake(message: ByteArray): Session? {
        for ((peer, initiator) in pending.entries.toList()) {
            val result = try {
                initiator.readMessage2(message)
            } catch (_: HandshakeFailure) {
                continue
            } catch (_: IllegalStateException) {
                continue
            }
            pending.remove(peer)
            return store(result)
        }
        return null
    }

    private fun store(result: HandshakeResult): Session {
        sessions.remove(result.peer)?.destroy()
        if (sessions.size >= maxSessions) evictOldest()

        val session = Session(
            peer = result.peer,
            sessionId = result.sessionId,
            sendKey = result.sendKey,
            receiveKey = result.receiveKey,
            crypto = crypto,
            createdAtMillis = clock.nowMillis(),
            policy = policy,
        )
        sessions[result.peer] = session
        return session
    }

    // ---- lookup and lifecycle ---------------------------------------------

    /** The live session with [peer], or null if there is none or it has expired. */
    fun sessionFor(peer: PeerIdentity): Session? {
        val session = sessions[peer] ?: return null
        if (session.isExpired(clock.nowMillis())) {
            sessions.remove(peer)
            session.destroy()
            return null
        }
        return session
    }

    fun activeSessions(): List<Session> {
        purgeExpired()
        return sessions.values.toList()
    }

    /** Destroys every expired session. Safe to call on a timer. */
    fun purgeExpired(): Int {
        val now = clock.nowMillis()
        val expired = sessions.entries.filter { it.value.isExpired(now) }
        for (entry in expired) {
            sessions.remove(entry.key)
            entry.value.destroy()
        }
        return expired.size
    }

    /**
     * Destroys all key material.
     *
     * Called on shutdown. After this the process holds no session keys, which is
     * the strongest statement the RAM-only design can make at the application level.
     */
    fun destroyAll() {
        sessions.values.forEach { it.destroy() }
        sessions.clear()
        pending.clear()
    }

    /** Approximate retained bytes, for budget accounting. */
    fun estimatedBytes(): Long =
        sessions.values.sumOf { it.estimatedBytes() } +
            pending.size.toLong() * PENDING_HANDSHAKE_BYTES

    // ---- addressing --------------------------------------------------------

    /**
     * Tag-derivation secret for [peer].
     *
     * Derived from the session id rather than being a session key: a tag is
     * visible to every relay, so the value it is computed from must not be one
     * that also protects message content.
     */
    override fun secretFor(peer: PeerIdentity): ByteArray? {
        val session = sessionFor(peer) ?: return null
        return crypto.hkdf(session.sessionId, ByteArray(0), TAG_SECRET_INFO, 32)
    }

    override fun knownPeers(): List<PeerIdentity> = sessions.keys.toList()

    private fun evictOldest() {
        val oldest = sessions.keys.firstOrNull() ?: return
        sessions.remove(oldest)?.destroy()
    }

    companion object {
        const val DEFAULT_MAX_SESSIONS = 256
        const val DEFAULT_MAX_PENDING = 32

        /** Ephemeral keypair, symmetric state and object overhead. */
        private const val PENDING_HANDSHAKE_BYTES = 512L

        private val TAG_SECRET_INFO = "insnaps-tag-secret-v1".encodeToByteArray()
    }
}
