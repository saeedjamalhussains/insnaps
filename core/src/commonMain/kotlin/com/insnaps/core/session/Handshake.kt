package com.insnaps.core.session

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.X25519KeyPair

/**
 * Noise IK handshake over X25519.
 *
 * IK is the right pattern here: the initiator already **k**nows the responder's
 * static key (it is what a contact *is* in insnaps), and transmits its own static
 * key **e**ncrypted, so a relay watching the handshake does not learn who is
 * initiating. It completes in one round trip, which matters on a link where a
 * round trip can cost seconds.
 *
 * ```
 *   <- s                                (responder static, known in advance)
 *   ...
 *   -> e, es, s, ss                     msg1
 *   <- e, ee, se                        msg2
 * ```
 *
 * ## Status: implemented here, not borrowed
 *
 * The primitives are all platform-supplied ([CryptoProvider]) -- nothing
 * cryptographic is invented -- but the *pattern composition* below is written by
 * hand rather than taken from a vetted Noise implementation. That is the single
 * highest-risk piece of code in insnaps.
 *
 * It is structured to be replaceable: everything outside this file depends only
 * on [HandshakeResult], so dropping in an audited Noise library changes nothing
 * else. **This implementation MUST be replaced or independently audited before
 * any production use.**
 *
 * Note on nonces: every `encryptAndHash` below is preceded by a `mixKey`, so each
 * AEAD key encrypts exactly once during a handshake and the all-zero nonce is
 * safe. Adding a message without a preceding `mixKey` would break that and MUST
 * NOT be done without introducing a handshake nonce counter.
 */
private class SymmetricState(private val crypto: CryptoProvider) {

    private var chainingKey: ByteArray = crypto.sha256(PROTOCOL_NAME)
    private var handshakeHash: ByteArray = chainingKey.copyOf()
    private var key: ByteArray? = null

    val hash: ByteArray get() = handshakeHash

    fun mixHash(data: ByteArray) {
        handshakeHash = crypto.sha256(handshakeHash + data)
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val output = crypto.hkdf(
            inputKeyMaterial = inputKeyMaterial,
            salt = chainingKey,
            info = ByteArray(0),
            outputLength = 64,
        )
        chainingKey = output.copyOfRange(0, 32)
        key = output.copyOfRange(32, 64)
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val k = key ?: throw IllegalStateException("no handshake key established")
        val ciphertext = crypto.aeadSeal(k, ZERO_NONCE, handshakeHash, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
        val k = key ?: throw IllegalStateException("no handshake key established")
        // The hash must advance over the ciphertext regardless of the outcome, but a
        // failed open aborts the handshake anyway, so ordering here is not observable.
        val plaintext = crypto.aeadOpen(k, ZERO_NONCE, handshakeHash, ciphertext) ?: return null
        mixHash(ciphertext)
        return plaintext
    }

    /** Final key split. The initiator sends under the first key, the responder under the second. */
    fun split(): Pair<ByteArray, ByteArray> {
        val output = crypto.hkdf(ByteArray(0), chainingKey, ByteArray(0), 64)
        return output.copyOfRange(0, 32) to output.copyOfRange(32, 64)
    }

    private companion object {
        val PROTOCOL_NAME = "Noise_IK_25519_AESGCM_SHA256".encodeToByteArray()
        val ZERO_NONCE = ByteArray(CryptoProvider.AEAD_NONCE_SIZE)
    }
}

/**
 * Diffie-Hellman against a key supplied by a peer.
 *
 * [CryptoProvider.x25519] rejects invalid contributions -- small-order points in
 * particular -- by throwing [IllegalArgumentException]. During a handshake those
 * bytes arrive from the network, so an uncaught throw here is a remote crash: any
 * peer could kill a node by sending 96 zero bytes. Every DH over peer-supplied
 * material goes through this function so the failure becomes an ordinary rejected
 * handshake instead.
 */
private fun CryptoProvider.guardedDh(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray =
    try {
        x25519(privateKey, peerPublicKey)
    } catch (e: IllegalArgumentException) {
        throw HandshakeFailure("peer supplied an unusable X25519 key: ${e.message}")
    }

/** Directional keys produced by a completed handshake. */
class HandshakeResult(
    val peer: PeerIdentity,
    val sendKey: ByteArray,
    val receiveKey: ByteArray,
    /** Final handshake hash: a unique session identifier, safe to compare or display. */
    val sessionId: ByteArray,
)

class HandshakeFailure(message: String) : Exception(message)

/**
 * Initiator half of the handshake. Single use: one instance per attempt.
 */
class HandshakeInitiator(
    private val crypto: CryptoProvider,
    private val staticKeys: X25519KeyPair,
    private val remoteStatic: ByteArray,
) {
    private val state = SymmetricState(crypto)
    private val ephemeral: X25519KeyPair = crypto.generateX25519KeyPair()
    private var wrote = false

    init {
        require(remoteStatic.size == CryptoProvider.X25519_KEY_SIZE) { "remote static key must be 32 bytes" }
        state.mixHash(remoteStatic) // pre-message: the responder's static key
    }

    /** Produces `e, es, s, ss`. */
    fun writeMessage1(payload: ByteArray = ByteArray(0)): ByteArray {
        check(!wrote) { "handshake initiator is single use" }
        wrote = true

        state.mixHash(ephemeral.publicKey)
        state.mixKey(crypto.guardedDh(ephemeral.privateKey, remoteStatic))
        val encryptedStatic = state.encryptAndHash(staticKeys.publicKey)
        state.mixKey(crypto.guardedDh(staticKeys.privateKey, remoteStatic))
        val encryptedPayload = state.encryptAndHash(payload)

        return ephemeral.publicKey + encryptedStatic + encryptedPayload
    }

    /** Consumes `e, ee, se` and completes the session. */
    fun readMessage2(message: ByteArray): HandshakeResult {
        check(wrote) { "message 1 must be written first" }
        if (message.size < CryptoProvider.X25519_KEY_SIZE + CryptoProvider.AEAD_TAG_SIZE) {
            throw HandshakeFailure("handshake message 2 is too short")
        }

        val remoteEphemeral = message.copyOfRange(0, CryptoProvider.X25519_KEY_SIZE)
        val encryptedPayload = message.copyOfRange(CryptoProvider.X25519_KEY_SIZE, message.size)

        state.mixHash(remoteEphemeral)
        state.mixKey(crypto.guardedDh(ephemeral.privateKey, remoteEphemeral))
        state.mixKey(crypto.guardedDh(staticKeys.privateKey, remoteEphemeral))
        state.decryptAndHash(encryptedPayload) ?: throw HandshakeFailure("handshake message 2 failed authentication")

        val (initiatorSends, responderSends) = state.split()
        return HandshakeResult(
            peer = PeerIdentity(remoteStatic),
            sendKey = initiatorSends,
            receiveKey = responderSends,
            sessionId = state.hash,
        )
    }
}

/**
 * Responder half of the handshake. Single use: one instance per attempt.
 */
class HandshakeResponder(
    private val crypto: CryptoProvider,
    private val staticKeys: X25519KeyPair,
) {
    private val state = SymmetricState(crypto)
    private val ephemeral: X25519KeyPair = crypto.generateX25519KeyPair()
    private var remoteStatic: ByteArray? = null
    private var remoteEphemeral: ByteArray? = null

    init {
        state.mixHash(staticKeys.publicKey)
    }

    /**
     * Consumes `e, es, s, ss` and reveals who is initiating.
     *
     * Throws [HandshakeFailure] on anything malformed or unauthenticated: on an
     * open mesh this is expected traffic, and the caller should drop the attempt
     * without further work.
     */
    fun readMessage1(message: ByteArray): PeerIdentity {
        check(remoteStatic == null) { "handshake responder is single use" }

        val minimum = CryptoProvider.X25519_KEY_SIZE + // e
            CryptoProvider.X25519_KEY_SIZE + CryptoProvider.AEAD_TAG_SIZE + // encrypted s
            CryptoProvider.AEAD_TAG_SIZE // encrypted payload
        if (message.size < minimum) throw HandshakeFailure("handshake message 1 is too short")

        val staticEnd = CryptoProvider.X25519_KEY_SIZE * 2 + CryptoProvider.AEAD_TAG_SIZE
        val theirEphemeral = message.copyOfRange(0, CryptoProvider.X25519_KEY_SIZE)
        val encryptedStatic = message.copyOfRange(CryptoProvider.X25519_KEY_SIZE, staticEnd)
        val encryptedPayload = message.copyOfRange(staticEnd, message.size)

        state.mixHash(theirEphemeral)
        state.mixKey(crypto.guardedDh(staticKeys.privateKey, theirEphemeral))
        val theirStatic = state.decryptAndHash(encryptedStatic)
            ?: throw HandshakeFailure("handshake message 1 failed authentication")
        state.mixKey(crypto.guardedDh(staticKeys.privateKey, theirStatic))
        state.decryptAndHash(encryptedPayload)
            ?: throw HandshakeFailure("handshake message 1 payload failed authentication")

        remoteEphemeral = theirEphemeral
        remoteStatic = theirStatic
        return PeerIdentity(theirStatic)
    }

    /** Produces `e, ee, se` and completes the session. */
    fun writeMessage2(payload: ByteArray = ByteArray(0)): Pair<ByteArray, HandshakeResult> {
        val theirEphemeral = remoteEphemeral ?: throw IllegalStateException("message 1 must be read first")
        val theirStatic = remoteStatic ?: throw IllegalStateException("message 1 must be read first")

        state.mixHash(ephemeral.publicKey)
        state.mixKey(crypto.guardedDh(ephemeral.privateKey, theirEphemeral))
        state.mixKey(crypto.guardedDh(ephemeral.privateKey, theirStatic))
        val encryptedPayload = state.encryptAndHash(payload)

        val (initiatorSends, responderSends) = state.split()
        val result = HandshakeResult(
            peer = PeerIdentity(theirStatic),
            sendKey = responderSends,
            receiveKey = initiatorSends,
            sessionId = state.hash,
        )
        return (ephemeral.publicKey + encryptedPayload) to result
    }
}
