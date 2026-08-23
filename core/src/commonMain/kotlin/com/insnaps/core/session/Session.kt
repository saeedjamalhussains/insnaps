package com.insnaps.core.session

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter

/** When a session must be discarded and renegotiated. */
data class SessionPolicy(
    /** Wall-clock lifetime, regardless of use. Bounds the value of a compromised key. */
    val maxAgeMillis: Long = 60 * 60 * 1000L,
    /** Idle timeout. A session nobody is using should not sit in memory holding keys. */
    val maxIdleMillis: Long = 15 * 60 * 1000L,
    /** Hard cap on messages sent, well below nonce exhaustion. */
    val maxMessages: Long = 1L shl 20,
)

/**
 * An established, authenticated, one-to-one encrypted session.
 *
 * Holds directional keys, a send counter, and a replay window. Everything here is
 * RAM-only and is destroyed by [destroy]; nothing in this class touches storage.
 *
 * The mesh layer never sees any of it. [seal] produces the opaque bytes the mesh
 * carries, and [open] consumes them.
 */
class Session(
    val peer: PeerIdentity,
    val sessionId: ByteArray,
    sendKey: ByteArray,
    receiveKey: ByteArray,
    private val crypto: CryptoProvider,
    private val createdAtMillis: Long,
    private val policy: SessionPolicy = SessionPolicy(),
) {
    private val sendKey = SecretBytes(sendKey)
    private val receiveKey = SecretBytes(receiveKey)
    private val replayWindow = ReplayWindow()

    private var sendCounter: Long = 0
    private var lastUsedMillis: Long = createdAtMillis

    var destroyed: Boolean = false
        private set

    var messagesSent: Long = 0
        private set
    var messagesReceived: Long = 0
        private set

    /**
     * Encrypts [plaintext] into the frame the mesh will carry as an opaque payload.
     *
     * Frame layout: `counter (8 bytes) || ciphertext || tag`. The counter is
     * cleartext because the recipient needs it to derive the nonce before it can
     * decrypt anything -- and it is bound into the AEAD's associated data, so an
     * attacker who edits it in flight causes an authentication failure rather than
     * a decryption against the wrong nonce.
     */
    fun seal(plaintext: ByteArray, nowMillis: Long): ByteArray {
        check(!destroyed) { "session has been destroyed" }
        check(messagesSent < policy.maxMessages) { "session message limit reached; renegotiate" }

        val counter = sendCounter++
        val nonce = nonceFor(counter)
        val aad = associatedData(counter)

        val ciphertext = sendKey.use { key -> crypto.aeadSeal(key, nonce, aad, plaintext) }
        messagesSent++
        lastUsedMillis = nowMillis

        return ByteWriter(COUNTER_SIZE + ciphertext.size)
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .bytes(ciphertext)
            .finish()
    }

    /**
     * Decrypts a frame received from the mesh.
     *
     * Returns null for anything that is not a valid, non-replayed message from
     * this peer. On an open mesh, frames that fail here are ordinary traffic --
     * other people's packets, forgeries, replays -- not exceptional conditions.
     */
    fun open(frame: ByteArray, nowMillis: Long): ByteArray? {
        if (destroyed) return null
        if (frame.size < COUNTER_SIZE + CryptoProvider.AEAD_TAG_SIZE) return null

        val reader = ByteReader(frame)
        val counter = (reader.u32() shl 32) or reader.u32()
        val ciphertext = reader.bytes(reader.remaining)

        // Check the window before spending a decryption on a known replay.
        if (counter < 0) return null

        val plaintext = receiveKey.use { key ->
            crypto.aeadOpen(key, nonceFor(counter), associatedData(counter), ciphertext)
        } ?: return null

        // Only advance the window once the message is proven authentic; otherwise
        // anyone could burn counter slots by sending forged frames.
        if (!replayWindow.accept(counter)) return null

        messagesReceived++
        lastUsedMillis = nowMillis
        return plaintext
    }

    fun isExpired(nowMillis: Long): Boolean =
        destroyed ||
            nowMillis - createdAtMillis >= policy.maxAgeMillis ||
            nowMillis - lastUsedMillis >= policy.maxIdleMillis ||
            messagesSent >= policy.maxMessages

    /** Zeroes both directional keys and makes the session unusable. Idempotent. */
    fun destroy() {
        if (destroyed) return
        sendKey.destroy()
        receiveKey.destroy()
        replayWindow.reset()
        destroyed = true
    }

    /** Approximate retained bytes, for budget accounting. */
    fun estimatedBytes(): Long = ESTIMATED_BYTES

    private fun nonceFor(counter: Long): ByteArray =
        ByteWriter(CryptoProvider.AEAD_NONCE_SIZE)
            .u32(0) // 4 zero bytes, then the 8-byte counter
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .finish()

    private fun associatedData(counter: Long): ByteArray =
        ByteWriter(AAD_CONTEXT.size + COUNTER_SIZE)
            .bytes(AAD_CONTEXT)
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .finish()

    private companion object {
        const val COUNTER_SIZE = 8

        /** Two 32-byte keys, a session id, counters and window, plus object overhead. */
        const val ESTIMATED_BYTES = 256L

        val AAD_CONTEXT = "insnaps-msg-v1".encodeToByteArray()
    }
}
