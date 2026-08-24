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

    /**
     * Replay protection for the message channel only.
     *
     * File transfer does not use it -- see [openChannel]. A window is the right
     * tool for a conversation, where messages are few and roughly ordered, and the
     * wrong one for a burst of a quarter of a million chunks that the mesh will
     * reorder arbitrarily.
     */
    private val replayWindow = ReplayWindow()

    /** Per-channel send counters, so no (channel, counter) pair is ever reused. */
    private val sendCounters = HashMap<Int, Long>()

    /**
     * Non-message channels currently accepting traffic.
     *
     * A channel must be opened before its frames will decrypt, and closed when the
     * transfer ends. That is what stops a captured chunk being replayed into the
     * session after the transfer it belonged to is over: the channel is gone, so
     * the frame is refused before any key is used.
     */
    private val openChannels = HashSet<Int>()

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
     * Frame layout: `channel (4) || counter (8) || ciphertext || tag`. Both header
     * fields are cleartext because the recipient needs them to derive the nonce
     * before it can decrypt anything -- and both are bound into the AEAD's
     * associated data, so an attacker who edits either causes an authentication
     * failure rather than a decryption against the wrong nonce.
     *
     * Each channel has its own counter space, and the nonce is `channel || counter`,
     * so distinct channels can never collide on a nonce.
     */
    fun seal(plaintext: ByteArray, nowMillis: Long, channel: Int = MESSAGE_CHANNEL): ByteArray {
        check(!destroyed) { "session has been destroyed" }
        check(messagesSent < policy.maxMessages) { "session message limit reached; renegotiate" }

        val counter = sendCounters.getOrElse(channel) { 0L }
        sendCounters[channel] = counter + 1
        val nonce = nonceFor(channel, counter)
        val aad = associatedData(channel, counter)

        val ciphertext = sendKey.use { key -> crypto.aeadSeal(key, nonce, aad, plaintext) }
        messagesSent++
        lastUsedMillis = nowMillis

        return ByteWriter(FRAME_HEADER_SIZE + ciphertext.size)
            .u32(channel.toLong() and 0xFFFFFFFFL)
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .bytes(ciphertext)
            .finish()
    }

    /**
     * Opens a non-message channel for inbound traffic.
     *
     * Replay protection on such a channel is **delegated to the layer above** --
     * for file transfer, the receiver's per-chunk bitmap, which knows the transfer
     * geometry and can tell chunk #800 from a replay without guessing from
     * arrival order. Bounded so an attacker cannot open channels without limit.
     */
    fun openChannel(channel: Int): Boolean {
        require(channel != MESSAGE_CHANNEL) { "channel 0 is the message channel and is always open" }
        if (destroyed) return false
        if (openChannels.size >= MAX_OPEN_CHANNELS) return false
        return openChannels.add(channel)
    }

    /** Closes a channel. Frames for it are refused afterwards, before any key is used. */
    fun closeChannel(channel: Int) {
        openChannels.remove(channel)
        sendCounters.remove(channel)
    }

    fun isChannelOpen(channel: Int): Boolean = channel == MESSAGE_CHANNEL || channel in openChannels

    /**
     * Decrypts a frame received from the mesh.
     *
     * Returns null for anything that is not a valid, non-replayed message from
     * this peer. On an open mesh, frames that fail here are ordinary traffic --
     * other people's packets, forgeries, replays -- not exceptional conditions.
     */
    fun open(frame: ByteArray, nowMillis: Long): ByteArray? {
        if (destroyed) return null
        if (frame.size < FRAME_HEADER_SIZE + CryptoProvider.AEAD_TAG_SIZE) return null

        val reader = ByteReader(frame)
        val channel = reader.u32().toInt()
        val counter = (reader.u32() shl 32) or reader.u32()
        val ciphertext = reader.bytes(reader.remaining)

        if (counter < 0) return null
        // Refuse a closed channel before touching a key: a chunk captured from a
        // finished transfer must not decrypt just because the session is still up.
        if (!isChannelOpen(channel)) return null

        val plaintext = receiveKey.use { key ->
            crypto.aeadOpen(key, nonceFor(channel, counter), associatedData(channel, counter), ciphertext)
        } ?: return null

        // The message channel keeps window-based replay protection. Other channels
        // delegate it upward, where the transfer geometry is known -- a window
        // cannot distinguish legitimate reordering from replay at burst scale.
        // Only advance the window once the message is proven authentic; otherwise
        // anyone could burn counter slots by sending forged frames.
        if (channel == MESSAGE_CHANNEL && !replayWindow.accept(counter)) return null

        messagesReceived++
        lastUsedMillis = nowMillis
        return plaintext
    }

    /** The channel a frame is addressed to, without decrypting it. */
    fun channelOf(frame: ByteArray): Int? {
        if (frame.size < FRAME_HEADER_SIZE) return null
        return try { ByteReader(frame).u32().toInt() } catch (_: IllegalArgumentException) { null }
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
        openChannels.clear()
        sendCounters.clear()
        destroyed = true
    }

    /** Approximate retained bytes, for budget accounting. */
    fun estimatedBytes(): Long = ESTIMATED_BYTES

    /** `channel (4) || counter (8)`. Distinct channels therefore never share a nonce. */
    private fun nonceFor(channel: Int, counter: Long): ByteArray =
        ByteWriter(CryptoProvider.AEAD_NONCE_SIZE)
            .u32(channel.toLong() and 0xFFFFFFFFL)
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .finish()

    private fun associatedData(channel: Int, counter: Long): ByteArray =
        ByteWriter(AAD_CONTEXT.size + FRAME_HEADER_SIZE)
            .bytes(AAD_CONTEXT)
            .u32(channel.toLong() and 0xFFFFFFFFL)
            .u32(counter ushr 32)
            .u32(counter and 0xFFFFFFFFL)
            .finish()

    companion object {
        /** Ordinary messages. Window-based replay protection applies here and only here. */
        const val MESSAGE_CHANNEL = 0

        /** `channel (4) || counter (8)` */
        const val FRAME_HEADER_SIZE = 4 + 8

        /** Bounds the channel table against an attacker opening transfers endlessly. */
        const val MAX_OPEN_CHANNELS = 16

        /** Two 32-byte keys, a session id, counters, the 1024-bit replay window, and overhead. */
        const val ESTIMATED_BYTES = 512L

        private val AAD_CONTEXT = "insnaps-msg-v2".encodeToByteArray()
    }
}
