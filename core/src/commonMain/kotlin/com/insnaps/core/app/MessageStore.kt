package com.insnaps.core.app

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter
import com.insnaps.core.util.toHex

/**
 * Opaque byte storage supplied by the platform.
 *
 * Deliberately dumb: it stores and returns byte arrays and knows nothing about
 * messages. Everything handed to it is already sealed, so a platform
 * implementation backed by files, SQLite, or anything else never holds
 * plaintext, and a bug in it cannot leak message content.
 */
interface BlobStore {
    fun put(key: String, value: ByteArray)
    fun get(key: String): ByteArray?
    fun delete(key: String)
    fun keys(prefix: String): List<String>
    fun clear()
}

/**
 * Supplies the key that encrypts local history.
 *
 * MUST be backed by platform-protected storage -- Android Keystore, iOS Keychain
 * (Secure Enclave-backed where the device offers it). The key is generated once
 * per install and never leaves the device.
 *
 * Note this is a *different* key from the identity key in `IdentityStore`: reusing
 * one key for two purposes means a compromise of local storage also compromises
 * the identity, and rotating either becomes impossible without breaking the other.
 */
interface StorageKeyProvider {
    /** 32 bytes. Created on first use and persisted in platform-protected storage. */
    fun storageKey(): ByteArray
}

/** A message as an endpoint keeps it. Only ever exists at the sender or recipient. */
data class StoredMessage(
    val messageId: Long,
    val peer: PeerIdentity,
    val outgoing: Boolean,
    val timestampMillis: Long,
    val body: ByteArray,
    val read: Boolean = false,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (other is StoredMessage && messageId == other.messageId &&
            peer == other.peer && outgoing == other.outgoing &&
            timestampMillis == other.timestampMillis && body.contentEquals(other.body) &&
            read == other.read)

    override fun hashCode(): Int = (messageId.hashCode() * 31 + peer.hashCode()) * 31 + body.contentHashCode()

    /** Never renders the body. */
    override fun toString(): String =
        "StoredMessage(id=$messageId, outgoing=$outgoing, body=${body.size}B, read=$read)"
}

/**
 * Encrypted local history for Normal Mode conversations.
 *
 * ## What this guarantees
 *
 * Every record is sealed with AES-256-GCM under the platform-protected storage
 * key *before* it reaches [BlobStore], so what lands on disk is ciphertext. The
 * message id is bound in as associated data, so a record cannot be moved or
 * swapped between conversations without failing authentication.
 *
 * ## What it refuses
 *
 * [append] rejects private-mode messages outright. Private mode's guarantee is
 * that nothing is intentionally persisted, and the reliable way to keep that true
 * is to make the persistence path itself refuse -- not to rely on every caller
 * remembering to check the mode first.
 *
 * This is endpoint storage. A relay never constructs one of these, and the 25 MB
 * relay ceiling does not apply to it: it bounds relay/forwarding state, not a
 * user's own conversation history.
 */
class EncryptedMessageStore(
    private val blobs: BlobStore,
    private val keys: StorageKeyProvider,
    private val crypto: CryptoProvider,
) {

    /**
     * Persists a Normal Mode message.
     *
     * Throws [IllegalArgumentException] if [mode] is private -- a programming
     * error worth failing loudly on, because silently dropping it would look like
     * a storage bug and silently keeping it would break the mode's guarantee.
     */
    fun append(message: StoredMessage, mode: ConversationMode = ConversationMode.NORMAL) {
        require(mode == ConversationMode.NORMAL) {
            "private-mode messages are never persisted; this store refuses them by design"
        }
        blobs.put(keyFor(message.peer, message.messageId), seal(message))
    }

    /** Every retained message for [peer], oldest first. Records that fail to open are skipped. */
    fun history(peer: PeerIdentity): List<StoredMessage> =
        blobs.keys(prefixFor(peer))
            .mapNotNull { key ->
                val messageId = messageIdFromKey(key) ?: return@mapNotNull null
                blobs.get(key)?.let { open(it, peer, messageId) }
            }
            .sortedBy { it.timestampMillis }

    fun markRead(peer: PeerIdentity, messageId: Long): Boolean {
        val key = keyFor(peer, messageId)
        val existing = blobs.get(key)?.let { open(it, peer, messageId) } ?: return false
        blobs.put(key, seal(existing.copy(read = true)))
        return true
    }

    /** A single message, or null if it is absent or fails authentication. */
    fun get(peer: PeerIdentity, messageId: Long): StoredMessage? =
        blobs.get(keyFor(peer, messageId))?.let { open(it, peer, messageId) }

    fun delete(peer: PeerIdentity, messageId: Long) {
        blobs.delete(keyFor(peer, messageId))
    }

    /** Deletes an entire conversation. */
    fun deleteConversation(peer: PeerIdentity) {
        blobs.keys(prefixFor(peer)).forEach(blobs::delete)
    }

    /** Deletes all history on this device. */
    fun deleteAll() = blobs.clear()

    // ---- record format -----------------------------------------------------

    private fun seal(message: StoredMessage): ByteArray {
        val plaintext = ByteWriter(RECORD_HEADER + message.body.size)
            .u32(message.messageId ushr 32)
            .u32(message.messageId and 0xFFFFFFFFL)
            .u32(message.timestampMillis ushr 32)
            .u32(message.timestampMillis and 0xFFFFFFFFL)
            .u8(if (message.outgoing) 1 else 0)
            .u8(if (message.read) 1 else 0)
            .bytes(message.body)
            .finish()

        // A fresh nonce per write. Records are rewritten on markRead, so a nonce
        // derived from the message id would repeat under the same key.
        val nonce = crypto.nextBytes(CryptoProvider.AEAD_NONCE_SIZE)
        val sealed = crypto.aeadSeal(keys.storageKey(), nonce, aad(message.peer, message.messageId), plaintext)
        return nonce + sealed
    }

    /**
     * Opens a record.
     *
     * [expectedMessageId] comes from the storage key, and is bound into the
     * associated data. That is what stops a record being relabelled: moving a
     * record to another key, or to another peer's conversation, changes the
     * associated data and the open fails rather than silently succeeding.
     */
    private fun open(record: ByteArray, peer: PeerIdentity, expectedMessageId: Long): StoredMessage? {
        if (record.size <= CryptoProvider.AEAD_NONCE_SIZE) return null
        val nonce = record.copyOf(CryptoProvider.AEAD_NONCE_SIZE)
        val sealed = record.copyOfRange(CryptoProvider.AEAD_NONCE_SIZE, record.size)

        val plaintext = crypto.aeadOpen(keys.storageKey(), nonce, aad(peer, expectedMessageId), sealed)
            ?: return null

        return try {
            val reader = ByteReader(plaintext)
            val messageId = (reader.u32() shl 32) or reader.u32()
            val timestamp = (reader.u32() shl 32) or reader.u32()
            val outgoing = reader.u8() == 1
            val read = reader.u8() == 1
            // The id inside the record must agree with the one it was filed under.
            if (messageId != expectedMessageId) return null
            StoredMessage(messageId, peer, outgoing, timestamp, reader.bytes(reader.remaining), read)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun messageIdFromKey(key: String): Long? = key.substringAfterLast('/').toLongOrNull()

    private fun aad(peer: PeerIdentity, messageId: Long): ByteArray =
        ByteWriter(AAD_CONTEXT.size + peer.publicKey.size + 8)
            .bytes(AAD_CONTEXT)
            .bytes(peer.publicKey)
            .u32(messageId ushr 32)
            .u32(messageId and 0xFFFFFFFFL)
            .finish()

    private fun prefixFor(peer: PeerIdentity): String = "msg/${peer.publicKey.toHex()}/"

    private fun keyFor(peer: PeerIdentity, messageId: Long): String =
        prefixFor(peer) + messageId.toString().padStart(20, '0')

    private companion object {
        const val RECORD_HEADER = 8 + 8 + 1 + 1
        val AAD_CONTEXT = "insnaps-store-v1".encodeToByteArray()
    }
}
