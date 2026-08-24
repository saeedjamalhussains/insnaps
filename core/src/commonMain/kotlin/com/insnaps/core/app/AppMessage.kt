package com.insnaps.core.app

import com.insnaps.core.session.SecureMesh
import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter

/**
 * The application-level message, carried entirely inside the E2EE payload.
 *
 * Every field here -- including the conversation mode and the expiry policy --
 * is sealed before it reaches the mesh. A relay sees ciphertext of an opaque
 * length and cannot tell a private message from a normal one, a text message
 * from a file chunk, or read a receipt. Putting the mode in the packet header
 * would have been simpler and would have leaked exactly the metadata private
 * mode exists to protect.
 *
 * Layout:
 * ```
 *   version    1
 *   mode       1
 *   type       1
 *   expiry     1
 *   messageId  8
 *   body       n
 * ```
 */
data class AppMessage(
    val type: Type,
    val mode: ConversationMode,
    val expiry: ExpiryPolicy,
    val messageId: Long,
    val body: ByteArray,
) {
    enum class Type(val code: Int) {
        TEXT(1),
        FILE_MANIFEST(2),
        FILE_CHUNK(3),
        RECEIPT(4),

        /** Confirms a manifest arrived, so the sender stops retransmitting it. */
        FILE_MANIFEST_ACK(5),

        /** Selective acknowledgement carrying the ranges still missing. */
        FILE_CHUNK_ACK(6),
        ;

        companion object {
            fun fromCode(code: Int): Type? = entries.firstOrNull { it.code == code }
        }
    }

    init {
        require(body.size <= MAX_BODY_SIZE) { "body ${body.size} exceeds $MAX_BODY_SIZE" }
        require(!(mode.requiresExpiry && expiry == ExpiryPolicy.NONE)) {
            "a private message must carry an expiry policy"
        }
    }

    fun encode(): ByteArray = ByteWriter(HEADER_SIZE + body.size)
        .u8(VERSION)
        .u8(if (mode == ConversationMode.PRIVATE) 1 else 0)
        .u8(type.code)
        .u8(expiry.code)
        .u32(messageId ushr 32)
        .u32(messageId and 0xFFFFFFFFL)
        .bytes(body)
        .finish()

    override fun equals(other: Any?): Boolean =
        this === other || (other is AppMessage && type == other.type && mode == other.mode &&
            expiry == other.expiry && messageId == other.messageId && body.contentEquals(other.body))

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + mode.hashCode()
        result = 31 * result + expiry.hashCode()
        result = 31 * result + messageId.hashCode()
        result = 31 * result + body.contentHashCode()
        return result
    }

    /** Never renders the body: this type routinely holds private plaintext. */
    override fun toString(): String =
        "AppMessage(type=$type, mode=$mode, expiry=$expiry, id=$messageId, body=${body.size}B)"

    companion object {
        const val VERSION = 1
        const val HEADER_SIZE = 1 + 1 + 1 + 1 + 8

        /** What is left of a sealed payload once this header is accounted for. */
        const val MAX_BODY_SIZE = SecureMesh.MAX_PLAINTEXT_SIZE - HEADER_SIZE

        /**
         * Decodes a message that came out of a session.
         *
         * Returns null for anything malformed. The bytes are authenticated by the
         * AEAD before they reach here, so a failure means a peer running a
         * different or broken version rather than an attacker -- but it is still
         * handled as data, not as an exception.
         */
        fun decode(bytes: ByteArray): AppMessage? {
            if (bytes.size < HEADER_SIZE) return null
            return try {
                val reader = ByteReader(bytes)
                if (reader.u8() != VERSION) return null
                val mode = when (reader.u8()) {
                    0 -> ConversationMode.NORMAL
                    1 -> ConversationMode.PRIVATE
                    else -> return null
                }
                val type = Type.fromCode(reader.u8()) ?: return null
                val expiry = ExpiryPolicy.fromCode(reader.u8()) ?: return null
                val messageId = (reader.u32() shl 32) or reader.u32()
                val body = reader.bytes(reader.remaining)

                if (mode.requiresExpiry && expiry == ExpiryPolicy.NONE) return null
                AppMessage(type, mode, expiry, messageId, body)
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}
