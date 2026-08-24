package com.insnaps.core

import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.EncryptedMessageStore
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.app.StoredMessage
import com.insnaps.core.crypto.JvmCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Normal Mode: persistent history at the endpoints, encrypted at rest. */
class NormalModeStoreTest {

    private val crypto = JvmCryptoProvider()
    private val blobs = InMemoryBlobStore()
    private val keys = TestStorageKeys()
    private val store = EncryptedMessageStore(blobs, keys, crypto)
    private val alice = identity("alice")
    private val bob = identity("bob")

    private fun message(id: Long, text: String, outgoing: Boolean = true) =
        StoredMessage(id, bob, outgoing, 1_000_000 + id, text.encodeToByteArray())

    @Test
    fun `a message round trips through storage`() {
        store.append(message(1, "hello"))
        val history = store.history(bob)
        assertEquals(1, history.size)
        assertEquals("hello", history.single().body.decodeToString())
    }

    @Test
    fun `history survives a restart`() {
        // A new store over the same blobs and key is exactly what an app relaunch is.
        store.append(message(1, "before restart"))
        store.append(message(2, "also before"))

        val reopened = EncryptedMessageStore(blobs, keys, crypto)
        assertEquals(listOf("before restart", "also before"), reopened.history(bob).map { it.body.decodeToString() })
    }

    @Test
    fun `what reaches storage is ciphertext, never plaintext`() {
        val secret = "the meeting is at midnight"
        store.append(message(1, secret))

        val onDisk = blobs.allBytes()
        assertTrue(onDisk.isNotEmpty())
        val secretBytes = secret.encodeToByteArray().toList()
        assertFalse(
            onDisk.any { it.toList().windowed(secretBytes.size).any { w -> w == secretBytes } },
            "plaintext appeared in stored bytes",
        )
    }

    @Test
    fun `a record cannot be opened with the wrong storage key`() {
        store.append(message(1, "confidential"))
        val wrongKey = EncryptedMessageStore(blobs, TestStorageKeys(ByteArray(32) { 9 }), crypto)
        assertTrue(wrongKey.history(bob).isEmpty(), "history opened under the wrong key")
    }

    @Test
    fun `a record moved to another conversation fails authentication`() {
        // The peer is bound into the associated data, so relabelling is detected.
        store.append(message(1, "for bob"))
        val key = blobs.keys("msg/").single()
        val record = blobs.get(key)!!
        blobs.put("msg/${alice.publicKey.toHexForTest()}/${"1".padStart(20, '0')}", record)

        assertTrue(store.history(alice).isEmpty(), "a relabelled record must not open")
    }

    @Test
    fun `a tampered record is skipped rather than returned`() {
        store.append(message(1, "intact"))
        store.append(message(2, "tampered"))
        val key = blobs.keys("msg/").last()
        blobs.put(key, blobs.get(key)!!.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() })

        assertEquals(listOf("intact"), store.history(bob).map { it.body.decodeToString() })
    }

    @Test
    fun `read status can be set and persists`() {
        store.append(message(1, "unread", outgoing = false))
        assertFalse(store.history(bob).single().read)

        assertTrue(store.markRead(bob, 1))
        assertTrue(store.history(bob).single().read)
        assertFalse(store.markRead(bob, 999), "marking a missing message read should report failure")
    }

    @Test
    fun `deleting removes a message, a conversation, or everything`() {
        store.append(message(1, "one"))
        store.append(message(2, "two"))
        store.delete(bob, 1)
        assertEquals(1, store.history(bob).size)

        store.append(message(3, "three"))
        store.deleteConversation(bob)
        assertTrue(store.history(bob).isEmpty())
        assertTrue(blobs.contents.isEmpty(), "deleting a conversation must remove the stored bytes")

        store.append(message(4, "four"))
        store.deleteAll()
        assertTrue(blobs.contents.isEmpty())
    }

    @Test
    fun `the store refuses to persist a private message`() {
        // The guarantee is enforced at the persistence path, not left to callers.
        assertFailsWith<IllegalArgumentException> {
            store.append(message(1, "private"), ConversationMode.PRIVATE)
        }
        assertTrue(blobs.contents.isEmpty(), "a private message must never reach storage")
    }

    @Test
    fun `history is ordered oldest first`() {
        store.append(StoredMessage(3, bob, true, 3_000, "third".encodeToByteArray()))
        store.append(StoredMessage(1, bob, true, 1_000, "first".encodeToByteArray()))
        store.append(StoredMessage(2, bob, true, 2_000, "second".encodeToByteArray()))
        assertEquals(listOf("first", "second", "third"), store.history(bob).map { it.body.decodeToString() })
    }

    @Test
    fun `each write uses a fresh nonce`() {
        // markRead rewrites the record under the same key; a nonce derived from the
        // message id would repeat under the same storage key.
        store.append(message(1, "same content"))
        val first = blobs.get(blobs.keys("msg/").single())!!.copyOf()
        store.markRead(bob, 1)
        val second = blobs.get(blobs.keys("msg/").single())!!

        assertFalse(first.contentEquals(second), "rewriting produced an identical record")
        assertFalse(
            first.copyOf(12).contentEquals(second.copyOf(12)),
            "the nonce was reused across two writes under the same key",
        )
    }

    @Test
    fun `the application message format carries mode and expiry inside the ciphertext`() {
        val message = AppMessage(
            type = AppMessage.Type.TEXT,
            mode = ConversationMode.PRIVATE,
            expiry = ExpiryPolicy.FIVE_MINUTES,
            messageId = 42,
            body = "hidden".encodeToByteArray(),
        )
        val decoded = AppMessage.decode(message.encode())
        assertNotNull(decoded)
        assertEquals(ConversationMode.PRIVATE, decoded.mode)
        assertEquals(ExpiryPolicy.FIVE_MINUTES, decoded.expiry)
        assertContentEquals("hidden".encodeToByteArray(), decoded.body)
    }

    @Test
    fun `malformed application messages decode to null`() {
        assertNull(AppMessage.decode(ByteArray(0)))
        assertNull(AppMessage.decode(ByteArray(5)))
        assertNull(AppMessage.decode(ByteArray(12) { 0xFF.toByte() }), "unknown version must be rejected")
        for (size in 0..40) AppMessage.decode(ByteArray(size) { (it * 13).toByte() })
    }

    @Test
    fun `a private application message without an expiry is rejected`() {
        assertFailsWith<IllegalArgumentException> {
            AppMessage(AppMessage.Type.TEXT, ConversationMode.PRIVATE, ExpiryPolicy.NONE, 1, ByteArray(0))
        }
    }
}

private fun ByteArray.toHexForTest(): String =
    joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
