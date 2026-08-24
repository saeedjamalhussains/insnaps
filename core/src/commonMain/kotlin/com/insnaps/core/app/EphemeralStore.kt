package com.insnaps.core.app

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.session.SecretBytes
import com.insnaps.core.util.Clock

/**
 * RAM-only holder for Private Mode messages.
 *
 * Private plaintext lives here and nowhere else. There is no [BlobStore] behind
 * it, no file handle, no serialization path -- the type simply has no way to
 * write anything down, which is a stronger guarantee than a policy that says it
 * should not.
 *
 * Bounded, because an endpoint receives private messages from anyone it has a
 * session with: [maxMessages] caps how many can be held, evicting the nearest to
 * expiry when full.
 */
class EphemeralStore(
    private val clock: Clock,
    private val maxMessages: Int = DEFAULT_MAX_MESSAGES,
) {

    /**
     * A live private message.
     *
     * The body is wrapped in [SecretBytes] so it is zeroed on expiry rather than
     * left for the garbage collector. As documented there, zeroing narrows the
     * exposure window and does not guarantee erasure.
     */
    class Entry internal constructor(
        val messageId: Long,
        val peer: PeerIdentity,
        val outgoing: Boolean,
        val expiry: ExpiryPolicy,
        val receivedAtMillis: Long,
        internal val secret: SecretBytes,
    ) {
        var viewed: Boolean = false
            internal set

        val destroyed: Boolean get() = secret.destroyed

        /** Deadline at which this message must be gone regardless of whether it was read. */
        val deadlineMillis: Long get() = receivedAtMillis + expiry.durationMillis

        /** Reads the body. Returns null once destroyed. */
        fun <T> read(block: (ByteArray) -> T): T? = if (destroyed) null else secret.use(block)
    }

    private val entries = LinkedHashMap<Long, Entry>()

    val size: Int get() = entries.size

    /** Number of messages destroyed so far. Diagnostics only; carries no content. */
    var destroyedCount: Long = 0
        private set

    fun put(
        messageId: Long,
        peer: PeerIdentity,
        body: ByteArray,
        expiry: ExpiryPolicy,
        outgoing: Boolean = false,
    ): Entry {
        require(expiry != ExpiryPolicy.NONE) { "a private message must have an expiry policy" }
        purgeExpired()
        entries.remove(messageId)?.let { destroy(it) }
        if (entries.size >= maxMessages) evictNearestDeadline()

        val entry = Entry(messageId, peer, outgoing, expiry, clock.nowMillis(), SecretBytes(body))
        entries[messageId] = entry
        return entry
    }

    /** A live message, or null if it never existed or has expired. */
    fun get(messageId: Long): Entry? {
        purgeExpired()
        return entries[messageId]
    }

    /**
     * Records that the user has seen a message, and destroys it if it was view-once.
     *
     * Destruction happens here rather than on a later sweep so the plaintext is
     * gone the moment the view ends, not whenever a timer next runs.
     */
    fun markViewed(messageId: Long): Boolean {
        val entry = get(messageId) ?: return false
        entry.viewed = true
        if (entry.expiry.isViewOnce) {
            entries.remove(messageId)
            destroy(entry)
        }
        return true
    }

    /** Destroys everything past its deadline. Safe to call on a timer. */
    fun purgeExpired(): Int {
        if (entries.isEmpty()) return 0
        val now = clock.nowMillis()
        var removed = 0
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next().value
            if (entry.deadlineMillis <= now) {
                iterator.remove()
                destroy(entry)
                removed++
            }
        }
        return removed
    }

    fun remove(messageId: Long): Boolean {
        val entry = entries.remove(messageId) ?: return false
        destroy(entry)
        return true
    }

    fun conversation(peer: PeerIdentity): List<Entry> {
        purgeExpired()
        return entries.values.filter { it.peer == peer }
    }

    /**
     * Destroys everything.
     *
     * Called when the app is terminating, when private mode is left, and when the
     * user asks. After this the process holds no private plaintext.
     */
    fun destroyAll() {
        entries.values.forEach { destroy(it) }
        entries.clear()
    }

    private fun destroy(entry: Entry) {
        entry.secret.destroy()
        destroyedCount++
    }

    private fun evictNearestDeadline() {
        val victim = entries.values.minByOrNull { it.deadlineMillis } ?: return
        entries.remove(victim.messageId)
        destroy(victim)
    }

    private companion object {
        const val DEFAULT_MAX_MESSAGES = 500
    }
}
