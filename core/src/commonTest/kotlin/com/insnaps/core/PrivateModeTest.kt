package com.insnaps.core

import com.insnaps.core.app.EphemeralStore
import com.insnaps.core.app.ExpiryPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Private Mode lifecycle: messages exist in RAM, expire on schedule, and leave
 * nothing behind.
 */
class PrivateModeTest {

    private val clock = TestClock()
    private val peer = identity("bob")
    private fun store() = EphemeralStore(clock)

    private fun body(text: String) = text.encodeToByteArray()

    @Test
    fun `a private message is readable until it expires`() {
        val store = store()
        val entry = store.put(1, peer, body("meet me"), ExpiryPolicy.THIRTY_SECONDS)

        assertEquals("meet me", entry.read { it.decodeToString() })
        clock.advance(29_000)
        assertNotNull(store.get(1))

        clock.advance(2_000)
        assertNull(store.get(1), "the message should be gone past its deadline")
        assertTrue(entry.destroyed)
        assertNull(entry.read { it.decodeToString() }, "a destroyed message must not be readable")
    }

    @Test
    fun `view once is destroyed the moment it is viewed`() {
        val store = store()
        val entry = store.put(1, peer, body("burn after reading"), ExpiryPolicy.VIEW_ONCE)

        assertTrue(store.markViewed(1))
        assertTrue(entry.destroyed, "view-once must be destroyed at the view, not on a later sweep")
        assertNull(store.get(1))
        assertEquals(0, store.size)
    }

    @Test
    fun `view once still expires if never viewed`() {
        val store = store()
        store.put(1, peer, body("unread"), ExpiryPolicy.VIEW_ONCE)
        clock.advance(ExpiryPolicy.VIEW_ONCE.durationMillis + 1)
        assertNull(store.get(1), "an unread view-once message must not live forever")
    }

    @Test
    fun `every expiry option behaves`() {
        for (policy in listOf(
            ExpiryPolicy.THIRTY_SECONDS,
            ExpiryPolicy.FIVE_MINUTES,
            ExpiryPolicy.ONE_HOUR,
            ExpiryPolicy.TWENTY_FOUR_HOURS,
        )) {
            val store = store()
            store.put(1, peer, body("x"), policy)

            clock.advance(policy.durationMillis - 1000)
            assertNotNull(store.get(1), "$policy expired early")

            clock.advance(2000)
            assertNull(store.get(1), "$policy did not expire")
        }
    }

    @Test
    fun `the body is zeroed on expiry rather than left behind`() {
        val store = store()
        val leaked = body("sensitive")
        store.put(1, peer, leaked, ExpiryPolicy.THIRTY_SECONDS)

        clock.advance(31_000)
        store.purgeExpired()

        assertTrue(leaked.all { it == 0.toByte() }, "the plaintext buffer was not zeroed")
    }

    @Test
    fun `destroyAll leaves no private plaintext`() {
        val store = store()
        val bodies = (1..10).map { body("secret $it") }
        bodies.forEachIndexed { i, b -> store.put(i.toLong(), peer, b, ExpiryPolicy.ONE_HOUR) }

        store.destroyAll()

        assertEquals(0, store.size)
        assertTrue(bodies.all { b -> b.all { it == 0.toByte() } }, "plaintext survived destroyAll")
    }

    @Test
    fun `the store is bounded so a peer cannot grow it without limit`() {
        val store = EphemeralStore(clock, maxMessages = 16)
        repeat(1_000) { store.put(it.toLong(), peer, body("flood $it"), ExpiryPolicy.ONE_HOUR) }
        assertTrue(store.size <= 16, "held ${store.size} private messages")
    }

    @Test
    fun `a private message must carry an expiry policy`() {
        val store = store()
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            store.put(1, peer, body("x"), ExpiryPolicy.NONE)
        }
    }

    @Test
    fun `replacing a message destroys the previous body`() {
        val store = store()
        val first = body("first")
        store.put(1, peer, first, ExpiryPolicy.ONE_HOUR)
        store.put(1, peer, body("second"), ExpiryPolicy.ONE_HOUR)

        assertTrue(first.all { it == 0.toByte() }, "the replaced body was not zeroed")
        assertEquals("second", store.get(1)?.read { it.decodeToString() })
    }

    @Test
    fun `removing a message destroys it immediately`() {
        val store = store()
        val b = body("gone")
        val entry = store.put(1, peer, b, ExpiryPolicy.TWENTY_FOUR_HOURS)
        assertTrue(store.remove(1))
        assertTrue(entry.destroyed)
        assertFalse(store.remove(1))
    }
}
