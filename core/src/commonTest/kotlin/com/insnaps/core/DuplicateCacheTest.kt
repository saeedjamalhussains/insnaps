package com.insnaps.core

import com.insnaps.core.packet.PacketId
import com.insnaps.core.relay.DuplicateCache
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DuplicateCacheTest {

    private val clock = TestClock()
    private fun id(n: Int) = PacketId(ByteArray(PacketId.SIZE) { (n + it).toByte() })

    @Test
    fun `an id is new once and a duplicate thereafter`() {
        val cache = DuplicateCache(maxEntries = 100, retentionMillis = 60_000, clock = clock)
        assertTrue(cache.offer(id(1)))
        assertFalse(cache.offer(id(1)))
        assertFalse(cache.offer(id(1)))
    }

    @Test
    fun `distinct ids do not collide`() {
        val cache = DuplicateCache(maxEntries = 100, retentionMillis = 60_000, clock = clock)
        repeat(50) { assertTrue(cache.offer(id(it))) }
        assertEquals(50, cache.size)
    }

    @Test
    fun `entries expire once past the retention window`() {
        val cache = DuplicateCache(maxEntries = 100, retentionMillis = 60_000, clock = clock)
        cache.offer(id(1))
        clock.advance(60_001)
        assertTrue(cache.offer(id(1)), "an id past retention is treated as new again")
        assertEquals(1, cache.size)
    }

    @Test
    fun `stays bounded under a flood of unique ids`() {
        // An attacker can mint unlimited fresh packet ids, so the bound matters.
        val cache = DuplicateCache(maxEntries = 64, retentionMillis = 600_000, clock = clock)
        repeat(10_000) { cache.offer(id(it)) }
        assertTrue(cache.size <= 64, "cache grew to ${cache.size}")
    }
}
