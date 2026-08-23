package com.insnaps.core

import com.insnaps.core.session.ReplayWindow
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReplayWindowTest {

    @Test
    fun `accepts an in-order sequence`() {
        val window = ReplayWindow()
        for (i in 0L until 1000L) assertTrue(window.accept(i), "counter $i should be accepted")
    }

    @Test
    fun `rejects an exact replay`() {
        val window = ReplayWindow()
        assertTrue(window.accept(5))
        assertFalse(window.accept(5))
    }

    @Test
    fun `accepts reordering inside the window`() {
        // The mesh delivers by several paths at once, so out-of-order arrival is
        // normal traffic and must not be treated as an attack.
        val window = ReplayWindow()
        assertTrue(window.accept(10))
        assertTrue(window.accept(7))
        assertTrue(window.accept(9))
        assertTrue(window.accept(8))
        assertFalse(window.accept(9), "but a repeat inside the window is still a replay")
    }

    @Test
    fun `rejects a counter that has fallen out of the window`() {
        val window = ReplayWindow()
        window.accept(0)
        window.accept(ReplayWindow.WINDOW_SIZE + 10)
        assertFalse(window.accept(1), "too old to prove it is not a replay")
    }

    @Test
    fun `a large forward jump resets the window without accepting stale counters`() {
        val window = ReplayWindow()
        window.accept(5)
        assertTrue(window.accept(100_000))
        assertFalse(window.accept(5))
        assertTrue(window.accept(99_999), "still inside the window after the jump")
    }

    @Test
    fun `rejects a negative counter`() {
        assertFalse(ReplayWindow().accept(-1))
    }

    @Test
    fun `reset clears all state`() {
        val window = ReplayWindow()
        window.accept(42)
        window.reset()
        assertTrue(window.accept(42))
    }
}
