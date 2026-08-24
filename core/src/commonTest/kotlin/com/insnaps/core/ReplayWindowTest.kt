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

/**
 * Regression: a burst larger than the old 64-message window.
 *
 * File transfer emits chunks as a burst and the mesh reorders it arbitrarily. With
 * a 64-bit window, exactly 64 of 112 chunks survived and the rest were rejected as
 * replays -- a silent, data-losing failure found by the sandbox, not by unit tests.
 */
class ReplayWindowBurstTest {

    @kotlin.test.Test
    fun `a fully shuffled burst of a thousand messages is accepted`() {
        val window = ReplayWindow()
        val counters = (0L until 1000L).shuffled(kotlin.random.Random(99))
        val accepted = counters.count { window.accept(it) }
        kotlin.test.assertEquals(1000, accepted, "only $accepted of 1000 shuffled counters were accepted")
    }

    @kotlin.test.Test
    fun `replays inside a shuffled burst are still caught`() {
        val window = ReplayWindow()
        val counters = (0L until 500L).shuffled(kotlin.random.Random(7))
        counters.forEach { window.accept(it) }
        kotlin.test.assertTrue(counters.none { window.accept(it) }, "a replay slipped through")
    }

    @kotlin.test.Test
    fun `a counter older than the window is still rejected after wrapping`() {
        // The ring index must not let a counter from a previous lap look unseen.
        val window = ReplayWindow()
        window.accept(0)
        window.accept(ReplayWindow.WINDOW_SIZE * 3)
        kotlin.test.assertFalse(window.accept(0), "a stale counter was accepted after the window wrapped")
        kotlin.test.assertFalse(
            window.accept(ReplayWindow.WINDOW_SIZE * 2),
            "a counter outside the window was accepted",
        )
    }
}
