package com.insnaps.core

import com.insnaps.core.routing.PeerTable
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.ThroughputClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PeerTableTest {

    private val clock = TestClock()
    private fun table() = PeerTable(maxEntries = 8, clock = clock)

    @Test
    fun `prefers the neighbour the platform reports as more reliable`() {
        val table = table()
        // This is the iOS-backgrounded case: both are advertising, one cannot relay.
        table.onPeerFound(PeerHandle("reliable", reliabilityHint = 0.95))
        table.onPeerFound(PeerHandle("backgrounded", reliabilityHint = 0.05))

        assertEquals("reliable", table.rankedPeers().first().handle.id)
    }

    @Test
    fun `prefers a fresher neighbour over a stale one`() {
        val table = table()
        table.onPeerFound(PeerHandle("old", reliabilityHint = 0.5))
        clock.advanceSeconds(60)
        table.onPeerFound(PeerHandle("new", reliabilityHint = 0.5))

        assertEquals("new", table.rankedPeers().first().handle.id)
    }

    @Test
    fun `demotes a neighbour that keeps failing to forward`() {
        val table = table()
        table.onPeerFound(PeerHandle("good", reliabilityHint = 0.5))
        table.onPeerFound(PeerHandle("flaky", reliabilityHint = 0.5))
        repeat(10) {
            table.recordForwardResult("good", succeeded = true)
            table.recordForwardResult("flaky", succeeded = false)
        }
        assertEquals("good", table.rankedPeers().first().handle.id)
    }

    @Test
    fun `a fast link is a tiebreaker but never beats reachability`() {
        val table = table()
        table.onPeerFound(PeerHandle("fast-but-unreliable", reliabilityHint = 0.1, throughputClass = ThroughputClass.HIGH))
        table.onPeerFound(PeerHandle("slow-but-reliable", reliabilityHint = 0.95, throughputClass = ThroughputClass.LOW))
        assertEquals("slow-but-reliable", table.rankedPeers().first().handle.id)
    }

    @Test
    fun `excludes the neighbour a packet came from`() {
        val table = table()
        table.onPeerFound(PeerHandle("a"))
        table.onPeerFound(PeerHandle("b"))
        assertEquals(listOf("b"), table.rankedPeers(excluding = "a").map { it.handle.id })
    }

    @Test
    fun `drops neighbours not heard from within the staleness window`() {
        val table = table()
        table.onPeerFound(PeerHandle("a"))
        clock.advance(PeerTable.DEFAULT_STALENESS_MILLIS + 1)
        assertEquals(1, table.purgeStale())
        assertEquals(0, table.size)
    }

    @Test
    fun `stays within its entry bound`() {
        val table = table()
        repeat(100) { table.onPeerFound(PeerHandle("peer-$it")); clock.advance(10) }
        assertTrue(table.size <= 8, "peer table grew to ${table.size}")
    }
}
