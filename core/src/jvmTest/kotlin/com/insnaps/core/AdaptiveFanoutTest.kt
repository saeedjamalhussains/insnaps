package com.insnaps.core

import com.insnaps.core.routing.ForwardingPolicy
import com.insnaps.core.routing.LinkConditions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Unit-level behaviour of the adaptive policy's fanout decision. */
class AdaptiveFanoutTest {

    private val policy = ForwardingPolicy.AdaptiveFanout()

    @Test
    fun `a thin neighbourhood floods`() {
        // Restricting a fanout below the degree in a sparse mesh is how nodes get
        // isolated, so below the threshold the policy does not restrict at all.
        assertEquals(3, policy.fanoutFor(LinkConditions(3, 0.9)))
        assertEquals(6, policy.fanoutFor(LinkConditions(6, 0.9)))
    }

    @Test
    fun `good conditions use the narrow fanout`() {
        assertEquals(6, policy.fanoutFor(LinkConditions(30, 0.8)))
    }

    @Test
    fun `moderate conditions widen the fanout`() {
        assertEquals(10, policy.fanoutFor(LinkConditions(30, 0.5)))
    }

    @Test
    fun `poor conditions widen it further`() {
        assertEquals(16, policy.fanoutFor(LinkConditions(30, 0.1)))
    }

    @Test
    fun `the fanout never exceeds the neighbours available`() {
        val targets = ForwardingPolicy.select(policy, (1..4).toList(), LinkConditions(4, 0.1), TestRandom())
        assertEquals(4, targets.size)
    }

    @Test
    fun `selection preserves the ranking order`() {
        val ranked = (1..20).toList()
        val targets = ForwardingPolicy.select(policy, ranked, LinkConditions(20, 0.9), TestRandom())
        assertEquals(listOf(1, 2, 3, 4, 5, 6), targets)
    }

    @Test
    fun `an incoherent configuration is rejected at construction`() {
        assertFailsWith<IllegalArgumentException> { ForwardingPolicy.AdaptiveFanout(goodFanout = 20, moderateFanout = 10) }
        assertFailsWith<IllegalArgumentException> { ForwardingPolicy.AdaptiveFanout(moderateQuality = 0.9, goodQuality = 0.5) }
    }
}
