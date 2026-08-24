package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.routing.ForwardingPolicy
import com.insnaps.core.routing.LinkConditions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

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
        val targets = ForwardingPolicy.select(policy, (1..4).toList(), LinkConditions(4, 0.1), JvmCryptoProvider())
        assertEquals(4, targets.size)
    }

    @Test
    fun `selection is a weighted sample, not the top k`() {
        // The v0.7 change. Taking the top k deterministically was measured to
        // deliver 55% of a geographic mesh, because every node picked the same
        // favoured neighbours at every hop.
        val ranked = (1..20).toList()
        val random = JvmCryptoProvider()
        val counts = IntArray(21)

        repeat(2_000) {
            ForwardingPolicy.select(policy, ranked, LinkConditions(20, 0.9), random) { 0.5 }
                .forEach { counts[it]++ }
        }

        assertEquals(6, ForwardingPolicy.select(policy, ranked, LinkConditions(20, 0.9), random) { 0.5 }.size)
        // With equal weights every neighbour must get a turn; none may be frozen out.
        assertTrue(counts.drop(1).all { it > 0 }, "some neighbour was never selected: ${counts.toList()}")
        assertTrue(counts.drop(1).min() > 200, "selection was far from uniform: ${counts.toList()}")
    }

    @Test
    fun `a better peer is preferred but not always chosen`() {
        // Both halves matter: quality must still bias the choice, and must not
        // determine it outright.
        val candidates = (1..12).toList()
        val random = JvmCryptoProvider()
        val counts = IntArray(13)

        repeat(3_000) {
            ForwardingPolicy.select(policy, candidates, LinkConditions(12, 0.9), random) { id ->
                if (id == 1) 1.0 else 0.2
            }.forEach { counts[it]++ }
        }

        val best = counts[1]
        val others = counts.drop(2)
        assertTrue(best > others.max(), "the high-quality peer should be preferred; got $best vs ${others.max()}")
        assertTrue(best < 3_000, "the high-quality peer was chosen every single time -- the old failure mode")
        assertTrue(others.min() > 0, "a low-quality peer was never chosen at all")
    }

    @Test
    fun `an incoherent configuration is rejected at construction`() {
        assertFailsWith<IllegalArgumentException> { ForwardingPolicy.AdaptiveFanout(goodFanout = 20, moderateFanout = 10) }
        assertFailsWith<IllegalArgumentException> { ForwardingPolicy.AdaptiveFanout(moderateQuality = 0.9, goodQuality = 0.5) }
    }
}
