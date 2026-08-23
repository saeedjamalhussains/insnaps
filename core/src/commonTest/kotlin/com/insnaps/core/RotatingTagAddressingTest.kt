package com.insnaps.core

import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.packet.RecipientTag
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RotatingTagAddressingTest {

    private val clock = TestClock()
    private val alice = identity("alice")
    private val bob = identity("bob")

    private fun addressing(secrets: TestSecrets) =
        RotatingTagAddressing(secrets, TestMac(), clock, rotationSeconds = 900)

    private fun aliceKnowingBob() = TestSecrets().also { it.add(bob, secret("ab")) }
    private fun bobKnowingAlice() = TestSecrets().also { it.add(alice, secret("ab")) }

    @Test
    fun `the recipient recognises a tag addressed to them`() {
        val tag = addressing(aliceKnowingBob()).tagFor(bob)
        assertTrue(addressing(bobKnowingAlice()).isForMe(tag))
    }

    @Test
    fun `a relay with no session cannot recognise the tag`() {
        val tag = addressing(aliceKnowingBob()).tagFor(bob)
        val stranger = TestSecrets().also { it.add(identity("mallory"), secret("other")) }
        assertFalse(addressing(stranger).isForMe(tag))
    }

    @Test
    fun `the tag changes across rotation periods`() {
        val alicesView = addressing(aliceKnowingBob())
        val first = alicesView.tagFor(bob)
        clock.advanceSeconds(1801) // two full rotations, past the skew tolerance
        assertNotEquals(first, alicesView.tagFor(bob))
    }

    @Test
    fun `tolerates a sender one rotation out of step`() {
        // Peers have no synchronised clock and a packet can sit in a relay buffer,
        // so a tag stamped in the adjacent epoch must still be accepted.
        val tag = addressing(aliceKnowingBob()).tagFor(bob)
        clock.advanceSeconds(900)
        assertTrue(addressing(bobKnowingAlice()).isForMe(tag))
    }

    @Test
    fun `stops accepting a tag two rotations old`() {
        val tag = addressing(aliceKnowingBob()).tagFor(bob)
        clock.advanceSeconds(1801)
        assertFalse(addressing(bobKnowingAlice()).isForMe(tag))
    }

    @Test
    fun `broadcast is for everyone`() {
        assertTrue(addressing(TestSecrets()).isForMe(RecipientTag.BROADCAST))
    }
}
