package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.session.HandshakeInitiator
import com.insnaps.core.session.HandshakeResponder
import com.insnaps.core.session.Session
import com.insnaps.core.session.SessionPolicy
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionTest {

    private val crypto = JvmCryptoProvider()
    private val clock = TestClock()
    private val alice = crypto.generateX25519KeyPair()
    private val bob = crypto.generateX25519KeyPair()

    /** Establishes a real session pair through the handshake. */
    private fun sessionPair(policy: SessionPolicy = SessionPolicy()): Pair<Session, Session> {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val responder = HandshakeResponder(crypto, bob)
        responder.readMessage1(initiator.writeMessage1())
        val (message2, bobResult) = responder.writeMessage2()
        val aliceResult = initiator.readMessage2(message2)

        val now = clock.nowMillis()
        return Session(aliceResult.peer, aliceResult.sessionId, aliceResult.sendKey, aliceResult.receiveKey, crypto, now, policy) to
            Session(bobResult.peer, bobResult.sessionId, bobResult.sendKey, bobResult.receiveKey, crypto, now, policy)
    }

    @Test
    fun `a sealed message opens on the other side`() {
        val (a, b) = sessionPair()
        val plaintext = "meet at the usual place".encodeToByteArray()
        val sealed = a.seal(plaintext, clock.nowMillis())
        assertContentEquals(plaintext, b.open(sealed, clock.nowMillis()))
    }

    @Test
    fun `the sealed frame does not contain the plaintext`() {
        val (a, _) = sessionPair()
        val plaintext = "secret".encodeToByteArray()
        val sealed = a.seal(plaintext, clock.nowMillis())
        assertFalse(
            sealed.toList().windowed(plaintext.size).any { it == plaintext.toList() },
            "plaintext appeared in the sealed frame",
        )
    }

    @Test
    fun `a replayed frame is rejected`() {
        val (a, b) = sessionPair()
        val sealed = a.seal("once".encodeToByteArray(), clock.nowMillis())
        assertNotNull(b.open(sealed, clock.nowMillis()))
        assertNull(b.open(sealed, clock.nowMillis()), "the same frame must not open twice")
    }

    @Test
    fun `out of order delivery is accepted`() {
        val (a, b) = sessionPair()
        val frames = (1..5).map { a.seal("msg $it".encodeToByteArray(), clock.nowMillis()) }
        for (frame in frames.reversed()) {
            assertNotNull(b.open(frame, clock.nowMillis()), "reordered frames are normal on a mesh")
        }
    }

    @Test
    fun `a tampered frame does not open`() {
        val (a, b) = sessionPair()
        val sealed = a.seal("integrity".encodeToByteArray(), clock.nowMillis())
        for (index in listOf(0, 8, sealed.size - 1)) {
            val tampered = sealed.copyOf().also { it[index] = (it[index] + 1).toByte() }
            assertNull(b.open(tampered, clock.nowMillis()), "tampering at $index went undetected")
        }
    }

    @Test
    fun `a frame from an unrelated session does not open`() {
        val (a, _) = sessionPair()
        val (_, otherB) = sessionPair()
        val sealed = a.seal("not for you".encodeToByteArray(), clock.nowMillis())
        assertNull(otherB.open(sealed, clock.nowMillis()))
    }

    @Test
    fun `a forged frame cannot burn a counter slot`() {
        // The replay window must only advance for authenticated messages, or anyone
        // could lock out counters by sending forgeries.
        val (a, b) = sessionPair()
        val genuine = a.seal("real".encodeToByteArray(), clock.nowMillis())
        val forged = genuine.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }

        assertNull(b.open(forged, clock.nowMillis()))
        assertContentEquals("real".encodeToByteArray(), b.open(genuine, clock.nowMillis()))
    }

    @Test
    fun `garbage frames of any length are rejected safely`() {
        val (_, b) = sessionPair()
        for (size in 0..64) {
            assertNull(b.open(ByteArray(size) { it.toByte() }, clock.nowMillis()))
        }
    }

    @Test
    fun `a session expires with age`() {
        val (a, _) = sessionPair(SessionPolicy(maxAgeMillis = 1000, maxIdleMillis = 1000))
        assertFalse(a.isExpired(clock.nowMillis()))
        clock.advance(1001)
        assertTrue(a.isExpired(clock.nowMillis()))
    }

    @Test
    fun `a session expires when idle`() {
        val (a, _) = sessionPair(SessionPolicy(maxAgeMillis = 1_000_000, maxIdleMillis = 500))
        clock.advance(501)
        assertTrue(a.isExpired(clock.nowMillis()))
    }

    @Test
    fun `a session stops sending at its message limit`() {
        val (a, _) = sessionPair(SessionPolicy(maxMessages = 3))
        repeat(3) { a.seal("x".encodeToByteArray(), clock.nowMillis()) }
        assertTrue(a.isExpired(clock.nowMillis()))
        assertFailsWith<IllegalStateException> { a.seal("one too many".encodeToByteArray(), clock.nowMillis()) }
    }

    @Test
    fun `destroying a session makes it unusable`() {
        val (a, b) = sessionPair()
        val sealed = a.seal("before".encodeToByteArray(), clock.nowMillis())
        b.destroy()

        assertTrue(b.destroyed)
        assertNull(b.open(sealed, clock.nowMillis()), "a destroyed session must not decrypt")
        assertFailsWith<IllegalStateException> { b.seal("after".encodeToByteArray(), clock.nowMillis()) }
        b.destroy() // idempotent
    }

    @Test
    fun `counters advance so no nonce repeats`() {
        val (a, _) = sessionPair()
        val frames = (1..200).map { a.seal("same".encodeToByteArray(), clock.nowMillis()).toList() }
        assertEquals(200, frames.toSet().size, "identical plaintext must not produce identical frames")
    }
}
