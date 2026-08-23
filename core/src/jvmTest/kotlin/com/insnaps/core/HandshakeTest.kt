package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.session.HandshakeFailure
import com.insnaps.core.session.HandshakeInitiator
import com.insnaps.core.session.HandshakeResponder
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HandshakeTest {

    private val crypto = JvmCryptoProvider()
    private val alice = crypto.generateX25519KeyPair()
    private val bob = crypto.generateX25519KeyPair()

    @Test
    fun `both sides derive matching directional keys`() {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val responder = HandshakeResponder(crypto, bob)

        val message1 = initiator.writeMessage1()
        responder.readMessage1(message1)
        val (message2, bobResult) = responder.writeMessage2()
        val aliceResult = initiator.readMessage2(message2)

        // Alice sends on the key Bob receives on, and vice versa.
        assertContentEquals(aliceResult.sendKey, bobResult.receiveKey)
        assertContentEquals(aliceResult.receiveKey, bobResult.sendKey)
        // Directional keys must differ, or a reflected message would decrypt.
        assertFalse(aliceResult.sendKey.contentEquals(aliceResult.receiveKey))
        assertContentEquals(aliceResult.sessionId, bobResult.sessionId)
    }

    @Test
    fun `each side learns the other's true identity`() {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val responder = HandshakeResponder(crypto, bob)

        val learned = responder.readMessage1(initiator.writeMessage1())
        val (message2, _) = responder.writeMessage2()
        val aliceResult = initiator.readMessage2(message2)

        assertContentEquals(alice.publicKey, learned.publicKey)
        assertContentEquals(bob.publicKey, aliceResult.peer.publicKey)
    }

    @Test
    fun `the initiator's identity is not sent in the clear`() {
        // This is the point of choosing IK: a relay watching msg1 must not learn
        // who is initiating.
        val message1 = HandshakeInitiator(crypto, alice, bob.publicKey).writeMessage1()
        assertFalse(
            message1.toList().windowed(alice.publicKey.size).any { it == alice.publicKey.toList() },
            "initiator static key appeared verbatim in message 1",
        )
    }

    @Test
    fun `two handshakes between the same pair produce different keys`() {
        fun run(): ByteArray {
            val i = HandshakeInitiator(crypto, alice, bob.publicKey)
            val r = HandshakeResponder(crypto, bob)
            r.readMessage1(i.writeMessage1())
            return i.readMessage2(r.writeMessage2().first).sendKey
        }
        assertFalse(run().contentEquals(run()), "ephemeral keys must make each session unique")
    }

    @Test
    fun `a responder with the wrong static key cannot complete the handshake`() {
        val mallory = crypto.generateX25519KeyPair()
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val wrongResponder = HandshakeResponder(crypto, mallory)

        assertFailsWith<HandshakeFailure> { wrongResponder.readMessage1(initiator.writeMessage1()) }
    }

    @Test
    fun `tampering with message 1 is detected`() {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val message1 = initiator.writeMessage1()

        for (index in listOf(0, 32, message1.size - 1)) {
            val tampered = message1.copyOf().also { it[index] = (it[index] + 1).toByte() }
            val responder = HandshakeResponder(crypto, bob)
            // Either authentication fails or the mangled point is rejected outright.
            val rejected = try {
                responder.readMessage1(tampered); false
            } catch (_: HandshakeFailure) { true } catch (_: IllegalArgumentException) { true }
            assertTrue(rejected, "tampering at byte $index went undetected")
        }
    }

    @Test
    fun `tampering with message 2 is detected`() {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val responder = HandshakeResponder(crypto, bob)
        responder.readMessage1(initiator.writeMessage1())
        val message2 = responder.writeMessage2().first

        val tampered = message2.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertFailsWith<HandshakeFailure> { initiator.readMessage2(tampered) }
    }

    @Test
    fun `truncated handshake messages are rejected without throwing unexpectedly`() {
        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val message1 = initiator.writeMessage1()
        for (size in 0 until message1.size) {
            val responder = HandshakeResponder(crypto, bob)
            try {
                responder.readMessage1(message1.copyOf(size))
            } catch (_: HandshakeFailure) {
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun `a replayed message 1 yields a different session`() {
        // The responder's ephemeral key changes per attempt, so a captured msg1
        // cannot be used to resurrect an old session's keys.
        val message1 = HandshakeInitiator(crypto, alice, bob.publicKey).writeMessage1()

        val first = HandshakeResponder(crypto, bob).run { readMessage1(message1); writeMessage2().second }
        val second = HandshakeResponder(crypto, bob).run { readMessage1(message1); writeMessage2().second }

        assertFalse(first.sendKey.contentEquals(second.sendKey))
    }
}
