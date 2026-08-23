package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.session.HandshakeFailure
import com.insnaps.core.session.SecureMesh
import com.insnaps.core.session.SecureMesh.SendOutcome
import com.insnaps.core.session.SessionManager
import com.insnaps.core.transport.PeerHandle
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests that a node survives hostile and malformed input.
 *
 * A mesh node processes bytes from anyone in radio range with no prior
 * relationship, so "an attacker can crash it remotely" is a live threat rather
 * than a theoretical one. Everything here feeds the node input it did not ask for
 * and asserts that it declines rather than dies.
 */
class HostileInputTest {

    private val crypto = JvmCryptoProvider()
    private val clock = TestClock()
    private val mesh = SimulatedMesh()

    private fun victim(id: String = "victim"): Pair<MeshEngine, SessionManager> {
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys)
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {}
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        val engine = MeshEngine(
            config = MeshConfig(),
            clock = clock,
            random = crypto,
            addressing = RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = staticKeys.publicKey),
            transport = mesh.transportFor(id),
            listener = secure,
        )
        secure.engine = engine
        engine.start()
        return engine to sessions
    }

    @Test
    fun `a handshake built from an all-zero point is rejected, not fatal`() {
        // Regression: this crashed the node. X25519 throws IllegalArgumentException
        // on a small-order point, and nothing on the handshake path caught that
        // type -- so 96 bytes of zeros from any peer in range killed the process.
        val (_, sessions) = victim()
        val hostile = ByteArray(32) + ByteArray(48) + ByteArray(16)

        assertFailsWith<HandshakeFailure> { sessions.acceptHandshake(hostile) }
        assertEquals(0, sessions.sessionCount)
    }

    @Test
    fun `a hostile handshake arriving over the mesh does not crash the node`() {
        val (engine, sessions) = victim()
        val hostileEnvelope = byteArrayOf(0x01) + ByteArray(32) + ByteArray(48) + ByteArray(16)

        // Delivered as if it were addressed to us, straight into the session layer.
        engine.onFrame(PeerHandle("attacker"), packetTo(engine, hostileEnvelope))

        assertEquals(0, sessions.sessionCount)
    }

    @Test
    fun `fuzzing the frame decoder never throws`() {
        val (engine, _) = victim()
        val random = Random(20260824)

        repeat(20_000) {
            val size = random.nextInt(0, 600)
            engine.onFrame(PeerHandle("fuzzer-${it % 5}"), random.nextBytes(size))
        }
        assertTrue(engine.stats.malformedDropped > 0)
    }

    @Test
    fun `fuzzing the session layer directly never throws`() {
        // Bypasses the packet decoder, so the envelope and handshake parsers get
        // the raw hostile bytes rather than well-formed packets.
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys)
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {}
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        secure.engine = MeshEngine(
            MeshConfig(), clock, crypto,
            RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = staticKeys.publicKey),
            mesh.transportFor("fuzz-target"), secure,
        ).also { it.start() }

        val random = Random(4242)
        repeat(10_000) {
            val body = random.nextBytes(random.nextInt(0, 200))
            val type = byteArrayOf((it % 5).toByte()) // includes the three real types and two unknown ones
            secure.onMessageDelivered(type + body, broadcast = it % 3 == 0)
        }
        assertEquals(0, sessions.sessionCount)
    }

    @Test
    fun `an oversized message is reported rather than thrown`() {
        // Regression: message length is user input, and an over-long message used
        // to propagate an IllegalArgumentException out of the mesh layer.
        val a = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, a)
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {}
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        secure.engine = MeshEngine(
            MeshConfig(), clock, crypto,
            RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = a.publicKey),
            mesh.transportFor("sender"), secure,
        )

        val huge = ByteArray(SecureMesh.MAX_PLAINTEXT_SIZE + 1)
        val outcome = secure.send(PeerIdentity(crypto.generateX25519KeyPair().publicKey), huge)
        assertTrue(outcome is SendOutcome.TooLarge, "expected TooLarge, got $outcome")
        assertEquals(SecureMesh.MAX_PLAINTEXT_SIZE, outcome.maxBytes)

        val hugeBroadcast = secure.broadcast(ByteArray(SecureMesh.MAX_BROADCAST_SIZE + 1))
        assertTrue(hugeBroadcast is SendOutcome.TooLarge)
    }

    @Test
    fun `a message of exactly the maximum size still fits one packet`() {
        // Guards the arithmetic: if the overhead constants drift, this is where it shows.
        val a = victimNode("a"); val b = victimNode("b")
        b.engine.start(); a.engine.start()
        mesh.link("a", "b")
        a.secure.connect(b.sessions.identity)

        val exact = ByteArray(SecureMesh.MAX_PLAINTEXT_SIZE) { 'x'.code.toByte() }
        assertTrue(a.secure.send(b.sessions.identity, exact) is SendOutcome.Queued)
        assertEquals(1, b.delivered.size)
        assertEquals(SecureMesh.MAX_PLAINTEXT_SIZE, b.delivered.single().size)
    }

    @Test
    fun `a synchronous transport cannot drive flush into unbounded recursion`() {
        // A loopback transport that delivers on the calling thread turns
        // flush -> send -> onFrame -> flush into recursion. The re-entrancy guard
        // is what keeps that from overflowing the stack.
        val loop = LoopbackMesh()
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys)
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {}
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        val engine = MeshEngine(
            MeshConfig(), clock, crypto,
            RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = staticKeys.publicKey),
            loop, secure,
        )
        secure.engine = engine
        engine.start()
        loop.engine = engine

        repeat(200) { engine.broadcast(byteArrayOf(0x03, it.toByte())) }
        assertTrue(loop.frames > 0)
    }

    // ---- helpers -----------------------------------------------------------

    private class Node(val engine: MeshEngine, val sessions: SessionManager, val secure: SecureMesh, val delivered: MutableList<ByteArray>)

    private fun victimNode(id: String): Node {
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys)
        val delivered = mutableListOf<ByteArray>()
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) { delivered += plaintext }
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        val engine = MeshEngine(
            MeshConfig(), clock, crypto,
            RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = staticKeys.publicKey),
            mesh.transportFor(id), secure,
        )
        secure.engine = engine
        return Node(engine, sessions, secure, delivered)
    }

    /** Wraps a payload in a broadcast packet, so it reaches the victim's session layer. */
    private fun packetTo(engine: MeshEngine, payload: ByteArray): ByteArray =
        com.insnaps.core.packet.Packet(
            header = com.insnaps.core.packet.Packet.Header(
                packetId = com.insnaps.core.packet.PacketId(crypto.nextBytes(16)),
                ttl = 4,
                lifetimeSeconds = 60,
                recipientTag = com.insnaps.core.packet.RecipientTag.BROADCAST,
                broadcast = true,
            ),
            payload = payload,
        ).encode()

    /** A transport that hands every sent frame straight back on the calling thread. */
    private class LoopbackMesh : com.insnaps.core.transport.Transport {
        var engine: MeshEngine? = null
        var frames = 0
        private var listener: com.insnaps.core.transport.TransportListener? = null
        override val maxFrameSize = 600

        override fun start(listener: com.insnaps.core.transport.TransportListener) {
            this.listener = listener
            listener.onPeerFound(PeerHandle("echo"))
        }
        override fun stop() { listener = null }
        override fun send(peer: PeerHandle, bytes: ByteArray): Boolean {
            frames++
            listener?.onFrame(PeerHandle("echo-back"), bytes)
            return true
        }
    }
}
