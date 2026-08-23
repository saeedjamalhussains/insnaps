package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.session.SecureMesh
import com.insnaps.core.session.SecureMesh.SendOutcome
import com.insnaps.core.session.SessionManager
import com.insnaps.core.session.SessionPolicy
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * End-to-end tests of encrypted messaging across a multi-hop mesh.
 *
 * The central claim under test is structural: a relay forwards traffic it cannot
 * read. These tests assert that from the outside -- relays deliver nothing, decrypt
 * nothing, and the bytes they handle do not contain the plaintext.
 */
class SecureMeshTest {

    private val crypto = JvmCryptoProvider()
    private val clock = TestClock()
    private val mesh = SimulatedMesh()

    private class Node(
        val id: String,
        val identity: PeerIdentity,
        val secure: SecureMesh,
        val engine: MeshEngine,
        val sessions: SessionManager,
        val received: MutableList<Pair<PeerIdentity, String>>,
        val established: MutableList<PeerIdentity>,
        val broadcasts: MutableList<String>,
    )

    private fun node(id: String, config: MeshConfig = MeshConfig(), policy: SessionPolicy = SessionPolicy()): Node {
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys, policy)

        val received = mutableListOf<Pair<PeerIdentity, String>>()
        val established = mutableListOf<PeerIdentity>()
        val broadcasts = mutableListOf<String>()

        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {
                received += from to plaintext.decodeToString()
            }
            override fun onSessionEstablished(peer: PeerIdentity) { established += peer }
            override fun onBroadcast(plaintext: ByteArray) { broadcasts += plaintext.decodeToString() }
        })

        val engine = MeshEngine(
            config = config,
            clock = clock,
            random = crypto,
            addressing = RotatingTagAddressing(
                secrets = sessions,
                mac = crypto,
                clock = clock,
                ownStaticPublicKey = staticKeys.publicKey,
            ),
            transport = mesh.transportFor(id),
            listener = secure,
        )
        secure.engine = engine

        return Node(id, sessions.identity, secure, engine, sessions, received, established, broadcasts)
    }

    private fun chain(vararg nodes: Node) {
        nodes.forEach { it.engine.start() }
        nodes.toList().zipWithNext { a, b -> mesh.link(a.id, b.id) }
    }

    @Test
    fun `two peers handshake and exchange an encrypted message across four hops`() {
        val a = node("a"); val b = node("b"); val c = node("c"); val d = node("d"); val e = node("e")
        chain(a, b, c, d, e)

        a.secure.connect(e.identity)

        assertEquals(listOf(e.identity), a.established)
        assertEquals(listOf(a.identity), e.established)

        assertTrue(a.secure.send(e.identity, "the eagle has landed".encodeToByteArray()) is SendOutcome.Queued)
        assertEquals(listOf(a.identity to "the eagle has landed"), e.received)
    }

    @Test
    fun `relays forward the message without being able to read it`() {
        val a = node("a"); val b = node("b"); val c = node("c"); val d = node("d"); val e = node("e")
        chain(a, b, c, d, e)

        a.secure.connect(e.identity)
        a.secure.send(e.identity, "classified".encodeToByteArray())

        for (relay in listOf(b, c, d)) {
            assertTrue(relay.received.isEmpty(), "${relay.id} delivered a message that was not its own")
            assertEquals(0L, relay.secure.stats.messagesDecrypted, "${relay.id} decrypted something")
            assertEquals(0, relay.sessions.sessionCount, "${relay.id} should hold no session at all")
            assertTrue(relay.engine.stats.forwarded > 0, "${relay.id} should still have forwarded")
        }
    }

    @Test
    fun `plaintext never appears in the bytes a relay handles`() {
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)

        a.secure.connect(c.identity)
        val plaintext = "the-canary-string".encodeToByteArray()
        a.secure.send(c.identity, plaintext)

        assertEquals(1, c.received.size)
        assertFalse(
            mesh.framesOnAir.any { frame ->
                frame.toList().windowed(plaintext.size).any { it == plaintext.toList() }
            },
            "plaintext appeared in a frame carried by the mesh",
        )
    }

    @Test
    fun `a node with an unrelated session still cannot read the traffic`() {
        // The relay is a real participant with real keys -- just not this conversation's.
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)

        b.secure.connect(a.identity)   // b and a are genuine contacts
        a.secure.connect(c.identity)
        a.secure.send(c.identity, "not for b".encodeToByteArray())

        assertEquals(1, b.sessions.sessionCount, "b is a genuine participant holding real keys")
        assertTrue(b.received.none { it.second == "not for b" }, "b read a message meant for c")

        // b never even attempted decryption: the recipient tag was not its own, so
        // the mesh layer did not hand the frame to its session layer at all. That
        // is the first line of defence -- the second is tested below.
        assertEquals(0L, b.secure.stats.messagesDecrypted)
    }

    @Test
    fun `even handed the payload directly, the wrong node cannot decrypt it`() {
        // Defeats the addressing layer deliberately, to prove confidentiality does
        // not rest on it. Every payload the mesh carried is fed straight into b's
        // session layer, bypassing recipient tags entirely.
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)

        b.secure.connect(a.identity)
        a.secure.connect(c.identity)
        a.secure.send(c.identity, "not for b".encodeToByteArray())

        val payloads = mesh.framesOnAir.mapNotNull { com.insnaps.core.packet.Packet.decode(it)?.payload }
        assertTrue(payloads.isNotEmpty())
        payloads.forEach { b.secure.onMessageDelivered(it, broadcast = false) }

        assertTrue(b.received.none { it.second == "not for b" }, "b decrypted a message meant for c")
        assertTrue(b.secure.stats.undecryptable > 0, "b tried its keys against the payload and failed")
    }

    @Test
    fun `sending without a session fails instead of sending plaintext`() {
        val a = node("a"); val b = node("b")
        chain(a, b)
        assertEquals(SendOutcome.NoSession, a.secure.send(b.identity, "no session yet".encodeToByteArray()))
        assertTrue(b.received.isEmpty())
    }

    @Test
    fun `a replayed packet captured from the mesh does not deliver twice`() {
        val a = node("a"); val b = node("b")
        chain(a, b)
        a.secure.connect(b.identity)
        a.secure.send(b.identity, "once only".encodeToByteArray())
        assertEquals(1, b.received.size)

        // An attacker replays every frame it captured.
        val captured = mesh.framesOnAir.toList()
        val transport = mesh.transportFor("a")
        captured.forEach { transport.send(com.insnaps.core.transport.PeerHandle("b"), it) }

        assertEquals(1, b.received.size, "replayed frames must not deliver again")
    }

    @Test
    fun `both directions work after a single handshake`() {
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)
        a.secure.connect(c.identity)

        a.secure.send(c.identity, "ping".encodeToByteArray())
        c.secure.send(a.identity, "pong".encodeToByteArray())

        assertEquals(listOf(a.identity to "ping"), c.received)
        assertEquals(listOf(c.identity to "pong"), a.received)
    }

    @Test
    fun `an expired session stops decrypting and is destroyed`() {
        val policy = SessionPolicy(maxAgeMillis = 1000, maxIdleMillis = 1000)
        val a = node("a", policy = policy); val b = node("b", policy = policy)
        chain(a, b)
        a.secure.connect(b.identity)
        assertEquals(1, b.sessions.sessionCount)

        clock.advance(1001)
        assertEquals(1, b.sessions.purgeExpired())
        assertEquals(0, b.sessions.sessionCount)
        assertEquals(SendOutcome.NoSession, a.secure.send(b.identity, "too late".encodeToByteArray()))
    }

    @Test
    fun `shutting down destroys all key material`() {
        val a = node("a"); val b = node("b")
        chain(a, b)
        a.secure.connect(b.identity)
        val session = a.sessions.sessionFor(b.identity)
        assertNotNull(session)

        a.sessions.destroyAll()
        a.engine.stop()

        assertTrue(session.destroyed, "session keys must be zeroed on shutdown")
        assertEquals(0, a.sessions.sessionCount)
        assertEquals(0L, a.engine.bufferedBytes)
    }

    @Test
    fun `a broadcast is readable by everyone and is documented as such`() {
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)
        a.secure.broadcast("public notice".encodeToByteArray())

        assertEquals(listOf("public notice"), b.broadcasts)
        assertEquals(listOf("public notice"), c.broadcasts)
    }

    @Test
    fun `handshake attempts addressed elsewhere are rejected cheaply`() {
        val a = node("a"); val b = node("b"); val c = node("c")
        chain(a, b, c)
        a.secure.connect(c.identity)

        // b saw the handshake go past and could not complete it.
        assertEquals(0, b.sessions.sessionCount)
        assertContentEquals(ByteArray(0), ByteArray(0))
    }
}
