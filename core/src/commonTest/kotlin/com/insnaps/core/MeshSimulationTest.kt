package com.insnaps.core

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * End-to-end multi-hop tests over a simulated radio environment.
 *
 * Every one of these runs on the JVM with no device, emulator, radio or SDK.
 * That is the payoff of keeping the transport boundary narrow: the routing,
 * relaying and expiry behaviour of the real protocol is exercised here.
 */
class MeshSimulationTest {

    private val clock = TestClock()
    private val mesh = SimulatedMesh()

    private class Node(
        val id: String,
        val engine: MeshEngine,
        val secrets: TestSecrets,
        val received: MutableList<String>,
    )

    private fun node(id: String, config: MeshConfig = MeshConfig()): Node {
        val secrets = TestSecrets()
        val received = mutableListOf<String>()
        val listener = object : MeshEngine.MeshListener {
            override fun onMessageDelivered(ciphertext: ByteArray, broadcast: Boolean) {
                received += ciphertext.decodeToString()
            }
        }
        val engine = MeshEngine(
            config = config,
            clock = clock,
            random = TestRandom(id.hashCode().toLong()),
            addressing = RotatingTagAddressing(secrets, TestMac(), clock),
            transport = mesh.transportFor(id),
            listener = listener,
        )
        return Node(id, engine, secrets, received)
    }

    /** Gives two nodes a session with each other, as a key exchange would. */
    private fun pair(a: Node, b: Node) {
        val shared = secret("${a.id}-${b.id}")
        a.secrets.add(identity(b.id), shared)
        b.secrets.add(identity(a.id), shared)
    }

    private fun chain(vararg nodes: Node) {
        nodes.forEach { it.engine.start() }
        nodes.toList().zipWithNext { a, b -> mesh.link(a.id, b.id) }
    }

    @Test
    fun `a message crosses four hops to reach its recipient`() {
        val a = node("a"); val b = node("b"); val c = node("c"); val d = node("d"); val e = node("e")
        pair(a, e)
        chain(a, b, c, d, e)

        a.engine.send(PeerIdentity("e".encodeToByteArray()), "ciphertext".encodeToByteArray())

        assertEquals(listOf("ciphertext"), e.received)
    }

    @Test
    fun `relays in the middle never deliver a message that is not theirs`() {
        val a = node("a"); val b = node("b"); val c = node("c"); val d = node("d"); val e = node("e")
        pair(a, e)
        chain(a, b, c, d, e)

        a.engine.send(PeerIdentity("e".encodeToByteArray()), "ciphertext".encodeToByteArray())

        // The relays forwarded it, and none of them could tell it was addressed to them.
        for (relay in listOf(b, c, d)) {
            assertTrue(relay.received.isEmpty(), "${relay.id} should not have delivered the message locally")
            assertTrue(relay.engine.stats.forwarded > 0, "${relay.id} should have forwarded it")
            assertEquals(0L, relay.engine.stats.delivered)
        }
    }

    @Test
    fun `the hop limit stops a message short of a too distant recipient`() {
        val config = MeshConfig(defaultTtl = 3)
        val a = node("a", config); val b = node("b", config); val c = node("c", config)
        val d = node("d", config); val e = node("e", config)
        pair(a, e)
        chain(a, b, c, d, e)

        a.engine.send(PeerIdentity("e".encodeToByteArray()), "too far".encodeToByteArray())

        assertTrue(e.received.isEmpty(), "a 3-hop limit must not cross a 4-hop chain")
        assertEquals(1L, d.engine.stats.hopLimitDropped, "the last relay should have dropped it")
    }

    @Test
    fun `a broadcast reaches every node exactly once`() {
        val nodes = ('a'..'f').map { node(it.toString()) }
        nodes.forEach { it.engine.start() }
        // A dense mesh: every node linked to every other. Without duplicate
        // suppression this topology is what turns one packet into a storm.
        for (i in nodes.indices) for (j in i + 1 until nodes.size) mesh.link(nodes[i].id, nodes[j].id)

        nodes.first().engine.broadcast("all hands".encodeToByteArray())

        for (n in nodes.drop(1)) {
            assertEquals(listOf("all hands"), n.received, "${n.id} should receive it exactly once")
        }
    }

    @Test
    fun `duplicate suppression keeps a dense mesh from flooding`() {
        val nodes = ('a'..'f').map { node(it.toString()) }
        nodes.forEach { it.engine.start() }
        for (i in nodes.indices) for (j in i + 1 until nodes.size) mesh.link(nodes[i].id, nodes[j].id)

        nodes.first().engine.broadcast("all hands".encodeToByteArray())

        // Duplicate suppression bounds a broadcast to one forward per node, so the
        // traffic is O(nodes x degree) -- not the exponential a cyclic graph would
        // otherwise produce.
        val ceiling = nodes.size * (nodes.size - 1)
        assertTrue(
            mesh.framesSent <= ceiling,
            "sent ${mesh.framesSent} frames for one broadcast across ${nodes.size} nodes (ceiling $ceiling)",
        )
        assertTrue(
            nodes.all { it.engine.stats.forwarded <= 1 },
            "every node must forward a given packet at most once",
        )
        assertTrue(nodes.drop(1).all { it.engine.stats.duplicatesDropped > 0 })
    }

    @Test
    fun `a packet with nowhere to go waits for a route instead of being dropped`() {
        // Store-and-forward under mobility: the sender is alone, then walks into range.
        val a = node("a"); val b = node("b")
        pair(a, b)
        a.engine.start(); b.engine.start()

        a.engine.send(PeerIdentity("b".encodeToByteArray()), "held".encodeToByteArray())
        assertEquals(1, a.engine.pendingCount, "with no neighbour the packet must stay buffered")
        assertTrue(b.received.isEmpty())

        mesh.link("a", "b")

        assertEquals(listOf("held"), b.received, "meeting a peer should release the buffered packet")
        assertEquals(0, a.engine.pendingCount)
    }

    @Test
    fun `a buffered packet is discarded once it expires`() {
        val config = MeshConfig(defaultLifetimeSeconds = 60)
        val a = node("a", config); val b = node("b", config)
        pair(a, b)
        a.engine.start(); b.engine.start()

        a.engine.send(PeerIdentity("b".encodeToByteArray()), "stale".encodeToByteArray())
        assertEquals(1, a.engine.pendingCount)

        clock.advanceSeconds(61)
        a.engine.tick()

        assertEquals(0, a.engine.pendingCount)
        assertEquals(0L, a.engine.bufferedBytes)

        mesh.link("a", "b")
        assertTrue(b.received.isEmpty(), "an expired packet must not be delivered late")
    }

    @Test
    fun `malformed frames from a peer are dropped without disturbing the node`() {
        val a = node("a"); val b = node("b")
        pair(a, b)
        a.engine.start(); b.engine.start()
        mesh.link("a", "b")

        val transport = mesh.transportFor("a")
        repeat(20) { i ->
            transport.send(com.insnaps.core.transport.PeerHandle("b"), ByteArray(i * 3) { it.toByte() })
        }

        assertTrue(b.engine.stats.malformedDropped > 0)
        assertEquals(0L, b.engine.stats.delivered)
        assertEquals(0, b.engine.pendingCount)
    }

    @Test
    fun `stopping a node discards all volatile state`() {
        val a = node("a"); val b = node("b")
        pair(a, b)
        a.engine.start(); b.engine.start()

        a.engine.send(PeerIdentity("b".encodeToByteArray()), "in flight".encodeToByteArray())
        assertTrue(a.engine.pendingCount > 0)

        a.engine.stop()

        assertEquals(0, a.engine.pendingCount)
        assertEquals(0L, a.engine.bufferedBytes)
        assertEquals(0, a.engine.peerCount)
    }
}
