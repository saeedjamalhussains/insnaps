package com.insnaps.core.sim

import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * What a hostile participant can do to the mesh.
 *
 * A mesh node accepts bytes from anyone in radio range, so every one of these is
 * a realistic attack rather than a hypothetical: an attacker needs a phone and
 * proximity, nothing else.
 */
class AdversarialTest {

    private fun hostilePacket(seed: Int, broadcast: Boolean = true, payloadSize: Int = Packet.MAX_PAYLOAD_SIZE) =
        Packet(
            header = Packet.Header(
                packetId = PacketId(ByteArray(PacketId.SIZE).also {
                    it[0] = (seed shr 24).toByte(); it[1] = (seed shr 16).toByte()
                    it[2] = (seed shr 8).toByte(); it[3] = seed.toByte()
                }),
                ttl = 24,
                lifetimeSeconds = 3000,
                recipientTag = if (broadcast) RecipientTag.BROADCAST else RecipientTag(ByteArray(8) { 0x7F }),
                broadcast = broadcast,
            ),
            payload = ByteArray(payloadSize),
        ).encode()

    @Test
    fun `a flooding attacker cannot exhaust a victim's memory`() {
        // Two nodes only. The victim's sole neighbour is the attacker, and a packet
        // is never forwarded back to its source -- so the victim has nowhere to
        // offload and the traffic accumulates. This is the case the per-peer quota
        // exists for: a node at the edge of the mesh being buried by its one link.
        // (With somewhere to forward, the buffer drains and no pressure builds.)
        val network = SimNetwork(101)
        Topology.line(network, 2)
        network.startAll()

        val victim = network.node(1)
        val attacker = 0

        // 100,000 distinct maximum-size packets: about 54 MB of traffic aimed at a
        // node whose entire budget is 25 MB.
        repeat(100_000) { network.inject(attacker, 1, hostilePacket(it, broadcast = false)) }
        network.run()

        val ceiling = network.config.meshConfig.totalBudgetBytes
        println("  flood: victim held ${victim.engine.estimatedMemoryBytes() / 1024}KB, " +
            "quotaDropped=${victim.engine.stats.quotaDropped}")

        assertTrue(
            victim.engine.estimatedMemoryBytes() <= ceiling,
            "victim held ${victim.engine.estimatedMemoryBytes()} against a $ceiling ceiling",
        )
        assertTrue(victim.engine.stats.quotaDropped > 0, "the per-peer quota never engaged")
    }

    @Test
    fun `a flood from one peer does not stop traffic from others`() {
        // The point of the per-peer quota: an attacker gets its slice, not the mesh.
        val network = SimNetwork(202)
        Topology.normal(network, 100)
        network.startAll()

        val victimId = 1
        val attacker = network.neighbours(victimId).first()
        repeat(3_000) { network.inject(attacker, victimId, hostilePacket(it, broadcast = false)) }
        network.runSteps(20_000)

        // Legitimate broadcast, mid-flood.
        network.node(0).engine.broadcast(network.node(0).payload(999))
        network.run()

        val reached = (1 until 100).count { network.node(it).deliveries.containsKey(999) }
        println("  under flood: legitimate broadcast reached $reached/99 nodes")
        assertTrue(reached >= 95, "the flood suppressed legitimate traffic: only $reached nodes reached")
    }

    @Test
    fun `duplicate cache exhaustion does not crash or unbound memory`() {
        val network = SimNetwork(303)
        Topology.line(network, 3)
        network.startAll()

        val victim = network.node(1)
        val attacker = 0
        val cacheSize = network.config.meshConfig.duplicateCacheEntries

        // Five times the cache capacity in unique ids, which is the cheapest way to
        // attack it: packet ids are attacker-chosen and cost nothing to mint.
        repeat(cacheSize * 5) { network.inject(attacker, 1, hostilePacket(it)) }
        network.run()

        println("  dup-cache attack: victim mem=${victim.engine.estimatedMemoryBytes() / 1024}KB")
        assertTrue(victim.engine.estimatedMemoryBytes() <= network.config.meshConfig.totalBudgetBytes)
    }

    @Test
    fun `relay buffer exhaustion degrades gracefully`() {
        // A star centred on the victim: several attackers, and forwarding cannot
        // escape past the leaves.
        val network = SimNetwork(404)
        Topology.star(network, spokes = 8)
        network.startAll()

        val victimId = 0
        val attackers = (1..8).toList()
        repeat(60_000) { i ->
            network.inject(attackers[i % attackers.size], victimId, hostilePacket(i, broadcast = false))
        }
        network.run()

        val victim = network.node(victimId)
        assertTrue(victim.engine.estimatedMemoryBytes() <= network.config.meshConfig.totalBudgetBytes)
        assertTrue(victim.engine.stats.framesReceived > 0)
    }

    @Test
    fun `no remotely supplied packet can crash a node`() {
        // The headline safety property. Random bytes, truncated packets, valid
        // headers with junk payloads, and oversized frames, all from peers.
        val network = SimNetwork(505)
        Topology.normal(network, 100)
        network.startAll()
        val random = Random(505)

        repeat(20_000) { i ->
            val target = 1 + random.nextInt(99)
            val source = network.neighbours(target).random(random)
            val bytes = when (i % 4) {
                0 -> random.nextBytes(random.nextInt(0, 600))
                1 -> hostilePacket(i).copyOf(random.nextInt(1, 100))
                2 -> hostilePacket(i).also { it[random.nextInt(it.size)] = random.nextInt(256).toByte() }
                else -> random.nextBytes(700) // over the maximum packet size
            }
            network.inject(source, target, bytes)
        }
        network.run()

        val stats = network.aggregateStats()
        println("  fuzz: received=${stats.framesReceived} malformed=${stats.malformedDropped}")
        assertTrue(stats.malformedDropped > 0)

        // And the mesh still works afterwards.
        network.node(0).engine.broadcast(network.node(0).payload(1))
        network.run()
        val reached = (1 until 100).count { network.node(it).deliveries.containsKey(1) }
        assertTrue(reached >= 95, "mesh degraded after the fuzz run: $reached/99")
    }

    @Test
    fun `hop limit contains a packet with a forged maximum ttl`() {
        // A line longer than the hop limit, because that is the only topology where
        // the limit is what stops a packet. In a small-world graph the diameter is
        // a handful of hops and duplicate suppression terminates a flood long
        // before the 24-hop limit is approached -- the limit is a backstop against
        // pathological topologies, not the mechanism that normally ends a flood.
        val network = SimNetwork(606)
        Topology.line(network, 40)
        network.startAll()

        val attacker = 0
        repeat(20) { network.inject(attacker, 1, hostilePacket(it)) }
        network.run()

        val stats = network.aggregateStats()
        assertTrue(stats.hopLimitDropped > 0, "nothing was ever stopped by the hop limit")

        // TTL 24 from a line of 40: the far end is out of reach by construction.
        assertTrue(network.node(39).deliveries.isEmpty(), "a packet outran its hop limit")
        assertTrue(network.peakNodeMemory() <= network.config.meshConfig.totalBudgetBytes)
    }
}
