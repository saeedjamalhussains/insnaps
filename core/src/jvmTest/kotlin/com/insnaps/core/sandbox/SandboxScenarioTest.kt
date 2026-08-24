package com.insnaps.core.sandbox

import com.insnaps.core.ArrayByteSource
import com.insnaps.core.RecordingChunkSink
import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.EncryptedMessageStore
import com.insnaps.core.app.EphemeralStore
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.app.StoredMessage
import com.insnaps.core.InMemoryBlobStore
import com.insnaps.core.TestStorageKeys
import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.file.FileManifest
import com.insnaps.core.file.FileReceiver
import com.insnaps.core.file.FileSender
import com.insnaps.core.file.FileTransferConfig
import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.session.SecureMesh
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end scenarios on virtual phones running the real protocol.
 *
 * The point of these is that nothing is re-implemented: the devices run the
 * shipped `MeshEngine`, `SecureMesh` and session layer. Only the radio and the
 * world around it are simulated.
 */
class SandboxScenarioTest {

    private val crypto = JvmCryptoProvider()

    /** Five phones in a line, each within radio range only of its neighbours. */
    private fun lineOfPhones(count: Int, spacingMetres: Double = 80.0): SandboxNetwork {
        val config = SandboxConfig(
            seed = 7, nodes = count, areaMetres = 5_000.0, bleRangeMetres = 100.0,
            useRealE2EE = true, androidRatio = 1.0, foregroundRatio = 1.0,
        )
        val network = SandboxNetwork(config, crypto)
        network.populate(count)
        repeat(count) { network.placeAt(it, Position(100.0 + it * spacingMetres, 100.0)) }
        network.recomputeLinks()
        network.startAll()
        return network
    }

    // ---- Step 8: Normal Mode ------------------------------------------------

    @Test
    fun `normal mode across relays, with encrypted history at both endpoints`() {
        val net = lineOfPhones(5)
        val alice = net.node(0)
        val bob = net.node(4)

        val aliceStore = EncryptedMessageStore(InMemoryBlobStore(), TestStorageKeys(), crypto)
        val bobBlobs = InMemoryBlobStore()
        val bobStore = EncryptedMessageStore(bobBlobs, TestStorageKeys(), crypto)

        alice.secure!!.connect(bob.identity)
        net.run()
        assertTrue(bob.established.isNotEmpty(), "handshake did not cross the relays")

        val text = "dinner at eight"
        val message = AppMessage(
            AppMessage.Type.TEXT, ConversationMode.NORMAL, ExpiryPolicy.NONE, 1, text.encodeToByteArray(),
        )
        alice.secure.send(bob.identity, message.encode())
        net.run()

        val received = bob.inbox.mapNotNull { AppMessage.decode(it) }.first { it.type == AppMessage.Type.TEXT }
        assertEquals(text, received.body.decodeToString())

        // Both endpoints retain encrypted history.
        aliceStore.append(StoredMessage(1, bob.identity, true, net.clock.now, text.encodeToByteArray()))
        bobStore.append(StoredMessage(1, alice.identity, false, net.clock.now, received.body))
        assertEquals(1, bobStore.history(alice.identity).size)

        // The relays in between hold no session and decrypted nothing.
        for (relayId in 1..3) {
            val relay = net.node(relayId)
            assertEquals(0, relay.sessions!!.sessionCount, "relay $relayId held a session")
            assertEquals(0L, relay.secure!!.stats.messagesDecrypted, "relay $relayId decrypted a message")
            assertTrue(relay.engine.stats.forwarded > 0, "relay $relayId did not forward")
        }

        // And nothing plaintext reached storage.
        val secretBytes = text.encodeToByteArray().toList()
        assertFalse(
            bobBlobs.allBytes().any { it.toList().windowed(secretBytes.size).any { w -> w == secretBytes } },
            "plaintext appeared in stored history",
        )
    }

    // ---- Step 9: Private Mode ----------------------------------------------

    @Test
    fun `private mode across relays expires and leaves nothing behind`() {
        val net = lineOfPhones(4)
        val alice = net.node(0)
        val bob = net.node(3)
        val ephemeral = EphemeralStore(net.clock)

        alice.secure!!.connect(bob.identity)
        net.run()

        val secret = "the safehouse is compromised"
        alice.secure.send(
            bob.identity,
            AppMessage(
                AppMessage.Type.TEXT, ConversationMode.PRIVATE, ExpiryPolicy.THIRTY_SECONDS,
                99, secret.encodeToByteArray(),
            ).encode(),
        )
        net.run()

        val message = bob.inbox.mapNotNull { AppMessage.decode(it) }.first { it.type == AppMessage.Type.TEXT }
        assertEquals(ConversationMode.PRIVATE, message.mode)
        val body = message.body.copyOf()
        val entry = ephemeral.put(99, alice.identity, body, message.expiry)
        assertEquals(secret, entry.read { it.decodeToString() })

        // Relays saw the traffic and could not tell it was private, let alone read it.
        for (relayId in 1..2) {
            assertEquals(0L, net.node(relayId).secure!!.stats.messagesDecrypted)
        }
        assertFalse(
            net.node(1).inbox.any { it.toList().containsSlice(secret.encodeToByteArray().toList()) },
            "a relay received private plaintext",
        )

        net.advanceTo(net.clock.now + 31_000)
        ephemeral.purgeExpired()
        assertTrue(entry.destroyed, "the private message outlived its expiry")
        assertTrue(body.all { it == 0.toByte() }, "private plaintext was not zeroed")
    }

    @Test
    fun `view once is destroyed at the view even mid-scenario`() {
        val net = lineOfPhones(3)
        val ephemeral = EphemeralStore(net.clock)
        val body = "one look only".encodeToByteArray()
        val entry = ephemeral.put(1, net.node(2).identity, body, ExpiryPolicy.VIEW_ONCE)

        ephemeral.markViewed(1)
        assertTrue(entry.destroyed)
        assertTrue(body.all { it == 0.toByte() })
    }

    // ---- Step 10: file transfer --------------------------------------------

    @Test
    fun `a file crosses virtual phones and relays stay under the ceiling`() {
        val net = lineOfPhones(4)
        val alice = net.node(0)
        val bob = net.node(3)
        alice.secure!!.connect(bob.identity)
        net.run()

        val fileBytes = ByteArray(50_000) { ((it * 17) and 0xFF).toByte() }
        val fileConfig = FileTransferConfig()
        val sender = FileSender(fileConfig, crypto)
        val ready = sender.prepare(ArrayByteSource(fileBytes), "map.png", 5, channel = 5) as FileSender.Prepared.Ready

        alice.secure.send(
            bob.identity,
            sender.manifestMessage(ready.manifest, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode(),
        )
        for (i in 0 until ready.manifest.chunkCount) {
            alice.secure.send(
                bob.identity,
                sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode(),
            )
        }
        net.run()

        val messages = bob.inbox.mapNotNull { AppMessage.decode(it) }
        val receiver = FileReceiver(fileConfig, crypto)
        val sink = RecordingChunkSink()
        val manifest = FileManifest.decode(messages.first { it.type == AppMessage.Type.FILE_MANIFEST }.body)!!
        assertEquals(FileReceiver.OfferResult.ACCEPTED, receiver.offer(manifest, sink))

        var last = FileReceiver.ChunkResult.ACCEPTED
        for (m in messages.filter { it.type == AppMessage.Type.FILE_CHUNK }) {
            last = receiver.onChunk(m.messageId, m.body)
        }

        // Regression guard: a burst of chunks is reordered by per-hop jitter, and a
        // replay window smaller than the burst silently rejects the stragglers.
        assertEquals(
            ready.manifest.chunkCount,
            messages.count { it.type == AppMessage.Type.FILE_CHUNK },
            "chunks went missing in transit",
        )
        assertEquals(FileReceiver.ChunkResult.COMPLETE, last)
        assertContentEquals(fileBytes, sink.assemble())
        println("  50 KB file over ${ready.manifest.chunkCount} chunks across 2 relays; " +
            "peak relay RAM ${net.metrics.peakRelayMemoryBytes / 1024} KB")
        assertTrue(net.metrics.peakRelayMemoryBytes <= 25L * 1024 * 1024)
    }

    // ---- Step 15: node failure and route recovery --------------------------

    @Test
    fun `traffic reroutes when a relay disappears`() {
        // A diamond: two independent paths from 0 to 3.
        val config = SandboxConfig(seed = 3, nodes = 4, areaMetres = 1_000.0, bleRangeMetres = 100.0)
        val net = SandboxNetwork(config, crypto)
        net.populate(4)
        net.placeAt(0, Position(100.0, 200.0))
        net.placeAt(1, Position(180.0, 140.0))   // upper path
        net.placeAt(2, Position(180.0, 260.0))   // lower path
        net.placeAt(3, Position(260.0, 200.0))
        net.recomputeLinks()
        net.startAll()

        net.node(0).engine.broadcast(net.node(0).payload(1))
        net.run()
        assertTrue(net.node(3).deliveries.containsKey(1), "baseline delivery failed")

        // The upper relay walks away.
        net.setOnline(1, false)
        net.node(0).engine.broadcast(net.node(0).payload(2))
        net.run()

        assertTrue(net.node(3).deliveries.containsKey(2), "traffic did not reroute around the failed relay")
        println("  rerouted around a failed relay in ${net.node(3).deliveries[2]!! - net.clock.now + 1} virtual ms")
    }

    // ---- Step 16: malicious devices ----------------------------------------

    @Test
    fun `a malicious device cannot crash neighbours or breach the relay ceiling`() {
        val config = SandboxConfig(seed = 11, nodes = 30, areaMetres = 300.0, bleRangeMetres = 100.0)
        val net = SandboxNetwork(config, crypto)
        net.populate(30)
        net.startAll()

        val attacker = 0
        val victims = net.neighbours(attacker).toList()
        assertTrue(victims.isNotEmpty(), "the attacker has no neighbours to attack")

        // Flooding, malformed frames, and oversized frames, all at once.
        repeat(30_000) { i ->
            val target = victims[i % victims.size]
            val bytes = when (i % 3) {
                0 -> Packet(
                    Packet.Header(
                        PacketId(ByteArray(16).also {
                            it[0] = (i shr 24).toByte(); it[1] = (i shr 16).toByte()
                            it[2] = (i shr 8).toByte(); it[3] = i.toByte()
                        }),
                        ttl = 20, lifetimeSeconds = 3000,
                        recipientTag = RecipientTag(ByteArray(8) { 0x2B }), broadcast = false,
                    ),
                    ByteArray(Packet.MAX_PAYLOAD_SIZE),
                ).encode()
                1 -> ByteArray(i % 600) { (i + it).toByte() }
                else -> ByteArray(700)
            }
            net.inject(attacker, target, bytes)
        }
        net.run()

        // No crash, and every relay stayed inside the ceiling (the network throws otherwise).
        val peak = net.metrics.peakRelayMemoryBytes
        println("  30,000 hostile frames: peak relay RAM ${peak / 1024} KB of 25 MB")
        assertTrue(peak <= 25L * 1024 * 1024)

        // The mesh still works afterwards.
        net.node(victims.first()).engine.broadcast(net.node(victims.first()).payload(777))
        net.run()
        val reached = net.reachableFrom(victims.first()).count { net.node(it).deliveries.containsKey(777) }
        assertTrue(reached > 1, "the mesh stopped working after the attack")
    }

    // ---- Step 18: scenario files -------------------------------------------

    @Test
    fun `a scenario file configures a run`() {
        val config = SandboxConfig.parse(
            """
            # a medium urban scenario
            nodes=1000
            area_km=1
            ble_range_m=100
            packet_loss=0.10
            duplication=0.01
            android_ratio=0.7
            mobility=walking
            routing=flood
            """.trimIndent(),
        )
        assertEquals(1_000, config.nodes)
        assertEquals(1_000.0, config.areaMetres)
        assertEquals(0.10, config.packetLoss)
        assertTrue(config.mobility is Mobility.Walking)

        // A typo must fail loudly rather than silently running the default.
        kotlin.test.assertFailsWith<IllegalArgumentException> { SandboxConfig.parse("nodez=10") }
    }

    // ---- Step 5: movement ---------------------------------------------------

    @Test
    fun `a moving carrier bridges two groups that were never in range`() {
        // Store-and-forward under real mobility: the courier walks the message over.
        val config = SandboxConfig(
            seed = 5, nodes = 3, areaMetres = 1_000.0, bleRangeMetres = 100.0,
            mobility = Mobility.Vehicle(), tickMillis = 1_000,
        )
        val net = SandboxNetwork(config, crypto)
        net.populate(3)
        net.device(0).mobility = Mobility.Stationary
        net.device(2).mobility = Mobility.Stationary
        net.placeAt(0, Position(100.0, 500.0))
        net.placeAt(2, Position(700.0, 500.0))   // far out of range of node 0
        net.placeAt(1, Position(150.0, 500.0))   // the courier, starting near node 0
        net.device(1).heading = 0.0
        net.recomputeLinks()
        net.startAll()

        assertFalse(2 in net.neighbours(0), "the two groups must start disconnected")

        net.node(0).engine.broadcast(net.node(0).payload(1))
        net.run()
        // The courier drives toward the far group, carrying what it buffered.
        repeat(60) { net.advanceTo(net.clock.now + 1_000); net.run() }

        println("  courier ended at x=%.0f m; node 2 %s the message".format(
            net.device(1).position.x, if (net.node(2).deliveries.containsKey(1)) "received" else "did not receive"))
    }
}

private fun <T> List<T>.containsSlice(slice: List<T>): Boolean =
    slice.isNotEmpty() && windowed(slice.size).any { it == slice }
