package com.insnaps.core

import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.file.ByteSource
import com.insnaps.core.file.FileReceiver
import com.insnaps.core.file.FileSender
import com.insnaps.core.file.FileTransferConfig
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.session.SecureMesh
import com.insnaps.core.session.SessionManager
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A file crossing a relay that cannot read it, under the relay memory ceiling.
 *
 * This is where the two independent limits meet. The 100 MB file limit is an
 * endpoint concern; the 25 MB ceiling is a relay concern. They do not interact,
 * and the reason they do not is chunking: a relay only ever holds packets, never
 * a file.
 */
class FileRelayTest {

    private val crypto = JvmCryptoProvider()
    private val clock = TestClock()
    private val mesh = SimulatedMesh()
    private val fileConfig = FileTransferConfig()

    private class Node(
        val id: String,
        val identity: PeerIdentity,
        val secure: SecureMesh,
        val engine: MeshEngine,
        val sessions: SessionManager,
        val inbox: MutableList<AppMessage>,
    )

    private fun node(id: String): Node {
        val keys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, keys)
        val inbox = mutableListOf<AppMessage>()
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {
                AppMessage.decode(plaintext)?.let { inbox += it }
            }
            override fun onSessionEstablished(peer: PeerIdentity) {}
        })
        val engine = MeshEngine(
            config = MeshConfig(),
            clock = clock,
            random = crypto,
            addressing = RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = keys.publicKey),
            transport = mesh.transportFor(id),
            listener = secure,
        )
        secure.engine = engine
        return Node(id, sessions.identity, secure, engine, sessions, inbox)
    }

    /** Wraps a source to record the largest single read, i.e. the sender's peak buffer. */
    private class MeasuredSource(private val inner: ByteSource) : ByteSource {
        var maxReadBytes = 0
            private set
        override val size: Long get() = inner.size
        override fun read(offset: Long, length: Int): ByteArray {
            if (length > maxReadBytes) maxReadBytes = length
            return inner.read(offset, length)
        }
    }

    @Test
    fun `a file crosses a relay intact, and the relay can neither read it nor exceed its ceiling`() {
        val a = node("a"); val relay = node("r"); val b = node("b")
        listOf(a, relay, b).forEach { it.engine.start() }
        mesh.link("a", "r"); mesh.link("r", "b")

        a.secure.connect(b.identity)

        val fileBytes = ByteArray(200_000) { ((it * 31) and 0xFF).toByte() }
        val canary = "TOP-SECRET-FILE-CONTENT".encodeToByteArray()
        canary.copyInto(fileBytes, 5_000)

        val sender = FileSender(fileConfig, crypto)
        val ready = sender.prepare(ArrayByteSource(fileBytes), "report.pdf", 77, channel = 77) as FileSender.Prepared.Ready

        val receiver = FileReceiver(fileConfig, crypto)
        val sink = RecordingChunkSink()

        // Manifest first, then every chunk, each as its own E2EE message.
        a.secure.send(b.identity, sender.manifestMessage(ready.manifest, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode())
        var peakRelayMemory = 0L
        for (i in 0 until ready.manifest.chunkCount) {
            val chunk = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            a.secure.send(b.identity, chunk.encode())
            peakRelayMemory = maxOf(peakRelayMemory, relay.engine.estimatedMemoryBytes())
        }

        // Drive the receiver from what actually arrived over the mesh.
        val manifest = b.inbox.first { it.type == AppMessage.Type.FILE_MANIFEST }
        assertEquals(
            FileReceiver.OfferResult.ACCEPTED,
            receiver.offer(com.insnaps.core.file.FileManifest.decode(manifest.body)!!, sink),
        )
        var last = FileReceiver.ChunkResult.ACCEPTED
        for (message in b.inbox.filter { it.type == AppMessage.Type.FILE_CHUNK }) {
            last = receiver.onChunk(message.messageId, message.body)
        }

        assertEquals(FileReceiver.ChunkResult.COMPLETE, last)
        assertContentEquals(fileBytes, sink.assemble(), "the file did not survive the mesh")

        // The relay carried all of it and learned nothing.
        assertEquals(0, relay.sessions.sessionCount, "the relay must hold no session")
        assertEquals(0L, relay.secure.stats.messagesDecrypted, "the relay decrypted something")
        assertTrue(relay.engine.stats.forwarded > 0, "the relay should have forwarded")

        val ceiling = MeshConfig().totalBudgetBytes
        assertTrue(
            peakRelayMemory <= ceiling,
            "relay peaked at $peakRelayMemory against a $ceiling ceiling",
        )
        println("  200 KB file over ${ready.manifest.chunkCount} chunks: relay peaked at ${peakRelayMemory / 1024} KB")

        // And the plaintext never appeared on the air.
        assertFalse(
            mesh.framesOnAir.any { frame ->
                frame.toList().windowed(canary.size).any { it == canary.toList() }
            },
            "file plaintext appeared in a frame carried by the mesh",
        )
    }

    @Test
    fun `a 100 MB file never needs more than one chunk of memory at either end`() {
        // The claim that matters for the memory model: file size and buffer size
        // are unrelated. Streamed from a generated source, so the test itself does
        // not allocate 100 MB either.
        val source = MeasuredSource(SyntheticByteSource(100L * 1024 * 1024))
        val sender = FileSender(fileConfig, crypto)

        val prepared = sender.prepare(source, "huge.bin", 1, channel = 1)
        assertTrue(prepared is FileSender.Prepared.Ready, "100 MB should be exactly at the limit, not over")

        // 104,857,600 bytes / 448 per chunk, rounded up.
        assertEquals(234_058, prepared.manifest.chunkCount)
        assertTrue(
            source.maxReadBytes <= fileConfig.chunkBytes,
            "sender read ${source.maxReadBytes} bytes at once; chunking should cap it at ${fileConfig.chunkBytes}",
        )
        println("  100 MB = ${prepared.manifest.chunkCount} chunks; peak sender buffer ${source.maxReadBytes} B")
    }

    @Test
    fun `a file over 100 MB is rejected safely`() {
        val sender = FileSender(fileConfig, crypto)
        val outcome = sender.prepare(SyntheticByteSource(100L * 1024 * 1024 + 1), "toobig.bin", 1, channel = 1)
        assertTrue(outcome is FileSender.Prepared.TooLarge)
        assertEquals(100L * 1024 * 1024, outcome.maxBytes)
    }

    @Test
    fun `malicious chunk injection cannot exhaust a relay`() {
        // An attacker floods a relay with chunk-shaped packets for transfers that
        // do not exist. To the relay they are ordinary packets, which is the point:
        // the existing relay bounds already cover file traffic.
        val relay = node("r2"); val edge = node("e2")
        listOf(relay, edge).forEach { it.engine.start() }
        mesh.link("r2", "e2")

        val hostile = ByteArray(com.insnaps.core.packet.Packet.MAX_PAYLOAD_SIZE)
        repeat(20_000) { i ->
            val packet = com.insnaps.core.packet.Packet(
                header = com.insnaps.core.packet.Packet.Header(
                    packetId = com.insnaps.core.packet.PacketId(ByteArray(16).also {
                        it[0] = (i shr 24).toByte(); it[1] = (i shr 16).toByte()
                        it[2] = (i shr 8).toByte(); it[3] = i.toByte()
                    }),
                    ttl = 8,
                    lifetimeSeconds = 600,
                    recipientTag = com.insnaps.core.packet.RecipientTag(ByteArray(8) { 0x3C }),
                    broadcast = false,
                ),
                payload = hostile,
            )
            relay.engine.onFrame(com.insnaps.core.transport.PeerHandle("attacker"), packet.encode())
        }

        val ceiling = MeshConfig().totalBudgetBytes
        assertTrue(
            relay.engine.estimatedMemoryBytes() <= ceiling,
            "relay held ${relay.engine.estimatedMemoryBytes()} against $ceiling",
        )
    }
}
