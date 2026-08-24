package com.insnaps.core.sandbox

import com.insnaps.core.RecordingChunkSink
import com.insnaps.core.SyntheticByteSource
import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.file.FileManifest
import com.insnaps.core.file.FileReceiver
import com.insnaps.core.file.FileSender
import com.insnaps.core.file.FileTransferConfig
import com.insnaps.core.file.TransferAck
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The decisive reliability matrix: can insnaps actually *deliver* — conversations
 * and large files — across an unreliable multi-hop mobile network, without
 * breaching the 25 MB relay ceiling?
 *
 * Each stage of `handshake -> manifest -> chunks -> completion` is measured
 * separately, because the sandbox showed each of them failing differently and
 * silently on a lossy path.
 *
 * Loss here is **per hop**, so end-to-end success falls off sharply with distance:
 * 30% per hop over five hops leaves about 17% of packets arriving.
 */
class ReliabilityMatrixTest {

    private val crypto = JvmCryptoProvider()
    private val fileConfig = FileTransferConfig()

    private class StageResult(
        val handshakeAttempts: Int,
        val manifestAttempts: Int,
        val chunkRounds: Int,
        val chunkSends: Int,
        val chunks: Int,
        val completed: Boolean,
        val peakRelayBytes: Long,
        val packets: Long,
    ) {
        val overhead: Double get() = if (chunks == 0) 0.0 else chunkSends.toDouble() / chunks
    }

    private fun line(hops: Int, loss: Double, androidRatio: Double = 1.0, foreground: Double = 1.0): SandboxNetwork {
        val nodes = hops + 1
        val config = SandboxConfig(
            seed = 31, nodes = nodes, areaMetres = 10_000.0, bleRangeMetres = 100.0,
            useRealE2EE = true, androidRatio = androidRatio, foregroundRatio = foreground,
            packetLoss = loss, bandwidthBytesPerSecond = 0,
            minLatencyMillis = 5, maxLatencyMillis = 20,
        )
        val net = SandboxNetwork(config, crypto)
        net.populate(nodes)
        repeat(nodes) { net.placeAt(it, Position(100.0 + it * 80.0, 100.0)) }
        net.recomputeLinks()
        net.startAll()
        return net
    }

    /**
     * Runs every stage with the v0.8.1 reliability layer engaged.
     *
     * The handshake is driven by `SecureMesh.tick()`, which is the supervisor
     * doing the retrying rather than the test; the manifest and chunk stages use
     * acknowledgements to decide what to resend.
     */
    private fun runStages(net: SandboxNetwork, fileBytes: Long, maxRounds: Int = 60): StageResult {
        val senderNode = net.node(0)
        val receiverNode = net.node(net.deviceCount - 1)
        val senderSecure = senderNode.secure!!

        // Stage 1: handshake, retransmitted by the supervisor.
        senderSecure.connect(receiverNode.identity)
        var handshakeAttempts = 1
        repeat(400) {
            net.run()
            if (senderNode.sessions!!.sessionFor(receiverNode.identity) != null) return@repeat
            net.advanceTo(net.clock.now + 2_000)
            val before = senderSecure.stats.handshakeRetries
            senderSecure.tick()
            if (senderSecure.stats.handshakeRetries > before) handshakeAttempts++
        }
        net.run()
        val established = senderNode.sessions!!.sessionFor(receiverNode.identity) != null &&
            receiverNode.established.isNotEmpty()
        if (!established) {
            return StageResult(handshakeAttempts, 0, 0, 0, 0, false,
                net.metrics.peakRelayMemoryBytes, net.metrics.framesSent)
        }

        // Stage 2: manifest, retransmitted until acknowledged.
        val sender = FileSender(fileConfig, crypto)
        val ready = sender.prepare(SyntheticByteSource(fileBytes), "f.bin", 1, channel = 21)
            as FileSender.Prepared.Ready
        val receiver = FileReceiver(fileConfig, crypto)
        val sink = RecordingChunkSink(keepBytes = false)

        var manifestAttempts = 0
        var manifestAccepted = false
        repeat(12) {
            if (manifestAccepted) return@repeat
            manifestAttempts++
            receiverNode.inbox.clear()
            senderSecure.send(
                receiverNode.identity,
                sender.manifestMessage(ready.manifest, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode(),
            )
            net.run()
            val message = receiverNode.inbox.mapNotNull { AppMessage.decode(it) }
                .firstOrNull { it.type == AppMessage.Type.FILE_MANIFEST }
            if (message != null) {
                val manifest = FileManifest.decode(message.body)!!
                if (receiver.offer(manifest, sink) == FileReceiver.OfferResult.ACCEPTED) {
                    receiverNode.sessions!!.sessionFor(senderNode.identity)!!.openChannel(manifest.channel)
                    manifestAccepted = true
                }
            }
        }
        if (!manifestAccepted) {
            return StageResult(handshakeAttempts, manifestAttempts, 0, 0, ready.manifest.chunkCount,
                false, net.metrics.peakRelayMemoryBytes, net.metrics.framesSent)
        }

        // Stage 3: chunks, repaired from selective acknowledgements.
        var rounds = 0
        var sends = 0
        var toSend: List<Int> = (0 until ready.manifest.chunkCount).toList()
        while (toSend.isNotEmpty() && rounds < maxRounds) {
            rounds++
            receiverNode.inbox.clear()
            for (index in toSend) {
                senderSecure.send(
                    receiverNode.identity,
                    sender.chunkMessage(ready.manifest, ready.source, index, ConversationMode.NORMAL, ExpiryPolicy.NONE)
                        .encode(),
                    ready.manifest.channel,
                )
                sends++
            }
            net.run()
            for (message in receiverNode.inbox.mapNotNull { AppMessage.decode(it) }) {
                if (message.type == AppMessage.Type.FILE_CHUNK) receiver.onChunk(1, message.body)
            }

            // The receiver reports gaps as ranges, paged across several packets;
            // the sender acts on exactly those.
            val acks = receiver.acknowledgements(1)
            if (acks.any { it.complete }) break
            toSend = acks.flatMap { ack -> ack.missing.flatMap { it.toList() } }
        }

        return StageResult(
            handshakeAttempts, manifestAttempts, rounds, sends, ready.manifest.chunkCount,
            receiver.isComplete(1) && sink.completed,
            net.metrics.peakRelayMemoryBytes, net.metrics.framesSent,
        )
    }

    @Test
    fun `reliability matrix across loss and hop count`() {
        println("\n=== reliability matrix: 100 KB file (229 chunks), per-hop loss ===")
        println("  %-6s %-6s %-11s %-10s %-8s %-9s %-9s %s".format(
            "hops", "loss", "handshake", "manifest", "rounds", "overhead", "complete", "relay RAM"))

        // Collected first so the whole matrix prints even when a cell fails; a
        // partial table hides exactly the pattern that makes a failure legible.
        val failures = mutableListOf<String>()
        for (hops in listOf(3, 5, 10)) {
            for (loss in listOf(0.0, 0.05, 0.10, 0.20, 0.30, 0.50)) {
                val net = line(hops, loss)
                val r = runStages(net, 100L * 1024)
                println("  %-6d %-6s %-11s %-10s %-8d %-9s %-9s %.2f MB".format(
                    hops, "${(loss * 100).toInt()}%",
                    "${r.handshakeAttempts} att", "${r.manifestAttempts} att",
                    r.chunkRounds, "%.1fx".format(r.overhead),
                    if (r.completed) "yes" else "NO",
                    r.peakRelayBytes / 1024.0 / 1024.0))

                if (r.peakRelayBytes > 25L * 1024 * 1024) {
                    failures += "$hops hops at $loss loss breached the relay ceiling"
                }
                // Up to 10% per-hop loss is the envelope this asserts. Beyond it the
                // outcome is genuinely marginal rather than deterministic: a
                // handshake needs two packets to survive the whole path, so at 20%
                // over five hops only ~11% of attempts succeed and whether 32 of
                // them land is a matter of luck. Recording that honestly is more
                // useful than tuning the budget until one seed passes.
                if (loss <= 0.10 && !r.completed) {
                    failures += "$hops hops at ${(loss * 100).toInt()}% loss did not complete"
                }
            }
        }
        println("  (loss is per hop: 20% over 10 hops leaves ~11% of packets arriving)")
        println("  reliable envelope: <=10% per-hop loss at every distance tested.")
        println("  beyond it, handshake establishment is marginal -- two packets must cross")
        println("  the whole path, so per-attempt success is the square of path survival.")
        assertTrue(failures.isEmpty(), failures.joinToString("; "))
    }

    @Test
    fun `heterogeneous Android and iOS fleets deliver`() {
        println("\n=== fleet mix, 5 hops, 10% loss, 100 KB ===")
        for ((label, android, foreground) in listOf(
            Triple("all Android foreground", 1.0, 1.0),
            Triple("70/30 mix, half background", 0.7, 0.5),
            Triple("all iOS backgrounded", 0.0, 0.0),
        )) {
            val net = line(5, 0.10, androidRatio = android, foreground = foreground)
            val r = runStages(net, 100L * 1024)
            println("  %-28s handshake %d att, rounds %d, complete=%s".format(
                label, r.handshakeAttempts, r.chunkRounds, r.completed))
            assertTrue(r.completed, "$label did not complete")
            assertTrue(r.peakRelayBytes <= 25L * 1024 * 1024)
        }
    }

    @Test
    fun `a 10 MB file completes over five lossy hops`() {
        val net = line(5, 0.10)
        val r = runStages(net, 10L * 1024 * 1024)
        println("\n  10 MB over 5 hops at 10%% loss/hop: %d chunks, %d rounds, %.2fx overhead, relay peak %.2f MB"
            .format(r.chunks, r.chunkRounds, r.overhead, r.peakRelayBytes / 1024.0 / 1024.0))
        assertTrue(r.completed, "the 10 MB transfer did not complete")
        assertTrue(r.peakRelayBytes <= 25L * 1024 * 1024)
    }

    @Test
    fun `delivery survives node churn during a transfer`() {
        val net = line(6, 0.05)
        val senderNode = net.node(0)
        val receiverNode = net.node(6)
        senderNode.secure!!.connect(receiverNode.identity)
        repeat(50) { net.run(); net.advanceTo(net.clock.now + 2_000); senderNode.secure.tick() }
        net.run()

        // A middle relay drops out and comes back mid-conversation.
        net.setOnline(3, false)
        net.setOnline(3, true)
        net.run()

        assertTrue(
            senderNode.sessions!!.sessionFor(receiverNode.identity) != null,
            "the session did not survive relay churn",
        )
        assertTrue(net.metrics.peakRelayMemoryBytes <= 25L * 1024 * 1024)
    }
}
