package com.insnaps.core.sandbox

import com.insnaps.core.RecordingChunkSink
import com.insnaps.core.SyntheticByteSource
import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.file.ByteSource
import com.insnaps.core.file.FileManifest
import com.insnaps.core.file.FileReceiver
import com.insnaps.core.file.FileSender
import com.insnaps.core.file.FileTransferConfig
import com.insnaps.core.session.SecureMesh
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * v0.8: file transfer across a geographically simulated multi-hop mesh.
 *
 * The question these answer is not "can a file be encrypted" but the one that
 * ties the requirements together: **can a large file cross a real-shaped network
 * with loss, reordering, duplication and churn while every relay stays under
 * 25 MB?**
 *
 * Chunks travel on their own session channel, so the message replay window never
 * sees them and arbitrary reordering is judged by the transfer's own per-chunk
 * bookkeeping.
 */
class ChunkedTransferTest {

    private val crypto = JvmCryptoProvider()
    private val fileConfig = FileTransferConfig()

    private companion object {
        /** Stands in for the manifest acknowledgement the protocol does not yet have. */
        const val MANIFEST_ATTEMPTS = 8
    }

    /** A line of phones, each in range only of its neighbours, running real E2EE. */
    private fun line(count: Int, loss: Double = 0.0, duplication: Double = 0.0): SandboxNetwork {
        val config = SandboxConfig(
            seed = 21, nodes = count, areaMetres = 5_000.0, bleRangeMetres = 100.0,
            useRealE2EE = true, androidRatio = 1.0, foregroundRatio = 1.0,
            packetLoss = loss, duplicationRate = duplication,
            bandwidthBytesPerSecond = 0, minLatencyMillis = 5, maxLatencyMillis = 30,
        )
        val net = SandboxNetwork(config, crypto)
        net.populate(count)
        repeat(count) { net.placeAt(it, Position(100.0 + it * 80.0, 100.0)) }
        net.recomputeLinks()
        net.startAll()
        return net
    }

    /**
     * Drives one transfer end to end, resending whatever is missing.
     *
     * Resend rounds are how a large transfer survives a lossy link: the receiver
     * reports the chunk indices it lacks and the sender resends exactly those,
     * rather than restarting a 100 MB file because one packet was dropped.
     */
    private class TransferRun(
        val completed: Boolean,
        val rounds: Int,
        val chunksSent: Int,
        val peakRelayBytes: Long,
    )

    /**
     * Establishes a session, retrying the handshake.
     *
     * Nothing in the protocol retransmits a handshake. Over three hops at 30% loss
     * a two-message exchange completes maybe one time in eight, and every
     * subsequent send then returns `NoSession` with no indication of why. Retrying
     * here stands in for the retransmission the protocol needs; see the open items.
     */
    private fun connectWithRetry(net: SandboxNetwork, from: SandboxNode, to: SandboxNode, attempts: Int = 60): Int {
        // `connect` suppresses duplicates, so retransmission is driven by `tick`
        // rather than by calling connect again -- which is the point of the v0.8.1
        // supervisor: the caller no longer implements its own retry loop.
        from.secure!!.connect(to.identity)
        var sent = 1
        repeat(attempts) {
            net.run()
            if (from.sessions!!.sessionFor(to.identity) != null && to.established.isNotEmpty()) return sent
            net.advanceTo(net.clock.now + 2_000)
            val before = from.secure.stats.handshakeRetries
            from.secure.tick()
            if (from.secure.stats.handshakeRetries > before) sent++
        }
        net.run()
        return if (from.sessions!!.sessionFor(to.identity) != null) sent else -1
    }

    private fun runTransfer(
        net: SandboxNetwork,
        source: ByteSource,
        name: String,
        transferId: Long,
        channel: Int,
        maxRounds: Int = 12,
        sink: RecordingChunkSink = RecordingChunkSink(keepBytes = false),
    ): TransferRun {
        val senderNode = net.node(0)
        val receiverNode = net.node(net.deviceCount - 1)

        val attempts = connectWithRetry(net, senderNode, receiverNode)
        check(attempts > 0) { "handshake did not complete after retries" }

        val senderSecure = senderNode.secure!!
        val sender = FileSender(fileConfig, crypto)
        val ready = sender.prepare(source, name, transferId, channel) as FileSender.Prepared.Ready
        val receiver = FileReceiver(fileConfig, crypto)

        // The manifest goes on the message channel; the receiver then opens the
        // transfer's channel before any chunk can decrypt.
        //
        // It is retried, because the manifest is a single point of failure: lose
        // that one packet and the transfer never starts, with no chunk able to be
        // interpreted. On a 30% loss link a single attempt frequently vanishes.
        // A production implementation needs a manifest acknowledgement rather than
        // blind retries; this loop stands in for it so the chunk path can be tested.
        var manifestMessage: AppMessage? = null
        for (attempt in 1..MANIFEST_ATTEMPTS) {
            senderSecure.send(
                receiverNode.identity,
                sender.manifestMessage(ready.manifest, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode(),
            )
            net.run()
            manifestMessage = receiverNode.inbox.mapNotNull { AppMessage.decode(it) }
                .firstOrNull { it.type == AppMessage.Type.FILE_MANIFEST }
            if (manifestMessage != null) break
        }
        if (manifestMessage == null) return TransferRun(false, 0, 0, net.metrics.peakRelayMemoryBytes)
        val manifest = FileManifest.decode(manifestMessage.body)!!
        check(receiver.offer(manifest, sink) == FileReceiver.OfferResult.ACCEPTED)
        receiverNode.sessions!!.sessionFor(senderNode.identity)!!.openChannel(manifest.channel)

        var chunksSent = 0
        var rounds = 0
        var toSend: List<Int> = (0 until ready.manifest.chunkCount).toList()

        while (toSend.isNotEmpty() && rounds < maxRounds) {
            rounds++
            receiverNode.inbox.clear()
            for (index in toSend) {
                senderSecure.send(
                    receiverNode.identity,
                    sender.chunkMessage(ready.manifest, ready.source, index, ConversationMode.NORMAL, ExpiryPolicy.NONE)
                        .encode(),
                    manifest.channel,
                )
                chunksSent++
            }
            net.run()

            for (message in receiverNode.inbox.mapNotNull { AppMessage.decode(it) }) {
                if (message.type == AppMessage.Type.FILE_CHUNK) receiver.onChunk(message.messageId, message.body)
            }
            toSend = receiver.missingChunks(transferId)
        }

        return TransferRun(
            completed = receiver.isComplete(transferId) && sink.completed,
            rounds = rounds,
            chunksSent = chunksSent,
            peakRelayBytes = net.metrics.peakRelayMemoryBytes,
        )
    }

    // ---- the size matrix ---------------------------------------------------

    @Test
    fun `files from 1 KB to 10 MB cross a lossy multi-hop mesh`() {
        println("\n=== transfers across 4 phones, 5% loss, 2% duplication ===")
        println("  %-10s %-9s %-8s %-8s %s".format("size", "chunks", "rounds", "sent", "peak relay RAM"))

        for ((label, size) in listOf(
            "1 KB" to 1_024L,
            "28 KB" to 28L * 1024,
            "100 KB" to 100L * 1024,
            "1 MB" to 1024L * 1024,
            "10 MB" to 10L * 1024 * 1024,
        )) {
            val net = line(4, loss = 0.05, duplication = 0.02)
            val chunks = ((size + 447) / 448).toInt()
            val run = runTransfer(net, SyntheticByteSource(size), "f.bin", 1, channel = 11)

            println("  %-10s %-9d %-8d %-8d %.3f MB".format(
                label, chunks, run.rounds, run.chunksSent, run.peakRelayBytes / 1024.0 / 1024.0))

            assertTrue(run.completed, "$label did not complete after ${run.rounds} rounds")
            assertTrue(run.peakRelayBytes <= 25L * 1024 * 1024, "$label breached the relay ceiling")
        }
    }

    /**
     * The requirement-joining test: 100 MB across a multi-hop mesh, relays bounded.
     *
     * Run without loss so it finishes in one pass -- 234,058 chunks through several
     * resend rounds would take the suite into minutes for no extra insight, since
     * the lossy path is already covered above at 10 MB. What this establishes is
     * that transfer size and relay memory are genuinely unrelated.
     */
    @Test
    fun `a 100 MB file crosses a multi-hop mesh with every relay under 25 MB`() {
        val net = line(4)
        val size = 100L * 1024 * 1024
        val started = System.currentTimeMillis()
        val run = runTransfer(net, SyntheticByteSource(size), "huge.bin", 42, channel = 99, maxRounds = 2)
        val seconds = (System.currentTimeMillis() - started) / 1000.0

        println("\n  100 MB across 4 phones (2 relays): ${run.chunksSent} chunks, " +
            "peak relay RAM %.3f MB, %.0fs wall clock".format(run.peakRelayBytes / 1024.0 / 1024.0, seconds))

        assertTrue(run.completed, "the 100 MB transfer did not complete")
        assertEquals(234_058, run.chunksSent)
        assertTrue(
            run.peakRelayBytes <= 25L * 1024 * 1024,
            "relay peaked at ${run.peakRelayBytes} carrying a 100 MB file",
        )
    }

    // ---- adversarial and edge cases ----------------------------------------

    @Test
    fun `a chunk replayed after the transfer completes cannot decrypt`() {
        // The reason chunks get their own channel: once the transfer ends the
        // channel closes, and a captured chunk is refused before any key is used.
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val session = receiver.sessions!!.sessionFor(sender.identity)!!
        assertTrue(session.openChannel(55))
        assertTrue(session.isChannelOpen(55))

        val sealed = sender.sessions!!.sessionFor(receiver.identity)!!.seal("chunk".encodeToByteArray(), 0, 55)
        assertTrue(session.open(sealed, 0) != null, "an open channel should decrypt")

        session.closeChannel(55)
        assertNull(session.open(sealed, 0), "a chunk replayed after the transfer must not decrypt")
    }

    @Test
    fun `arbitrary reordering at burst scale is not mistaken for replay`() {
        // The v0.7 defect, now structurally impossible: chunks never touch the
        // message replay window.
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val outbound = sender.sessions!!.sessionFor(receiver.identity)!!
        val inbound = receiver.sessions!!.sessionFor(sender.identity)!!
        inbound.openChannel(77)

        val frames = (0 until 5_000).map { outbound.seal(byteArrayOf(it.toByte()), 0, 77) }
        val accepted = frames.shuffled(kotlin.random.Random(3)).count { inbound.open(it, 0) != null }

        assertEquals(5_000, accepted, "only $accepted of 5,000 fully shuffled chunks decrypted")
    }

    @Test
    fun `the message channel still rejects replays`() {
        // Decoupling file transfer must not weaken conversation replay protection.
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val outbound = sender.sessions!!.sessionFor(receiver.identity)!!
        val inbound = receiver.sessions!!.sessionFor(sender.identity)!!
        val frame = outbound.seal("once".encodeToByteArray(), 0)

        assertTrue(inbound.open(frame, 0) != null)
        assertNull(inbound.open(frame, 0), "a replayed message must still be rejected")
    }

    @Test
    fun `an unopened channel is refused before any key is used`() {
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val outbound = sender.sessions!!.sessionFor(receiver.identity)!!
        val inbound = receiver.sessions!!.sessionFor(sender.identity)!!
        val frame = outbound.seal("chunk".encodeToByteArray(), 0, 1234)

        assertNull(inbound.open(frame, 0), "a chunk on an unopened channel must be refused")
    }

    @Test
    fun `open channels are bounded so transfers cannot be opened without limit`() {
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val inbound = receiver.sessions!!.sessionFor(sender.identity)!!
        val opened = (1..100).count { inbound.openChannel(it) }
        assertTrue(opened <= 16, "opened $opened channels")
    }

    @Test
    fun `simultaneous transfers to the same peer stay separate`() {
        val net = line(3)
        val sender = net.node(0)
        val receiver = net.node(2)
        sender.secure!!.connect(receiver.identity)
        net.run()

        val outbound = sender.sessions!!.sessionFor(receiver.identity)!!
        val inbound = receiver.sessions!!.sessionFor(sender.identity)!!
        inbound.openChannel(1); inbound.openChannel(2)

        // Both transfers start at counter 0 on their own channels; the nonce is
        // channel||counter, so they cannot collide.
        val a = outbound.seal("transfer A".encodeToByteArray(), 0, 1)
        val b = outbound.seal("transfer B".encodeToByteArray(), 0, 2)

        assertEquals("transfer A", inbound.open(a, 0)?.decodeToString())
        assertEquals("transfer B", inbound.open(b, 0)?.decodeToString())
    }

    @Test
    fun `handshake and manifest both need retransmission on a lossy path`() {
        // Two real gaps, recorded rather than hidden by the harness:
        //
        //  1. Nothing retransmits a handshake. Over three hops at 30% loss the
        //     two-message exchange rarely completes first time, and every later
        //     send then returns NoSession with no indication of why.
        //  2. Nothing retransmits the manifest. It is the only message that
        //     explains what the chunks are, so losing it means the transfer never
        //     starts even though the chunks arrive fine.
        //
        // Both are application-layer concerns and are listed as open items.
        val net = line(4, loss = 0.30)
        val sender = net.node(0)
        val receiver = net.node(3)
        val handshakeAttempts = connectWithRetry(net, sender, receiver)
        println("\n  handshake over 3 hops at 30% loss took $handshakeAttempts attempts")
        assertTrue(handshakeAttempts > 0, "the handshake never completed even with retries")

        val fileSender = FileSender(fileConfig, crypto)
        val ready = fileSender.prepare(SyntheticByteSource(10_000), "m.bin", 1, channel = 44)
            as FileSender.Prepared.Ready

        var delivered = 0
        repeat(10) {
            receiver.inbox.clear()
            sender.secure!!.send(
                receiver.identity,
                fileSender.manifestMessage(ready.manifest, ConversationMode.NORMAL, ExpiryPolicy.NONE).encode(),
            )
            net.run()
            if (receiver.inbox.mapNotNull { AppMessage.decode(it) }.any { it.type == AppMessage.Type.FILE_MANIFEST }) {
                delivered++
            }
        }
        println("  manifest delivery at 30% loss: $delivered of 10 single attempts arrived")
        assertTrue(delivered < 10, "at 30% loss some manifests should be lost; got $delivered/10")
    }

    @Test
    fun `an interrupted transfer resumes from what is missing`() {
        // 30% loss per hop over three hops leaves roughly a 34% end-to-end success
        // rate, so each round clears about a third of what remains and the tail
        // decays geometrically. Reaching zero takes far more rounds than intuition
        // suggests -- which is the real cost of having no per-chunk acknowledgement.
        val net = line(4, loss = 0.30)
        val sink = RecordingChunkSink(keepBytes = false)
        val run = runTransfer(net, SyntheticByteSource(200_000), "resume.bin", 8, channel = 33,
            maxRounds = 40, sink = sink)

        println("\n  200 KB at 30% loss/hop: completed=${run.completed} after ${run.rounds} resend rounds, " +
            "${run.chunksSent} chunk sends for 447 chunks (%.1fx overhead)"
                .format(run.chunksSent / 447.0))
        assertTrue(run.completed, "the transfer never completed in ${run.rounds} rounds")
        assertTrue(run.rounds > 1, "30% loss should have required at least one resend round")
        assertTrue(run.peakRelayBytes <= 25L * 1024 * 1024)
    }
}
