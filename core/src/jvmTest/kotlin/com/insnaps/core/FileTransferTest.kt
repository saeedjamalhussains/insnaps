package com.insnaps.core

import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.file.FileManifest
import com.insnaps.core.file.FileReceiver
import com.insnaps.core.file.FileSender
import com.insnaps.core.file.FileTransferConfig
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Chunked file transfer over the E2EE mesh.
 *
 * The properties under test are that a file arrives intact, that neither endpoint
 * needs the whole file in memory, and that every way a transfer can go wrong --
 * corruption, reordering, duplication, replay, truncation, oversize -- produces a
 * reported outcome rather than a bad file or a crash.
 */
class FileTransferTest {

    private val crypto = JvmCryptoProvider()
    private val config = FileTransferConfig()
    private val sender = FileSender(config, crypto)
    private fun receiver(cfg: FileTransferConfig = config) = FileReceiver(cfg, crypto)

    private fun prepared(bytes: ByteArray, name: String = "photo.jpg"): FileSender.Prepared.Ready =
        sender.prepare(ArrayByteSource(bytes), name, transferId = 7, channel = 7) as FileSender.Prepared.Ready

    /** Sends every chunk of a prepared transfer into a receiver, in order. */
    private fun transferAll(
        ready: FileSender.Prepared.Ready,
        receiver: FileReceiver,
        sink: RecordingChunkSink,
    ): FileReceiver.ChunkResult {
        assertEquals(FileReceiver.OfferResult.ACCEPTED, receiver.offer(ready.manifest, sink))
        var last = FileReceiver.ChunkResult.ACCEPTED
        for (i in 0 until ready.manifest.chunkCount) {
            val message = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            last = receiver.onChunk(ready.manifest.transferId, message.body)
        }
        return last
    }

    @Test
    fun `a one kilobyte file arrives intact`() {
        val data = Random(1).nextBytes(1024)
        val ready = prepared(data)
        val sink = RecordingChunkSink()

        assertEquals(FileReceiver.ChunkResult.COMPLETE, transferAll(ready, receiver(), sink))
        assertTrue(sink.completed)
        assertContentEquals(data, sink.assemble())
    }

    @Test
    fun `files of many sizes round trip`() {
        // Boundary sizes around the chunk size are where off-by-one errors live.
        for (size in listOf(1, 2, 447, 448, 449, 895, 896, 897, 5_000, 100_000)) {
            val data = Random(size).nextBytes(size)
            val sink = RecordingChunkSink()
            assertEquals(
                FileReceiver.ChunkResult.COMPLETE,
                transferAll(prepared(data), receiver(), sink),
                "size $size did not complete",
            )
            assertContentEquals(data, sink.assemble(), "size $size came back wrong")
        }
    }

    @Test
    fun `every chunk fits inside one packet`() {
        // The whole design rests on this: a chunk must never need fragmenting.
        val ready = prepared(Random(2).nextBytes(10_000))
        for (i in 0 until ready.manifest.chunkCount) {
            val message = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            assertTrue(
                message.body.size <= AppMessage.MAX_BODY_SIZE,
                "chunk $i body ${message.body.size} exceeds ${AppMessage.MAX_BODY_SIZE}",
            )
            assertTrue(message.encode().size <= com.insnaps.core.session.SecureMesh.MAX_PLAINTEXT_SIZE)
        }
    }

    @Test
    fun `a file over the limit is rejected without being read`() {
        val small = FileTransferConfig(maxFileBytes = 1024)
        val outcome = FileSender(small, crypto).prepare(SyntheticByteSource(1025), "big.bin", 1, channel = 1)
        assertTrue(outcome is FileSender.Prepared.TooLarge)
        assertEquals(1024L, outcome.maxBytes)
    }

    @Test
    fun `a file of exactly the limit is accepted`() {
        val exact = FileTransferConfig(maxFileBytes = 4096)
        val outcome = FileSender(exact, crypto).prepare(SyntheticByteSource(4096), "exact.bin", 1, channel = 1)
        assertTrue(outcome is FileSender.Prepared.Ready, "the boundary must be inclusive")
    }

    @Test
    fun `a receiver rejects a manifest claiming more than the limit`() {
        // The sender's check is not enough: the manifest comes from the network.
        val manifest = FileManifest(1, config.maxFileBytes + 1, 448, 1, ByteArray(32), "huge.bin", channel = 9)
        assertEquals(FileReceiver.OfferResult.TOO_LARGE, receiver().offer(manifest, RecordingChunkSink()))
    }

    @Test
    fun `a receiver rejects an inconsistent manifest`() {
        // Claiming a small file with a huge chunk count would let a sender stream
        // unbounded chunks into an accepted transfer.
        val lying = FileManifest(1, 1000, 448, 100_000, ByteArray(32), "lie.bin", channel = 9)
        assertEquals(FileReceiver.OfferResult.INVALID, receiver().offer(lying, RecordingChunkSink()))
    }

    @Test
    fun `out of order chunks reassemble correctly`() {
        val data = Random(3).nextBytes(10_000)
        val ready = prepared(data)
        val sink = RecordingChunkSink()
        val receiver = receiver()
        receiver.offer(ready.manifest, sink)

        val indices = (0 until ready.manifest.chunkCount).shuffled(Random(9))
        var last = FileReceiver.ChunkResult.ACCEPTED
        for (i in indices) {
            val m = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            last = receiver.onChunk(ready.manifest.transferId, m.body)
        }
        assertEquals(FileReceiver.ChunkResult.COMPLETE, last)
        assertContentEquals(data, sink.assemble())
    }

    @Test
    fun `duplicate and replayed chunks are ignored`() {
        val data = Random(4).nextBytes(3_000)
        val ready = prepared(data)
        val sink = RecordingChunkSink()
        val receiver = receiver()
        receiver.offer(ready.manifest, sink)

        val first = sender.chunkMessage(ready.manifest, ready.source, 0, ConversationMode.NORMAL, ExpiryPolicy.NONE)
        assertEquals(FileReceiver.ChunkResult.ACCEPTED, receiver.onChunk(7, first.body))
        // The mesh legitimately delivers the same packet by several paths.
        repeat(5) { assertEquals(FileReceiver.ChunkResult.DUPLICATE, receiver.onChunk(7, first.body)) }

        for (i in 1 until ready.manifest.chunkCount) {
            val m = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            receiver.onChunk(7, m.body)
        }
        assertContentEquals(data, sink.assemble())
    }

    @Test
    fun `a corrupted chunk is caught by the digest and the output discarded`() {
        val data = Random(5).nextBytes(5_000)
        val ready = prepared(data)
        val sink = RecordingChunkSink()
        val receiver = receiver()
        receiver.offer(ready.manifest, sink)

        var last = FileReceiver.ChunkResult.ACCEPTED
        for (i in 0 until ready.manifest.chunkCount) {
            val m = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            val body = if (i == 2) m.body.copyOf().also { it[10] = (it[10] + 1).toByte() } else m.body
            last = receiver.onChunk(7, body)
        }

        assertEquals(FileReceiver.ChunkResult.DIGEST_MISMATCH, last)
        assertTrue(sink.discarded, "a corrupted transfer must not be presented as a file")
        assertTrue(!sink.completed)
    }

    @Test
    fun `a chunk of the wrong size is rejected`() {
        val ready = prepared(Random(6).nextBytes(2_000))
        val receiver = receiver()
        receiver.offer(ready.manifest, RecordingChunkSink())
        val m = sender.chunkMessage(ready.manifest, ready.source, 0, ConversationMode.NORMAL, ExpiryPolicy.NONE)
        assertEquals(FileReceiver.ChunkResult.WRONG_SIZE, receiver.onChunk(7, m.body.copyOf(m.body.size - 5)))
    }

    @Test
    fun `an out of range chunk index is rejected`() {
        val ready = prepared(Random(7).nextBytes(1_000))
        val receiver = receiver()
        receiver.offer(ready.manifest, RecordingChunkSink())
        val body = byteArrayOf(0x7F, 0x7F, 0x7F, 0x7F) + ByteArray(448)
        assertEquals(FileReceiver.ChunkResult.OUT_OF_RANGE, receiver.onChunk(7, body))
    }

    @Test
    fun `chunks for an unknown transfer are ignored`() {
        assertEquals(FileReceiver.ChunkResult.UNKNOWN_TRANSFER, receiver().onChunk(999, ByteArray(452)))
    }

    @Test
    fun `an interrupted transfer leaves nothing behind`() {
        val ready = prepared(Random(8).nextBytes(10_000))
        val sink = RecordingChunkSink()
        val receiver = receiver()
        receiver.offer(ready.manifest, sink)
        repeat(3) { i ->
            val m = sender.chunkMessage(ready.manifest, ready.source, i, ConversationMode.NORMAL, ExpiryPolicy.NONE)
            receiver.onChunk(7, m.body)
        }
        assertEquals(3 to ready.manifest.chunkCount, receiver.progress(7))

        assertTrue(receiver.cancel(7))
        assertTrue(sink.discarded, "a cancelled transfer must clean up its partial output")
        assertNull(receiver.progress(7))
    }

    @Test
    fun `concurrent transfers are bounded`() {
        val receiver = receiver(FileTransferConfig(maxConcurrentTransfers = 3))
        repeat(3) { i ->
            val m = FileManifest(i.toLong(), 448, 448, 1, ByteArray(32), "f$i", channel = 100 + i)
            assertEquals(FileReceiver.OfferResult.ACCEPTED, receiver.offer(m, RecordingChunkSink()))
        }
        val extra = FileManifest(99, 448, 448, 1, ByteArray(32), "f99", channel = 9)
        assertEquals(FileReceiver.OfferResult.TOO_MANY_TRANSFERS, receiver.offer(extra, RecordingChunkSink()))
    }

    @Test
    fun `a manifest claiming the message channel is rejected`() {
        // Channel 0 carries conversation and keeps window-based replay protection.
        // A transfer must not be able to route its chunks through it.
        val hijack = FileManifest(1, 448, 448, 1, ByteArray(32), "hijack.bin", channel = 0)
        assertEquals(FileReceiver.OfferResult.INVALID, receiver().offer(hijack, RecordingChunkSink()))
        assertNull(FileManifest.decode(hijack.encode()), "channel 0 must not survive decoding either")
    }

    @Test
    fun `a manifest round trips and rejects garbage`() {
        val manifest = FileManifest(42, 10_000, 448, 23, ByteArray(32) { it.toByte() }, "holiday photo.jpg", channel = 9)
        assertEquals(manifest, FileManifest.decode(manifest.encode()))
        assertNull(FileManifest.decode(ByteArray(0)))
        assertNull(FileManifest.decode(manifest.encode().copyOf(20)))
        assertNull(FileManifest.decode(manifest.encode() + ByteArray(3)))
        for (size in 0..80) FileManifest.decode(ByteArray(size) { (it * 11).toByte() })
    }

    @Test
    fun `the file name fits inside one packet`() {
        val longName = "a".repeat(FileManifest.MAX_NAME_BYTES)
        val manifest = FileManifest(1, 448, 448, 1, ByteArray(32), longName, channel = 9)
        assertTrue(manifest.encode().size <= AppMessage.MAX_BODY_SIZE)
        assertNotNull(FileManifest.decode(manifest.encode()))
    }

    @Test
    fun `an empty file is reported rather than transferred`() {
        assertTrue(sender.prepare(ArrayByteSource(ByteArray(0)), "empty.txt", 1, channel = 1) is FileSender.Prepared.Empty)
    }
}
