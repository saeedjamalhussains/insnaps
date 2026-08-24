package com.insnaps.core.file

import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter

/**
 * Limits for file transfer. Configurable so the ceiling can move without a
 * protocol change -- nothing here appears on the wire except the chunk size,
 * which is carried in the manifest.
 */
data class FileTransferConfig(
    /** Largest file accepted, in bytes. */
    val maxFileBytes: Long = 100L * 1024 * 1024,
    /**
     * Payload bytes per chunk.
     *
     * ## Why this is 448 and not 16-64 KB
     *
     * A chunk has to fit inside one insnaps packet, and a packet carries at most
     * 512 payload bytes, chosen for BLE. After the AEAD seal, the application
     * header and the chunk header there are 459 bytes left, so the chunk is
     * sized just under that.
     *
     * The consequence is worth stating plainly: a 100 MB file is about 234,000
     * packets. At realistic BLE mesh throughput -- single-digit KB/s across a
     * multi-hop path -- that is hours, not minutes. Large transfers are supported
     * by the protocol and are not practical over BLE alone; they need the
     * same-platform Wi-Fi accelerators, and even then only between peers on the
     * same platform. Nothing here should be read as a claim that a 100 MB file
     * moves quickly across a mesh.
     */
    val chunkBytes: Int = DEFAULT_CHUNK_BYTES,
    /** Cap on transfers a receiver will track at once, so an attacker cannot open unlimited ones. */
    val maxConcurrentTransfers: Int = 8,
) {
    init {
        require(maxFileBytes > 0) { "maxFileBytes must be positive" }
        require(chunkBytes in 1..MAX_CHUNK_BYTES) { "chunkBytes must be in 1..$MAX_CHUNK_BYTES" }
        require(maxConcurrentTransfers >= 1)
    }

    val maxChunks: Long get() = (maxFileBytes + chunkBytes - 1) / chunkBytes

    companion object {
        /** Chunk header: a 4-byte index. */
        const val CHUNK_HEADER_SIZE = 4

        /** The most that can fit in one packet after every layer of framing. */
        const val MAX_CHUNK_BYTES = AppMessage.MAX_BODY_SIZE - CHUNK_HEADER_SIZE

        const val DEFAULT_CHUNK_BYTES = 448
    }
}

/**
 * Describes a transfer, sent ahead of the chunks.
 *
 * Carried inside the E2EE payload like everything else, so a relay learns
 * nothing from it -- not the size, not the chunk count, and not the file name.
 * The name is treated as sensitive content rather than metadata, because it
 * frequently is one.
 */
data class FileManifest(
    val transferId: Long,
    val totalBytes: Long,
    val chunkSize: Int,
    val chunkCount: Int,
    /** Chained digest of the plaintext, for end-to-end integrity (see [FileDigest]). */
    val digest: ByteArray,
    val fileName: String,
    /**
     * Session channel the chunks will arrive on.
     *
     * Chunks travel on their own channel so the session's message replay window
     * never sees them. A window is the wrong instrument for a burst of a quarter
     * of a million chunks that the mesh reorders arbitrarily; the receiver's
     * per-chunk bitmap is the right one, because it knows the transfer geometry.
     */
    val channel: Int,
) {
    init {
        require(digest.size == CryptoProvider.HASH_SIZE) { "digest must be ${CryptoProvider.HASH_SIZE} bytes" }
    }

    fun encode(): ByteArray {
        val nameBytes = fileName.encodeToByteArray()
        require(nameBytes.size <= MAX_NAME_BYTES) { "file name too long: ${nameBytes.size} > $MAX_NAME_BYTES" }
        return ByteWriter(FIXED_SIZE + nameBytes.size)
            .u32(transferId ushr 32).u32(transferId and 0xFFFFFFFFL)
            .u32(totalBytes ushr 32).u32(totalBytes and 0xFFFFFFFFL)
            .u32(chunkSize.toLong())
            .u32(chunkCount.toLong())
            .bytes(digest)
            .u32(channel.toLong() and 0xFFFFFFFFL)
            .u8(nameBytes.size)
            .bytes(nameBytes)
            .finish()
    }

    override fun equals(other: Any?): Boolean =
        this === other || (other is FileManifest && transferId == other.transferId &&
            totalBytes == other.totalBytes && chunkSize == other.chunkSize &&
            chunkCount == other.chunkCount && digest.contentEquals(other.digest) &&
            fileName == other.fileName && channel == other.channel)

    override fun hashCode(): Int = transferId.hashCode() * 31 + digest.contentHashCode()

    companion object {
        const val FIXED_SIZE = 8 + 8 + 4 + 4 + CryptoProvider.HASH_SIZE + 4 + 1
        val MAX_NAME_BYTES = minOf(255, AppMessage.MAX_BODY_SIZE - FIXED_SIZE)

        fun decode(bytes: ByteArray): FileManifest? {
            if (bytes.size < FIXED_SIZE) return null
            return try {
                val r = ByteReader(bytes)
                val transferId = (r.u32() shl 32) or r.u32()
                val totalBytes = (r.u32() shl 32) or r.u32()
                val chunkSize = r.u32().toInt()
                val chunkCount = r.u32().toInt()
                val digest = r.bytes(CryptoProvider.HASH_SIZE)
                val channel = r.u32().toInt()
                val nameLength = r.u8()
                if (r.remaining != nameLength) return null
                val name = r.bytes(nameLength).decodeToString()

                if (totalBytes < 0 || chunkSize <= 0 || chunkCount < 0) return null
                // Channel 0 is the message channel; a transfer must not claim it.
                if (channel == 0) return null
                FileManifest(transferId, totalBytes, chunkSize, chunkCount, digest, name, channel)
            } catch (_: IllegalArgumentException) {
                null
            }
        }
    }
}

/**
 * Running digest over a file's plaintext.
 *
 * `h = SHA256(h || chunk)` per chunk, starting from a domain-separated constant.
 * Chained rather than a plain hash of the whole file so it can be computed and
 * verified incrementally: neither endpoint ever needs the file in memory, which
 * is the point of chunking in the first place.
 *
 * Note this is an *integrity* check against corruption and reordering, layered on
 * top of the per-chunk AEAD that already provides authenticity.
 */
class FileDigest(private val crypto: CryptoProvider) {
    private var state: ByteArray = crypto.sha256(CONTEXT)
    private var chunks = 0

    fun update(chunk: ByteArray) {
        state = crypto.sha256(state + chunk)
        chunks++
    }

    fun digest(): ByteArray = state.copyOf()

    private companion object {
        val CONTEXT = "insnaps-file-v1".encodeToByteArray()
    }
}

/** Random access over the file being sent, so the sender never holds it all in memory. */
interface ByteSource {
    val size: Long

    /** Reads exactly [length] bytes at [offset], or fewer at the end of the file. */
    fun read(offset: Long, length: Int): ByteArray
}

/** Where a receiver puts chunks. A platform implementation writes to a file. */
interface ChunkSink {
    fun write(index: Int, offset: Long, bytes: ByteArray)

    /** Called once every chunk has arrived and the digest has verified. */
    fun complete()

    /** Called on failure, expiry or cancellation. Must remove any partial output. */
    fun discard()
}

/**
 * Produces the messages for one outgoing transfer.
 *
 * Stateless with respect to memory: [chunkAt] reads exactly one chunk from the
 * source on demand, so sending a 100 MB file costs one chunk of RAM at a time.
 */
class FileSender(
    private val config: FileTransferConfig,
    private val crypto: CryptoProvider,
) {

    /** Rejection reasons, reported rather than thrown -- file size is user input. */
    sealed interface Prepared {
        data class Ready(val manifest: FileManifest, val source: ByteSource) : Prepared
        data class TooLarge(val actualBytes: Long, val maxBytes: Long) : Prepared
        data object Empty : Prepared
    }

    /**
     * Validates a file and builds its manifest.
     *
     * Computing the digest streams the source one chunk at a time; it never
     * materialises the file.
     */
    fun prepare(source: ByteSource, fileName: String, transferId: Long, channel: Int): Prepared {
        if (source.size > config.maxFileBytes) {
            return Prepared.TooLarge(source.size, config.maxFileBytes)
        }
        if (source.size <= 0) return Prepared.Empty

        val chunkCount = ((source.size + config.chunkBytes - 1) / config.chunkBytes).toInt()
        val digest = FileDigest(crypto)
        var offset = 0L
        while (offset < source.size) {
            val length = minOf(config.chunkBytes.toLong(), source.size - offset).toInt()
            digest.update(source.read(offset, length))
            offset += length
        }

        return Prepared.Ready(
            manifest = FileManifest(
                transferId = transferId,
                totalBytes = source.size,
                chunkSize = config.chunkBytes,
                chunkCount = chunkCount,
                digest = digest.digest(),
                fileName = fileName,
                channel = channel,
            ),
            source = source,
        )
    }

    fun manifestMessage(
        manifest: FileManifest,
        mode: ConversationMode,
        expiry: ExpiryPolicy,
    ): AppMessage = AppMessage(
        type = AppMessage.Type.FILE_MANIFEST,
        mode = mode,
        expiry = expiry,
        messageId = manifest.transferId,
        body = manifest.encode(),
    )

    /** Builds the message for one chunk, reading only that chunk from the source. */
    fun chunkMessage(
        manifest: FileManifest,
        source: ByteSource,
        index: Int,
        mode: ConversationMode,
        expiry: ExpiryPolicy,
    ): AppMessage {
        require(index in 0 until manifest.chunkCount) { "chunk index $index out of range" }
        val offset = index.toLong() * manifest.chunkSize
        val length = minOf(manifest.chunkSize.toLong(), manifest.totalBytes - offset).toInt()
        val data = source.read(offset, length)

        return AppMessage(
            type = AppMessage.Type.FILE_CHUNK,
            mode = mode,
            expiry = expiry,
            messageId = manifest.transferId,
            body = ByteWriter(FileTransferConfig.CHUNK_HEADER_SIZE + data.size)
                .u32(index.toLong())
                .bytes(data)
                .finish(),
        )
    }
}

/**
 * Reassembles incoming transfers.
 *
 * Every failure mode a hostile or unlucky sender can produce is a return value
 * rather than an exception: chunks arrive from the mesh, and the mesh carries
 * whatever anyone sends.
 */
class FileReceiver(
    private val config: FileTransferConfig,
    private val crypto: CryptoProvider,
) {

    enum class ChunkResult {
        ACCEPTED,
        /**
         * Already held.
         *
         * This is the transfer's own replay protection, and it is exact: a chunk
         * index either has been received or has not. Unlike a sliding window it
         * does not care how far out of order the chunk arrived, which is what
         * makes a 234,000-chunk transfer possible over a reordering mesh.
         */
        DUPLICATE,
        UNKNOWN_TRANSFER,
        OUT_OF_RANGE,
        WRONG_SIZE,
        COMPLETE,
        DIGEST_MISMATCH,
    }

    enum class OfferResult { ACCEPTED, TOO_LARGE, INVALID, TOO_MANY_TRANSFERS, DUPLICATE }

    private class Transfer(
        val manifest: FileManifest,
        val sink: ChunkSink,
        val received: BooleanArray,
        val digest: FileDigest,
    ) {
        var receivedCount = 0
        /** Chunks must be digested in order; out-of-order ones wait here. */
        val pending = HashMap<Int, ByteArray>()
        var nextToDigest = 0
    }

    private val transfers = LinkedHashMap<Long, Transfer>()

    val activeCount: Int get() = transfers.size

    /** Channels this receiver currently expects chunks on, for the session to open. */
    fun openChannels(): List<Int> = transfers.values.map { it.manifest.channel }

    /**
     * Chunk indices still outstanding.
     *
     * The basis for resuming an interrupted transfer: the sender resends exactly
     * these rather than starting again, which is what makes a large transfer
     * survivable on a lossy mesh.
     */
    fun missingChunks(transferId: Long, limit: Int = Int.MAX_VALUE): List<Int> {
        val transfer = transfers[transferId] ?: return emptyList()
        val missing = ArrayList<Int>()
        for (i in transfer.received.indices) {
            if (!transfer.received[i]) {
                missing.add(i)
                if (missing.size >= limit) break
            }
        }
        return missing
    }

    fun isComplete(transferId: Long): Boolean = transfers[transferId] == null

    /**
     * Builds a selective acknowledgement for [transferId].
     *
     * Bounded to one packet: if the missing set does not fit, the acknowledgement
     * is marked truncated and the sender resends what it was told about before
     * asking again. That keeps the feedback channel the same size whether the
     * transfer is 3 chunks or 234,058.
     *
     * **The relay is not involved.** This is receiver-side bookkeeping only; a
     * relay never learns a transfer exists, let alone which chunks are missing.
     */
    fun acknowledgement(transferId: Long): TransferAck =
        acknowledgements(transferId, maxPackets = 1).firstOrNull()
            ?: TransferAck(transferId, emptyList(), complete = true)

    /**
     * Builds acknowledgements covering the outstanding chunks, paged across packets.
     *
     * One packet is not enough. Losses on a mesh are scattered rather than
     * contiguous, so the missing set of a large transfer collapses into thousands
     * of single-chunk ranges — far more than the 58 that fit in one packet.
     * Reporting only the first 58 makes repair take `missing / 58` rounds: a
     * 23,000-chunk file at 10% loss per hop over five hops needed **160+ rounds**
     * and never finished within a sane budget.
     *
     * Paging fixes that. A few dozen acknowledgement packets are trivial next to
     * the thousands of chunks they repair, and [maxPackets] keeps the feedback
     * bounded so it can never itself become the traffic problem.
     *
     * **The relay is not involved.** This is receiver-side bookkeeping; a relay
     * never learns a transfer exists, let alone which chunks are missing.
     */
    fun acknowledgements(transferId: Long, maxPackets: Int = DEFAULT_ACK_PACKETS): List<TransferAck> {
        require(maxPackets >= 1)
        val transfer = transfers[transferId]
            ?: return listOf(TransferAck(transferId, emptyList(), complete = true))

        val capacity = maxPackets * TransferAck.MAX_RANGES
        val missing = missingChunks(transferId, limit = MISSING_SCAN_LIMIT)
        val ranges = TransferAck.toRanges(missing)
        val pages = ranges.chunked(TransferAck.MAX_RANGES).take(maxPackets)
        val truncated = ranges.size > capacity || missing.size >= MISSING_SCAN_LIMIT

        return pages.mapIndexed { index, page ->
            TransferAck(
                transferId = transferId,
                missing = page,
                complete = false,
                // Only the last page carries the truncation flag, so a sender knows
                // to ask again after acting on everything it was told.
                truncated = truncated && index == pages.lastIndex,
            )
        }
    }

    /**
     * Accepts or rejects an incoming manifest.
     *
     * This is where an oversized file is stopped -- before a single chunk is
     * buffered, so a hostile sender cannot make the receiver spend memory just by
     * claiming a large transfer.
     */
    fun offer(manifest: FileManifest, sink: ChunkSink): OfferResult {
        if (transfers.containsKey(manifest.transferId)) return OfferResult.DUPLICATE
        if (transfers.size >= config.maxConcurrentTransfers) return OfferResult.TOO_MANY_TRANSFERS
        if (manifest.totalBytes > config.maxFileBytes) return OfferResult.TOO_LARGE
        if (manifest.chunkSize !in 1..FileTransferConfig.MAX_CHUNK_BYTES) return OfferResult.INVALID
        if (manifest.chunkCount < 0 || manifest.chunkCount.toLong() > config.maxChunks) return OfferResult.INVALID
        if (manifest.channel == 0) return OfferResult.INVALID

        // The declared geometry must be internally consistent, or a sender could
        // claim a small file and then stream an unbounded number of chunks.
        val expectedChunks = (manifest.totalBytes + manifest.chunkSize - 1) / manifest.chunkSize
        if (expectedChunks != manifest.chunkCount.toLong()) return OfferResult.INVALID

        transfers[manifest.transferId] = Transfer(
            manifest = manifest,
            sink = sink,
            received = BooleanArray(manifest.chunkCount),
            digest = FileDigest(crypto),
        )
        return OfferResult.ACCEPTED
    }

    /** Feeds one chunk body (`index || data`) into its transfer. */
    fun onChunk(transferId: Long, body: ByteArray): ChunkResult {
        val transfer = transfers[transferId] ?: return ChunkResult.UNKNOWN_TRANSFER
        if (body.size < FileTransferConfig.CHUNK_HEADER_SIZE) return ChunkResult.OUT_OF_RANGE

        val reader = ByteReader(body)
        val index = reader.u32().toInt()
        if (index < 0 || index >= transfer.manifest.chunkCount) return ChunkResult.OUT_OF_RANGE

        val data = reader.bytes(reader.remaining)
        val offset = index.toLong() * transfer.manifest.chunkSize
        val expectedSize = minOf(
            transfer.manifest.chunkSize.toLong(),
            transfer.manifest.totalBytes - offset,
        ).toInt()
        if (data.size != expectedSize) return ChunkResult.WRONG_SIZE

        // A repeated chunk is normal on a mesh -- several paths deliver the same
        // packet -- so it is ignored, not treated as an attack.
        if (transfer.received[index]) return ChunkResult.DUPLICATE

        transfer.received[index] = true
        transfer.receivedCount++
        transfer.sink.write(index, offset, data)
        transfer.pending[index] = data
        drainDigest(transfer)

        if (transfer.receivedCount < transfer.manifest.chunkCount) return ChunkResult.ACCEPTED

        transfers.remove(transferId)
        return if (transfer.digest.digest().contentEquals(transfer.manifest.digest)) {
            transfer.sink.complete()
            ChunkResult.COMPLETE
        } else {
            // Corruption or a substituted chunk. The partial output must not be
            // presented to the user as a file.
            transfer.sink.discard()
            ChunkResult.DIGEST_MISMATCH
        }
    }

    /** Abandons a transfer, discarding partial output. */
    fun cancel(transferId: Long): Boolean {
        val transfer = transfers.remove(transferId) ?: return false
        transfer.pending.clear()
        transfer.sink.discard()
        return true
    }

    fun cancelAll() {
        transfers.values.forEach { it.pending.clear(); it.sink.discard() }
        transfers.clear()
    }

    fun progress(transferId: Long): Pair<Int, Int>? =
        transfers[transferId]?.let { it.receivedCount to it.manifest.chunkCount }

    /**
     * Folds contiguous chunks into the digest.
     *
     * The digest is chained, so chunks must be absorbed in order. Out-of-order
     * arrivals wait in [Transfer.pending] until the gap fills. That buffer is what
     * makes reordering safe, and it is bounded by the number of outstanding gaps.
     */
    private companion object {
        /**
         * How far ahead the missing-chunk scan looks.
         *
         * A transfer that has just started is missing everything, and materialising
         * 234,057 indices to describe that is pointless -- the sender is about to
         * send them anyway. The acknowledgement is a repair mechanism, not a
         * complete inventory.
         */
        const val MISSING_SCAN_LIMIT = 32_768

        /** Acknowledgement packets per round. Bounded so feedback cannot dominate traffic. */
        const val DEFAULT_ACK_PACKETS = 64
    }

    private fun drainDigest(transfer: Transfer) {
        while (true) {
            val next = transfer.pending.remove(transfer.nextToDigest) ?: return
            transfer.digest.update(next)
            transfer.nextToDigest++
        }
    }
}
