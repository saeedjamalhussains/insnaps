package com.insnaps.core

import com.insnaps.core.app.BlobStore
import com.insnaps.core.app.StorageKeyProvider
import com.insnaps.core.file.ByteSource
import com.insnaps.core.file.ChunkSink

/**
 * In-memory stand-in for platform storage.
 *
 * Deliberately keeps the raw bytes it was given, so a test can inspect exactly
 * what would have hit the disk and assert that no plaintext appears there.
 */
class InMemoryBlobStore : BlobStore {
    val contents = LinkedHashMap<String, ByteArray>()

    override fun put(key: String, value: ByteArray) { contents[key] = value }
    override fun get(key: String): ByteArray? = contents[key]
    override fun delete(key: String) { contents.remove(key) }
    override fun keys(prefix: String): List<String> = contents.keys.filter { it.startsWith(prefix) }.sorted()
    override fun clear() = contents.clear()

    /** Everything that would have been written, for leak assertions. */
    fun allBytes(): List<ByteArray> = contents.values.toList()
}

/** Fixed storage key. A real provider reads one from the Keystore or Keychain. */
class TestStorageKeys(private val key: ByteArray = ByteArray(32) { (it * 7 + 1).toByte() }) : StorageKeyProvider {
    override fun storageKey(): ByteArray = key
}

/**
 * A file that is generated rather than stored.
 *
 * Lets a test stream 100 MB without allocating 100 MB, which is the same property
 * the real sender relies on: bytes are produced a chunk at a time.
 */
class SyntheticByteSource(override val size: Long, private val seed: Int = 1) : ByteSource {
    override fun read(offset: Long, length: Int): ByteArray {
        require(offset >= 0 && offset + length <= size) { "read out of range" }
        return ByteArray(length) { i -> byteAt(offset + i) }
    }

    fun byteAt(position: Long): Byte = ((position * 31 + seed) and 0xFF).toByte()
}

/** A source backed by a real array, for small files. */
class ArrayByteSource(private val data: ByteArray) : ByteSource {
    override val size: Long get() = data.size.toLong()
    override fun read(offset: Long, length: Int): ByteArray =
        data.copyOfRange(offset.toInt(), offset.toInt() + length)
}

/** Collects what a receiver wrote, and records how it finished. */
class RecordingChunkSink(private val keepBytes: Boolean = true) : ChunkSink {
    val written = LinkedHashMap<Int, ByteArray>()
    var totalBytes = 0L
        private set
    var completed = false
        private set
    var discarded = false
        private set

    override fun write(index: Int, offset: Long, bytes: ByteArray) {
        if (keepBytes) written[index] = bytes
        totalBytes += bytes.size
    }

    override fun complete() { completed = true }
    override fun discard() { discarded = true; written.clear() }

    /** Reassembles what was written, for small transfers. */
    fun assemble(): ByteArray = written.entries.sortedBy { it.key }.fold(ByteArray(0)) { acc, e -> acc + e.value }
}
