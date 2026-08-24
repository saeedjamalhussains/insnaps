package com.insnaps.core.file

import com.insnaps.core.app.AppMessage
import com.insnaps.core.util.ByteReader
import com.insnaps.core.util.ByteWriter

/**
 * Selective acknowledgement for a transfer, expressed as **ranges**.
 *
 * One acknowledgement per chunk would turn a 234,058-chunk file into 234,058
 * return packets — an ACK storm larger than the traffic it is acknowledging, on a
 * mesh where every packet is forwarded several times. Ranges collapse that: a
 * transfer missing chunks 18 and 4,001–4,003 is two ranges, sixteen bytes,
 * regardless of how large the file is.
 *
 * Missing ranges are sent rather than received ranges, because the missing set is
 * what the sender must act on and is almost always the smaller of the two.
 */
data class TransferAck(
    val transferId: Long,
    /** Inclusive `[first, last]` ranges of chunk indices still outstanding. */
    val missing: List<IntRange>,
    /** True when this is the final acknowledgement and the transfer is complete. */
    val complete: Boolean,
    /**
     * True when the missing set did not fit in one packet.
     *
     * The sender should resend what it was told about and expect a further
     * acknowledgement afterwards, rather than assuming the rest arrived.
     */
    val truncated: Boolean = false,
) {
    fun encode(): ByteArray {
        require(missing.size <= MAX_RANGES) { "too many ranges for one packet: ${missing.size}" }
        val writer = ByteWriter(HEADER_SIZE + missing.size * RANGE_SIZE)
            .u32(transferId ushr 32)
            .u32(transferId and 0xFFFFFFFFL)
            .u8((if (complete) FLAG_COMPLETE else 0) or (if (truncated) FLAG_TRUNCATED else 0))
            .u8(missing.size)
        for (range in missing) {
            writer.u32(range.first.toLong() and 0xFFFFFFFFL)
            writer.u32(range.last.toLong() and 0xFFFFFFFFL)
        }
        return writer.finish()
    }

    companion object {
        const val HEADER_SIZE = 8 + 1 + 1
        const val RANGE_SIZE = 8

        /** How many ranges fit in one packet alongside the application header. */
        val MAX_RANGES = minOf(255, (AppMessage.MAX_BODY_SIZE - HEADER_SIZE) / RANGE_SIZE)

        private const val FLAG_COMPLETE = 0x01
        private const val FLAG_TRUNCATED = 0x02

        fun decode(bytes: ByteArray): TransferAck? {
            if (bytes.size < HEADER_SIZE) return null
            return try {
                val r = ByteReader(bytes)
                val transferId = (r.u32() shl 32) or r.u32()
                val flags = r.u8()
                val count = r.u8()
                if (r.remaining != count * RANGE_SIZE) return null

                val ranges = ArrayList<IntRange>(count)
                repeat(count) {
                    val first = r.u32().toInt()
                    val last = r.u32().toInt()
                    // A reversed or negative range would be nonsense to act on.
                    if (first < 0 || last < first) return null
                    ranges += first..last
                }
                TransferAck(
                    transferId = transferId,
                    missing = ranges,
                    complete = flags and FLAG_COMPLETE != 0,
                    truncated = flags and FLAG_TRUNCATED != 0,
                )
            } catch (_: IllegalArgumentException) {
                null
            }
        }

        /** Collapses a sorted index list into inclusive ranges. */
        fun toRanges(indices: List<Int>): List<IntRange> {
            if (indices.isEmpty()) return emptyList()
            val out = ArrayList<IntRange>()
            var start = indices.first()
            var previous = start
            for (index in indices.drop(1)) {
                if (index == previous + 1) { previous = index; continue }
                out += start..previous
                start = index
                previous = index
            }
            out += start..previous
            return out
        }
    }
}
