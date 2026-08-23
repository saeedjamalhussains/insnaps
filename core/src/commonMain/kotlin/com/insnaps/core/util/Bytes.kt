package com.insnaps.core.util

/** Minimal big-endian reader with strict bounds checking. */
internal class ByteReader(private val src: ByteArray, private var pos: Int = 0) {
    val remaining: Int get() = src.size - pos

    private fun require(n: Int) {
        if (remaining < n) throw IllegalArgumentException("truncated: need $n byte(s), have $remaining")
    }

    fun u8(): Int { require(1); return src[pos++].toInt() and 0xFF }

    fun u16(): Int { require(2); return (u8() shl 8) or u8() }

    fun u32(): Long { require(4); return (u16().toLong() shl 16) or u16().toLong() }

    fun bytes(n: Int): ByteArray {
        require(n)
        return src.copyOfRange(pos, pos + n).also { pos += n }
    }
}

/** Minimal big-endian writer backed by a fixed-capacity array. */
internal class ByteWriter(capacity: Int) {
    private val buf = ByteArray(capacity)
    private var pos = 0

    fun u8(v: Int) = apply { buf[pos++] = (v and 0xFF).toByte() }

    fun u16(v: Int) = apply { u8(v ushr 8); u8(v) }

    fun u32(v: Long) = apply { u16((v ushr 16).toInt()); u16(v.toInt()) }

    fun bytes(b: ByteArray) = apply { b.copyInto(buf, pos); pos += b.size }

    fun finish(): ByteArray = if (pos == buf.size) buf else buf.copyOf(pos)
}

/** Constant-time equality. Used wherever a comparison is over attacker-supplied bytes. */
fun ByteArray.constantTimeEquals(other: ByteArray): Boolean {
    if (size != other.size) return false
    var diff = 0
    for (i in indices) diff = diff or (this[i].toInt() xor other[i].toInt())
    return diff == 0
}

fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef"
    val out = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        out.append(hex[v ushr 4]).append(hex[v and 0x0F])
    }
    return out.toString()
}
