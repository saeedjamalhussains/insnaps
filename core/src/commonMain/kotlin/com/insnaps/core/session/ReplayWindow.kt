package com.insnaps.core.session

/**
 * Sliding-window replay protection over per-session message counters (RFC 6479 style).
 *
 * The mesh delivers packets out of order and duplicates them by design -- the same
 * message legitimately arrives by several paths -- so a strictly increasing
 * counter check would drop valid traffic. A window accepts reordering up to
 * [WINDOW_SIZE] while still rejecting any counter it has already seen.
 *
 * ## Why the window is 1024 and not 64
 *
 * A 64-message window is ample for conversation, and far too small for a file.
 * File chunks are emitted as a burst, and per-hop latency jitter reorders that
 * burst arbitrarily, so a transfer of more than a window's worth of chunks loses
 * whatever falls off the back -- silently, and as a replay rejection rather than
 * an error. Sandbox runs showed exactly 64 of 112 chunks surviving.
 *
 * The window therefore has to be at least as large as the reordering a burst can
 * produce. 1024 costs 128 bytes per session and covers a burst comfortably;
 * beyond that, a sender should pace its chunks rather than expect an unbounded
 * window.
 *
 * This is separate from, and additional to, the mesh-layer duplicate cache: that
 * one suppresses re-forwarding of a packet id and is a bandwidth measure, while
 * this one is a cryptographic guarantee that a captured message cannot be
 * replayed into the session later.
 */
class ReplayWindow {

    private var highestSeen: Long = -1

    /** One bit per counter position, indexed as a ring by `counter % WINDOW_SIZE`. */
    private val bitmap = LongArray(WORDS)

    /**
     * Records [counter] and reports whether it is acceptable.
     *
     * Returns false for a counter already seen, or one so old it has fallen out
     * of the window. A rejected counter does not advance any state.
     */
    fun accept(counter: Long): Boolean {
        if (counter < 0) return false

        if (counter > highestSeen) {
            val advance = counter - highestSeen
            if (advance >= WINDOW_SIZE) {
                // The whole window has moved past; nothing old remains valid.
                bitmap.fill(0L)
            } else {
                // Clear the positions the window has just swept over, so a counter
                // from a previous lap cannot be mistaken for one already seen.
                var position = highestSeen + 1
                while (position <= counter) {
                    clearBit(position)
                    position++
                }
            }
            setBit(counter)
            highestSeen = counter
            return true
        }

        val distance = highestSeen - counter
        if (distance >= WINDOW_SIZE) return false // too old to prove it is not a replay
        if (getBit(counter)) return false // already seen
        setBit(counter)
        return true
    }

    private fun index(counter: Long): Int = (counter % WINDOW_SIZE).toInt()
    private fun getBit(counter: Long): Boolean {
        val i = index(counter)
        return bitmap[i ushr 6] and (1L shl (i and 63)) != 0L
    }
    private fun setBit(counter: Long) {
        val i = index(counter)
        bitmap[i ushr 6] = bitmap[i ushr 6] or (1L shl (i and 63))
    }
    private fun clearBit(counter: Long) {
        val i = index(counter)
        bitmap[i ushr 6] = bitmap[i ushr 6] and (1L shl (i and 63)).inv()
    }

    fun reset() {
        highestSeen = -1
        bitmap.fill(0L)
    }

    companion object {
        /** Bits in the bitmap: how far out of order a message may arrive and still be accepted. */
        const val WINDOW_SIZE = 1024L

        private const val WORDS = (WINDOW_SIZE / 64).toInt()
    }
}
