package com.insnaps.core.session

/**
 * Sliding-window replay protection over per-session message counters (RFC 6479 style).
 *
 * The mesh delivers packets out of order and duplicates them by design -- the same
 * message legitimately arrives by several paths -- so a strictly increasing
 * counter check would drop valid traffic. A window accepts reordering up to
 * [WINDOW_SIZE] while still rejecting any counter it has already seen.
 *
 * This is separate from, and additional to, the mesh-layer duplicate cache: that
 * one suppresses re-forwarding of a packet id and is a bandwidth measure, while
 * this one is a cryptographic guarantee that a captured message cannot be
 * replayed into the session later.
 */
class ReplayWindow {

    private var highestSeen: Long = -1
    private var bitmap: ULong = 0uL

    /**
     * Records [counter] and reports whether it is acceptable.
     *
     * Returns false for a counter already seen, or one so old it has fallen out
     * of the window. A rejected counter does not advance any state.
     */
    fun accept(counter: Long): Boolean {
        if (counter < 0) return false

        if (counter > highestSeen) {
            val shift = counter - highestSeen
            bitmap = if (shift >= WINDOW_SIZE) 1uL else (bitmap shl shift.toInt()) or 1uL
            highestSeen = counter
            return true
        }

        val distance = highestSeen - counter
        if (distance >= WINDOW_SIZE) return false // too old to prove it is not a replay

        val mask = 1uL shl distance.toInt()
        if (bitmap and mask != 0uL) return false // already seen
        bitmap = bitmap or mask
        return true
    }

    fun reset() {
        highestSeen = -1
        bitmap = 0uL
    }

    companion object {
        /** Bits in the bitmap: how far out of order a message may arrive and still be accepted. */
        const val WINDOW_SIZE = 64L
    }
}
