package com.insnaps.core.util

/**
 * Monotonic time source, in milliseconds.
 *
 * Every expiry decision in insnaps is made against the *local* clock of the
 * device holding the packet, never against a timestamp carried in the packet.
 * Mesh peers have no synchronised wall clock, and a sender-supplied absolute
 * expiry time would be both unreliable and attacker-controlled.
 */
fun interface Clock {
    fun nowMillis(): Long
}
