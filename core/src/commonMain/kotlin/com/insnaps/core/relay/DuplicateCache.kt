package com.insnaps.core.relay

import com.insnaps.core.packet.PacketId
import com.insnaps.core.util.Clock

/**
 * Remembers recently seen packet ids so a packet is forwarded at most once per node.
 *
 * Without this, any cycle in the mesh graph -- and a dense mesh is almost all
 * cycles -- turns a single message into an exponential broadcast storm.
 *
 * Bounded in both entries and age: it is charged against the memory budget and is
 * also directly attacker-facing, since an attacker can mint unlimited fresh packet
 * ids. When full it evicts in insertion order, which costs correctness only for
 * traffic older than the eviction horizon.
 */
class DuplicateCache(
    private val maxEntries: Int,
    private val retentionMillis: Long,
    private val clock: Clock,
) {
    private val seen = LinkedHashMap<PacketId, Long>()

    val size: Int get() = seen.size

    /**
     * Records [id] and reports whether it is new.
     *
     * Returns true the first time an id is offered, false for a repeat. The caller
     * forwards only on true.
     */
    fun offer(id: PacketId): Boolean {
        val now = clock.nowMillis()
        purgeExpired(now)

        val previous = seen[id]
        if (previous != null) return false

        if (seen.size >= maxEntries) {
            val oldest = seen.keys.firstOrNull()
            if (oldest != null) seen.remove(oldest)
        }
        seen[id] = now
        return true
    }

    fun contains(id: PacketId): Boolean {
        purgeExpired(clock.nowMillis())
        return seen.containsKey(id)
    }

    fun clear() = seen.clear()

    /** Approximate retained bytes, for budget accounting. */
    fun estimatedBytes(): Long = seen.size.toLong() * ENTRY_OVERHEAD_BYTES

    private fun purgeExpired(now: Long) {
        if (seen.isEmpty()) return
        val cutoff = now - retentionMillis
        // Insertion-ordered, so the expired entries are a prefix and we can stop early.
        val iterator = seen.entries.iterator()
        while (iterator.hasNext()) {
            if (iterator.next().value > cutoff) break
            iterator.remove()
        }
    }

    private companion object {
        /** 16 id bytes + timestamp + map entry overhead, rounded up. */
        const val ENTRY_OVERHEAD_BYTES = 64
    }
}
