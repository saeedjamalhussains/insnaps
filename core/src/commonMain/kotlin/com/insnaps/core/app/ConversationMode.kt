package com.insnaps.core.app

/**
 * How a conversation treats its own history.
 *
 * This is an **endpoint** property. It changes what the sender and recipient
 * keep, never what a relay does: a relay is RAM-only in both modes, holds no
 * key in both modes, and cannot tell the two apart. The mode travels inside the
 * encrypted payload precisely so that stays true (see [AppMessage]).
 */
enum class ConversationMode {
    /**
     * Persistent encrypted messaging.
     *
     * Sender and recipient may retain history across restarts. History is
     * encrypted at rest with a key held in platform-protected storage; plaintext
     * is never written to ordinary storage.
     */
    NORMAL,

    /**
     * Ephemeral protected messaging.
     *
     * Plaintext may exist in RAM while a message is live and is destroyed on
     * expiry along with anything derived from it. Nothing is intentionally
     * persisted at either endpoint.
     */
    PRIVATE,
    ;

    val requiresExpiry: Boolean get() = this == PRIVATE
}

/**
 * When a private message stops being readable.
 *
 * Encoded as a small integer on the wire so the set can grow without a format
 * change; unknown codes are rejected rather than guessed at, since guessing an
 * expiry wrong means either destroying a message early or keeping it too long.
 */
enum class ExpiryPolicy(val code: Int, val durationMillis: Long) {
    /** Normal mode: the endpoint decides, not the protocol. */
    NONE(0, 0),

    /**
     * Destroyed the moment it has been read once.
     *
     * The timer is meaningless here -- what matters is the view event -- but a
     * ceiling still applies so an unread message does not live forever.
     */
    VIEW_ONCE(1, 24 * 60 * 60 * 1000L),

    THIRTY_SECONDS(2, 30 * 1000L),
    FIVE_MINUTES(3, 5 * 60 * 1000L),
    ONE_HOUR(4, 60 * 60 * 1000L),
    TWENTY_FOUR_HOURS(5, 24 * 60 * 60 * 1000L),
    ;

    val isViewOnce: Boolean get() = this == VIEW_ONCE

    companion object {
        /** Decodes a wire code, or null if this build does not know it. */
        fun fromCode(code: Int): ExpiryPolicy? = entries.firstOrNull { it.code == code }
    }
}
