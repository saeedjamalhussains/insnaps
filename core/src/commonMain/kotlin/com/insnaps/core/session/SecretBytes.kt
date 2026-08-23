package com.insnaps.core.session

/**
 * Key material with an explicit lifetime.
 *
 * Sensitive bytes are wrapped so that ownership is stated rather than assumed:
 * whoever holds a [SecretBytes] is responsible for calling [destroy] when the
 * session it belongs to ends.
 *
 * ## What zeroing does and does not guarantee
 *
 * [destroy] overwrites the array in place, which removes the value from *this*
 * buffer. It cannot promise the bytes are gone from the machine: a garbage
 * collector may already have copied the array while compacting the heap, and the
 * OS may have paged it out. This is a best-effort reduction of exposure window,
 * not an erasure guarantee, and no part of the design should depend on it being
 * absolute.
 *
 * The property insnaps actually relies on is weaker and achievable: key material
 * is never written to storage, and is dropped when the session ends.
 */
class SecretBytes(private val value: ByteArray) {

    var destroyed: Boolean = false
        private set

    val size: Int get() = value.size

    /**
     * Borrows the raw bytes for a single operation.
     *
     * Callers MUST NOT retain the array beyond the call: it is the live buffer,
     * and [destroy] will zero it underneath any retained reference.
     */
    fun <T> use(block: (ByteArray) -> T): T {
        check(!destroyed) { "secret has been destroyed" }
        return block(value)
    }

    /** Overwrites the buffer. Idempotent. After this the secret is unusable. */
    fun destroy() {
        if (destroyed) return
        value.fill(0)
        destroyed = true
    }

    /** Never logs the value. */
    override fun toString(): String = "SecretBytes(${size}B${if (destroyed) ", destroyed" else ""})"
}
