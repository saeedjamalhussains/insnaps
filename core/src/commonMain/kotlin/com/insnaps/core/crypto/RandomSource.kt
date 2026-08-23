package com.insnaps.core.crypto

/**
 * Source of cryptographically secure random bytes.
 *
 * Declared as an interface rather than an `expect fun` so tests can substitute a
 * deterministic generator without a platform-specific test source set. Production
 * implementations must be backed by the platform CSPRNG (`SecureRandom` on
 * Android, `SecRandomCopyBytes` on iOS) -- never by a general-purpose PRNG.
 */
fun interface RandomSource {
    fun nextBytes(size: Int): ByteArray
}
