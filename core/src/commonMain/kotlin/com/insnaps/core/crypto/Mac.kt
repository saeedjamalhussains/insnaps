package com.insnaps.core.crypto

/**
 * Keyed MAC used for recipient tag derivation.
 *
 * Injected rather than implemented in `commonMain`: hand-rolling a MAC in shared
 * Kotlin would be slower and far more error-prone than calling the platform
 * primitive (`javax.crypto.Mac` on Android, CryptoKit on iOS).
 */
fun interface Mac {
    /** HMAC-SHA256 of [data] under [key]. Must return 32 bytes. */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
}

/**
 * Supplies the pairwise shared secrets used to derive recipient tags.
 *
 * A secret exists only for peers the user has an established session with, which
 * is what makes a tag recognisable to its recipient and opaque to everyone else.
 */
interface SharedSecretProvider {
    /** Long-term pairwise secret with [peer], or null if no session exists. */
    fun secretFor(peer: PeerIdentity): ByteArray?

    /** Peers this device has a session with, checked when matching an inbound tag. */
    fun knownPeers(): List<PeerIdentity>
}
