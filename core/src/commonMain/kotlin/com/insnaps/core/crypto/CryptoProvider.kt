package com.insnaps.core.crypto

/**
 * Every cryptographic primitive insnaps uses, supplied by the platform.
 *
 * `commonMain` implements no primitive itself. Each method below maps onto a
 * vetted platform implementation -- the JDK / Tink / Conscrypt on Android,
 * CryptoKit or libsodium on iOS -- and the shared code only composes them.
 *
 * Implementations MUST be constant-time where the primitive requires it, and
 * MUST source randomness from the platform CSPRNG.
 */
interface CryptoProvider : RandomSource, Mac {

    /** Generates an X25519 key pair for use as an ephemeral or static identity key. */
    fun generateX25519KeyPair(): X25519KeyPair

    /**
     * X25519 Diffie-Hellman.
     *
     * Implementations MUST reject the all-zero shared secret (a small-order point
     * contribution) by throwing, rather than returning it.
     */
    fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray

    fun sha256(data: ByteArray): ByteArray

    /** HKDF-SHA256 (RFC 5869) extract-then-expand. */
    fun hkdf(inputKeyMaterial: ByteArray, salt: ByteArray, info: ByteArray, outputLength: Int): ByteArray

    /**
     * AEAD seal. AES-256-GCM or ChaCha20-Poly1305; returns ciphertext with its tag
     * appended. [nonce] MUST never repeat under a given [key].
     */
    fun aeadSeal(key: ByteArray, nonce: ByteArray, associatedData: ByteArray, plaintext: ByteArray): ByteArray

    /** AEAD open. Returns null on any authentication failure -- forgery is expected traffic, not an error. */
    fun aeadOpen(key: ByteArray, nonce: ByteArray, associatedData: ByteArray, ciphertext: ByteArray): ByteArray?

    companion object {
        const val X25519_KEY_SIZE = 32
        const val AEAD_KEY_SIZE = 32
        const val AEAD_NONCE_SIZE = 12
        const val AEAD_TAG_SIZE = 16
        const val HASH_SIZE = 32
    }
}

class X25519KeyPair(val publicKey: ByteArray, val privateKey: ByteArray)
