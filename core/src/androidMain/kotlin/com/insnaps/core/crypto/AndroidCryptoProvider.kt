package com.insnaps.core.crypto

import com.google.crypto.tink.subtle.X25519
import java.security.InvalidKeyException
import java.security.SecureRandom

/**
 * Android [CryptoProvider].
 *
 * Identical to the JVM provider in every primitive except X25519, which comes
 * from Tink rather than the JCA. Tink implements the curve directly instead of
 * going through the `XDH` binding that Android either lacks (API < 33) or refuses
 * to initialise with `NamedParameterSpec` (API 34) — both measured on real
 * hardware, see docs/TESTING.md.
 *
 * **The protocol is unchanged by this.** Same packet format, same handshake, same
 * session semantics, same tests. Only the source of one primitive differs, which
 * is the entire reason [CryptoProvider] is an interface.
 */
class AndroidCryptoProvider(
    secureRandom: SecureRandom = SecureRandom(),
) : JcaCryptoSupport(secureRandom) {

    override fun generateX25519KeyPair(): X25519KeyPair {
        val privateKey = X25519.generatePrivateKey()
        return X25519KeyPair(
            publicKey = X25519.publicFromPrivate(privateKey),
            privateKey = privateKey,
        )
    }

    override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == CryptoProvider.X25519_KEY_SIZE) { "private key must be 32 bytes" }
        require(peerPublicKey.size == CryptoProvider.X25519_KEY_SIZE) { "public key must be 32 bytes" }

        val shared = try {
            X25519.computeSharedSecret(privateKey, peerPublicKey)
        } catch (e: InvalidKeyException) {
            // Tink rejects small-order points as InvalidKeyException. Normalised to
            // IllegalArgumentException so the contract is identical on every
            // platform -- the handshake guards on that type, not on this one.
            throw IllegalArgumentException("peer contributed an invalid X25519 point", e)
        }

        // Backstop, matching the JVM provider: an all-zero secret would make every
        // derived key identical.
        if (shared.all { it == 0.toByte() }) {
            throw IllegalArgumentException("peer contributed a small-order point")
        }
        return shared
    }
}
