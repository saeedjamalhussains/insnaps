package com.insnaps.core.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import javax.crypto.KeyAgreement

/**
 * Desktop-JVM [CryptoProvider]. **Test environment only — not for Android.**
 *
 * Shares every JCA primitive with the Android provider through [JcaCryptoSupport]
 * and adds X25519 via the JDK's `XDH` binding. That binding is the one part that
 * does not port, which Firebase Test Lab established on real hardware:
 *
 * | Device | API | `XDH` registered | Result |
 * |---|---|---|---|
 * | Pixel 5 | 30 | no | `NoSuchAlgorithmException` — algorithm absent |
 * | Pixel 8 | 34 | yes | `InvalidAlgorithmParameterException: No AlgorithmParameterSpec classes are supported` |
 *
 * Below API 33 the algorithm does not exist; at API 34 Conscrypt rejects
 * `NamedParameterSpec`, which is how the JDK selects the curve. There is no API
 * level at which this class performs key agreement on a phone, which is why
 * `AndroidCryptoProvider` exists and why `androidMain` does not depend on
 * `jvmMain`.
 *
 * Note also that the algorithm is requested as `XDH`: the JDK registers both that
 * and `X25519`, Android registers only `XDH`, so no JVM test could ever have
 * distinguished them.
 */
class JvmCryptoProvider(
    secureRandom: SecureRandom = SecureRandom(),
) : JcaCryptoSupport(secureRandom) {

    override fun generateX25519KeyPair(): X25519KeyPair {
        val generator = KeyPairGenerator.getInstance(XDH)
        generator.initialize(NamedParameterSpec.X25519, secureRandom)
        val pair = generator.generateKeyPair()
        val private = (pair.private as XECPrivateKey).scalar.orElseThrow {
            IllegalStateException("platform withheld the X25519 scalar")
        }
        return X25519KeyPair(
            publicKey = rawPublicKey(pair.public as XECPublicKey),
            privateKey = private,
        )
    }

    override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == CryptoProvider.X25519_KEY_SIZE) { "private key must be 32 bytes" }
        require(peerPublicKey.size == CryptoProvider.X25519_KEY_SIZE) { "public key must be 32 bytes" }

        val factory = KeyFactory.getInstance(XDH)
        val private = factory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, privateKey))
        val public = factory.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(peerPublicKey)))

        val shared = try {
            KeyAgreement.getInstance(XDH).run {
                init(private)
                doPhase(public, true)
                generateSecret()
            }
        } catch (e: java.security.InvalidKeyException) {
            // The JDK rejects small-order points itself, but as InvalidKeyException.
            // Normalised so the contract -- invalid peer contributions throw
            // IllegalArgumentException -- holds identically on every platform.
            throw IllegalArgumentException("peer contributed an invalid X25519 point", e)
        }

        if (shared.all { it == 0.toByte() }) {
            throw IllegalArgumentException("peer contributed a small-order point")
        }
        return shared
    }

    /** RFC 7748 wire format is little-endian u, with the high bit of the last byte ignored. */
    private fun decodeU(raw: ByteArray): BigInteger {
        val littleEndian = raw.copyOf()
        littleEndian[littleEndian.size - 1] = (littleEndian[littleEndian.size - 1].toInt() and 0x7F).toByte()
        return BigInteger(1, littleEndian.reversedArray())
    }

    private fun rawPublicKey(key: XECPublicKey): ByteArray {
        val bigEndian = key.u.toByteArray()
        val out = ByteArray(CryptoProvider.X25519_KEY_SIZE)
        var written = 0
        for (i in bigEndian.indices.reversed()) {
            if (written == out.size) break
            out[written++] = bigEndian[i]
        }
        return out
    }

    private companion object {
        /** `XDH`, never `X25519`. See the class documentation. */
        const val XDH = "XDH"
    }
}
