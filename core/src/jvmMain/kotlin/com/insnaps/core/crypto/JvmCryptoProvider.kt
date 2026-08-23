package com.insnaps.core.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac as JavaMac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM / Android implementation of [CryptoProvider], backed entirely by the JDK.
 *
 * X25519 (`XDH`), SHA-256, HMAC-SHA256 and AES-256-GCM all come from the platform
 * provider. The only composition written here is HKDF, which is the standard
 * RFC 5869 extract-then-expand over HMAC -- a construction, not a primitive.
 * (`javax.crypto.KDF` with HKDF is only available from JDK 24; this can be
 * swapped for it once the minimum JDK allows.)
 *
 * On Android this class works as-is; Conscrypt supplies the same algorithms.
 * X25519 via `XDH` requires API 33+, so older Android minimums should route this
 * class to Tink or BouncyCastle instead. That substitution is invisible to the
 * rest of the codebase.
 */
class JvmCryptoProvider(
    private val secureRandom: SecureRandom = SecureRandom(),
) : CryptoProvider {

    override fun nextBytes(size: Int): ByteArray =
        ByteArray(size).also(secureRandom::nextBytes)

    override fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        JavaMac.getInstance(HMAC).run {
            // An all-zero key is legal for HMAC but rejected by SecretKeySpec, and
            // HKDF-Extract legitimately uses an empty salt.
            init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, HMAC))
            doFinal(data)
        }

    override fun hkdf(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputLength: Int,
    ): ByteArray {
        require(outputLength in 1..(255 * 32)) { "HKDF output length out of range" }

        val pseudoRandomKey = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, inputKeyMaterial)

        val output = ByteArray(outputLength)
        var block = ByteArray(0)
        var written = 0
        var counter = 1
        while (written < outputLength) {
            block = hmacSha256(pseudoRandomKey, block + info + byteArrayOf(counter.toByte()))
            val take = minOf(block.size, outputLength - written)
            block.copyInto(output, written, 0, take)
            written += take
            counter++
        }
        return output
    }

    override fun generateX25519KeyPair(): X25519KeyPair {
        val generator = KeyPairGenerator.getInstance(X25519)
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

        val factory = KeyFactory.getInstance(X25519)
        val private = factory.generatePrivate(XECPrivateKeySpec(NamedParameterSpec.X25519, privateKey))
        val public = factory.generatePublic(XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(peerPublicKey)))

        val shared = try {
            KeyAgreement.getInstance(X25519).run {
                init(private)
                doPhase(public, true)
                generateSecret()
            }
        } catch (e: java.security.InvalidKeyException) {
            // The JDK rejects small-order points itself, but as InvalidKeyException.
            // Normalised here so the contract -- invalid peer contributions throw
            // IllegalArgumentException -- holds identically on every platform,
            // including ones whose library returns the zero secret instead.
            throw IllegalArgumentException("peer contributed an invalid X25519 point", e)
        }

        // Backstop for a provider that returns the all-zero secret rather than
        // rejecting: it would make every derived key identical.
        if (shared.all { it == 0.toByte() }) {
            throw IllegalArgumentException("peer contributed a small-order point")
        }
        return shared
    }

    override fun aeadSeal(
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = cipher(Cipher.ENCRYPT_MODE, key, nonce, associatedData).doFinal(plaintext)

    override fun aeadOpen(
        key: ByteArray,
        nonce: ByteArray,
        associatedData: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? = try {
        cipher(Cipher.DECRYPT_MODE, key, nonce, associatedData).doFinal(ciphertext)
    } catch (_: AEADBadTagException) {
        null
    } catch (_: javax.crypto.IllegalBlockSizeException) {
        null
    } catch (_: java.security.GeneralSecurityException) {
        null
    }

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray): Cipher {
        require(key.size == CryptoProvider.AEAD_KEY_SIZE) { "AEAD key must be 32 bytes" }
        require(nonce.size == CryptoProvider.AEAD_NONCE_SIZE) { "AEAD nonce must be 12 bytes" }
        return Cipher.getInstance(AES_GCM).apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(CryptoProvider.AEAD_TAG_SIZE * 8, nonce))
            if (aad.isNotEmpty()) updateAAD(aad)
        }
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
        // Copy into little-endian order, dropping any BigInteger sign byte.
        var written = 0
        for (i in bigEndian.indices.reversed()) {
            if (written == out.size) break
            out[written++] = bigEndian[i]
        }
        return out
    }

    private companion object {
        const val X25519 = "X25519"
        const val HMAC = "HmacSHA256"
        const val AES_GCM = "AES/GCM/NoPadding"
    }
}
