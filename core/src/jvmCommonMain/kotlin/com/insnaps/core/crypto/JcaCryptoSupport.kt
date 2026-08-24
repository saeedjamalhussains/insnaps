package com.insnaps.core.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac as JavaMac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The JCA primitives shared by the JVM and Android providers.
 *
 * Everything here was verified running on real hardware (Pixel 5 / API 30 and
 * Pixel 8 / API 34) via Firebase Test Lab: AES-256-GCM, SHA-256, HMAC-SHA256 and
 * the HKDF composition over them. These are genuinely portable across ART and
 * HotSpot.
 *
 * X25519 is deliberately left abstract. It is the one primitive whose JCA binding
 * differs between the two platforms, and pretending otherwise is precisely the
 * mistake that survived 258 passing JVM tests.
 */
abstract class JcaCryptoSupport(
    protected val secureRandom: SecureRandom = SecureRandom(),
) : CryptoProvider {

    abstract override fun generateX25519KeyPair(): X25519KeyPair

    abstract override fun x25519(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray

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

    /**
     * HKDF-SHA256 (RFC 5869), extract then expand.
     *
     * A construction over HMAC rather than a primitive, which is why it is written
     * here rather than borrowed. Checked against the RFC's own test vector both on
     * the JVM and on device. (`javax.crypto.KDF` with HKDF only exists from JDK 24
     * and has no Android equivalent.)
     */
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

    protected companion object {
        const val HMAC = "HmacSHA256"
        const val AES_GCM = "AES/GCM/NoPadding"
    }
}
