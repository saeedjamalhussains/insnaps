package com.insnaps.core

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.JvmCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CryptoProviderTest {

    private val crypto: CryptoProvider = JvmCryptoProvider()

    @Test
    fun `x25519 agreement produces the same secret from both sides`() {
        val a = crypto.generateX25519KeyPair()
        val b = crypto.generateX25519KeyPair()
        assertContentEquals(
            crypto.x25519(a.privateKey, b.publicKey),
            crypto.x25519(b.privateKey, a.publicKey),
        )
    }

    @Test
    fun `x25519 public keys round trip through the raw wire encoding`() {
        // The JDK exposes X25519 keys as a BigInteger u-coordinate, so the raw
        // little-endian conversion is a real source of subtle breakage.
        repeat(50) {
            val pair = crypto.generateX25519KeyPair()
            assertEquals(CryptoProvider.X25519_KEY_SIZE, pair.publicKey.size)
            val other = crypto.generateX25519KeyPair()
            assertContentEquals(
                crypto.x25519(other.privateKey, pair.publicKey),
                crypto.x25519(pair.privateKey, other.publicKey),
            )
        }
    }

    @Test
    fun `x25519 rejects a small order point`() {
        val pair = crypto.generateX25519KeyPair()
        // An all-zero public key drives the shared secret to zero, which would make
        // every derived session key identical.
        assertFailsWith<IllegalArgumentException> {
            crypto.x25519(pair.privateKey, ByteArray(32))
        }
    }

    @Test
    fun `hkdf is deterministic and length correct`() {
        val ikm = "input".encodeToByteArray()
        val salt = "salt".encodeToByteArray()
        val info = "info".encodeToByteArray()
        assertContentEquals(crypto.hkdf(ikm, salt, info, 64), crypto.hkdf(ikm, salt, info, 64))
        assertEquals(64, crypto.hkdf(ikm, salt, info, 64).size)
        assertEquals(100, crypto.hkdf(ikm, salt, info, 100).size)
        assertNotEquals(
            crypto.hkdf(ikm, salt, info, 32).toList(),
            crypto.hkdf(ikm, salt, "other".encodeToByteArray(), 32).toList(),
        )
    }

    @Test
    fun `hkdf matches RFC 5869 test case 1`() {
        // Anchors the construction against the published vector rather than only
        // against itself.
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() }
        val info = ByteArray(10) { (0xf0 + it).toByte() }
        val expected = "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"
        assertEquals(expected, crypto.hkdf(ikm, salt, info, 42).joinToString("") {
            (it.toInt() and 0xFF).toString(16).padStart(2, '0')
        })
    }

    @Test
    fun `aead round trips and rejects tampering`() {
        val key = crypto.nextBytes(32)
        val nonce = crypto.nextBytes(12)
        val aad = "header".encodeToByteArray()
        val plaintext = "the message".encodeToByteArray()

        val sealed = crypto.aeadSeal(key, nonce, aad, plaintext)
        assertContentEquals(plaintext, crypto.aeadOpen(key, nonce, aad, sealed))

        val tampered = sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertNull(crypto.aeadOpen(key, nonce, aad, tampered), "a modified ciphertext must not open")
        assertNull(crypto.aeadOpen(key, nonce, "other".encodeToByteArray(), sealed), "AAD is authenticated")
        assertNull(crypto.aeadOpen(crypto.nextBytes(32), nonce, aad, sealed), "wrong key must not open")
        assertNull(crypto.aeadOpen(key, crypto.nextBytes(12), aad, sealed), "wrong nonce must not open")
    }

    @Test
    fun `aead open returns null rather than throwing on garbage`() {
        val key = crypto.nextBytes(32)
        val nonce = crypto.nextBytes(12)
        for (size in 0..40) {
            crypto.aeadOpen(key, nonce, ByteArray(0), ByteArray(size) { it.toByte() })
        }
    }

    @Test
    fun `random bytes are not repeated`() {
        val samples = List(100) { crypto.nextBytes(32).toList() }
        assertEquals(100, samples.toSet().size)
    }

    @Test
    fun `sha256 matches the known empty string digest`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            crypto.sha256(ByteArray(0)).joinToString("") {
                (it.toInt() and 0xFF).toString(16).padStart(2, '0')
            },
        )
    }

    @Test
    fun `hmac matches RFC 4231 test case 1`() {
        val mac = crypto.hmacSha256(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray())
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            mac.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') },
        )
        assertTrue(mac.size == 32)
    }
}
