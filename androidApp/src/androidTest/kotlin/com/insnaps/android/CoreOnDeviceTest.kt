package com.insnaps.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.insnaps.core.app.AppMessage
import com.insnaps.core.app.ConversationMode
import com.insnaps.core.app.ExpiryPolicy
import com.insnaps.core.crypto.AndroidCryptoProvider
import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.session.HandshakeInitiator
import com.insnaps.core.session.HandshakeResponder
import com.insnaps.core.session.Session
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * v0.9a acceptance suite: the E2EE stack on real Android hardware.
 *
 * The 258 JVM tests are not duplicated here. This covers only what a device can
 * disprove and a JVM cannot — which the first Test Lab run demonstrated is not a
 * theoretical category.
 */
@RunWith(AndroidJUnit4::class)
class CoreOnDeviceTest {

    private val crypto: CryptoProvider = AndroidCryptoProvider()

    private fun log(message: String) = android.util.Log.i("insnaps", message)

    @Test
    fun reportDeviceCapabilities() {
        val sdk = android.os.Build.VERSION.SDK_INT
        val xdh = runCatching { java.security.KeyPairGenerator.getInstance("XDH") }.isSuccess
        val gcm = runCatching { javax.crypto.Cipher.getInstance("AES/GCM/NoPadding") }.isSuccess
        log("device=${android.os.Build.MANUFACTURER}/${android.os.Build.MODEL} api=$sdk XDH=$xdh AES-GCM=$gcm")
        assertTrue("AES/GCM must exist on every supported Android version", gcm)
    }

    // ---- acceptance: crypto -------------------------------------------------

    @Test
    fun x25519KeyGeneration() {
        val pair = crypto.generateX25519KeyPair()
        assertEquals(32, pair.publicKey.size)
        assertEquals(32, pair.privateKey.size)
        assertNotEquals(
            "a generated key must not be all zeros",
            0,
            pair.publicKey.count { it != 0.toByte() },
        )
        log("api=${android.os.Build.VERSION.SDK_INT} x25519KeyGen=ok")
    }

    @Test
    fun x25519Agreement() {
        val a = crypto.generateX25519KeyPair()
        val b = crypto.generateX25519KeyPair()
        assertArrayEquals(
            crypto.x25519(a.privateKey, b.publicKey),
            crypto.x25519(b.privateKey, a.publicKey),
        )
        log("api=${android.os.Build.VERSION.SDK_INT} x25519Agreement=ok")
    }

    @Test
    fun x25519RejectsASmallOrderPoint() {
        // The contract must be identical across providers: invalid peer
        // contributions raise IllegalArgumentException, which is what the
        // handshake's guard catches.
        val pair = crypto.generateX25519KeyPair()
        val failure = runCatching { crypto.x25519(pair.privateKey, ByteArray(32)) }.exceptionOrNull()
        assertTrue(
            "expected IllegalArgumentException, got $failure",
            failure is IllegalArgumentException,
        )
    }

    @Test
    fun aes256GcmSealsAndRejectsTampering() {
        val key = crypto.nextBytes(32)
        val nonce = crypto.nextBytes(12)
        val plaintext = "on-device".encodeToByteArray()
        val sealed = crypto.aeadSeal(key, nonce, "aad".encodeToByteArray(), plaintext)

        assertArrayEquals(plaintext, crypto.aeadOpen(key, nonce, "aad".encodeToByteArray(), sealed))
        val tampered = sealed.copyOf().also { it[0] = (it[0] + 1).toByte() }
        assertNull(crypto.aeadOpen(key, nonce, "aad".encodeToByteArray(), tampered))
        assertNull(crypto.aeadOpen(key, nonce, "other".encodeToByteArray(), sealed))
    }

    @Test
    fun hkdfMatchesRfc5869Vector() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() }
        val info = ByteArray(10) { (0xf0 + it).toByte() }
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            crypto.hkdf(ikm, salt, info, 42).joinToString("") {
                (it.toInt() and 0xFF).toString(16).padStart(2, '0')
            },
        )
    }

    @Test
    fun sha256MatchesKnownDigest() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            crypto.sha256(ByteArray(0)).joinToString("") {
                (it.toInt() and 0xFF).toString(16).padStart(2, '0')
            },
        )
    }

    // ---- acceptance: protocol ----------------------------------------------

    @Test
    fun packetCodecRoundTrips() {
        val packet = Packet(
            header = Packet.Header(
                packetId = PacketId(crypto.nextBytes(16)),
                ttl = 8,
                lifetimeSeconds = 300,
                recipientTag = RecipientTag(crypto.nextBytes(8)),
                broadcast = false,
            ),
            payload = "hello from a phone".encodeToByteArray(),
        )
        assertEquals(packet, Packet.decode(packet.encode()))
        assertNull(Packet.decode(ByteArray(4)))
    }

    /**
     * Handshake, session establishment, encrypt/decrypt and replay protection —
     * the full E2EE path, executed entirely on the device.
     */
    @Test
    fun handshakeSessionAndReplayProtection() {
        val alice = crypto.generateX25519KeyPair()
        val bob = crypto.generateX25519KeyPair()

        val initiator = HandshakeInitiator(crypto, alice, bob.publicKey)
        val responder = HandshakeResponder(crypto, bob)
        responder.readMessage1(initiator.writeMessage1())
        val (message2, bobResult) = responder.writeMessage2()
        val aliceResult = initiator.readMessage2(message2)

        // Directional keys must cross over, or a reflected message would decrypt.
        assertArrayEquals(aliceResult.sendKey, bobResult.receiveKey)
        assertArrayEquals(aliceResult.receiveKey, bobResult.sendKey)
        assertArrayEquals(aliceResult.sessionId, bobResult.sessionId)

        val aliceSession = Session(
            aliceResult.peer, aliceResult.sessionId, aliceResult.sendKey, aliceResult.receiveKey, crypto, 0,
        )
        val bobSession = Session(
            bobResult.peer, bobResult.sessionId, bobResult.sendKey, bobResult.receiveKey, crypto, 0,
        )

        val message = AppMessage(
            AppMessage.Type.TEXT, ConversationMode.PRIVATE, ExpiryPolicy.FIVE_MINUTES, 1,
            "sealed on device".encodeToByteArray(),
        )
        val sealed = aliceSession.seal(message.encode(), 0)

        val opened = bobSession.open(sealed, 0)
        assertNotNull("the session did not open on device", opened)
        assertEquals("sealed on device", AppMessage.decode(opened!!)!!.body.decodeToString())

        // Replay protection, on device.
        assertNull("a replayed frame must be rejected", bobSession.open(sealed, 0))
        log("api=${android.os.Build.VERSION.SDK_INT} e2eeSession=ok replayRejected=true")
    }

    // ---- the reason AndroidCryptoProvider exists ---------------------------

    /**
     * The JDK provider is not tested here because it **cannot be referenced** from
     * Android code at all: `JvmCryptoProvider` lives in `jvmMain`, and `androidMain`
     * deliberately does not depend on it. A compile error is a stronger guarantee
     * than a passing test, so the misuse this once allowed is now unrepresentable.
     *
     * What the device can still show is the underlying platform fact, which
     * `reportDeviceCapabilities` logs as `XDH=false` on API 30 and `XDH=true` on
     * API 34 — where it exists but rejects `NamedParameterSpec`.
     */

    @Test
    fun deviceReportsBluetoothLeSupport() {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val hasBle = context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_BLUETOOTH_LE)
        log("bluetoothLe=$hasBle")
        assertTrue("insnaps requires BLE hardware", hasBle)
    }
}

/**
 * On-device checks for the BLE transport.
 *
 * These verify what a *single* device can prove: that the transport constructs
 * against the real Bluetooth stack, that the contract is satisfied, and that the
 * radio is actually present and usable. They cannot prove two phones link — that
 * needs layer 3 (docs/TESTING.md), and no amount of Test Lab makes it possible.
 */
@RunWith(AndroidJUnit4::class)
class BleTransportOnDeviceTest {

    private val context get() =
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext

    private fun log(message: String) = android.util.Log.i("insnaps", message)

    @Test
    fun bluetoothStackIsPresentAndReportsCapabilities() {
        val manager = context.getSystemService(android.content.Context.BLUETOOTH_SERVICE)
            as android.bluetooth.BluetoothManager
        val adapter = manager.adapter
        assertNotNull("no Bluetooth adapter on this device", adapter)

        // Advertising is not universal: some chipsets are scan-only, which would
        // make a device a client of the mesh but never a relay.
        val canAdvertise = adapter.isMultipleAdvertisementSupported
        log(
            "api=${android.os.Build.VERSION.SDK_INT} btEnabled=${adapter.isEnabled} " +
                "multiAdvertisement=$canAdvertise",
        )
    }

    @Test
    fun transportConstructsAgainstTheRealBluetoothStack() {
        val transport = com.insnaps.core.transport.AndroidBleTransport(
            context = context,
            clock = { System.currentTimeMillis() },
        )
        // The core asks for this once and fragments to whatever the link supports.
        assertEquals(com.insnaps.core.packet.Packet.MAX_PACKET_SIZE, transport.maxFrameSize)
        assertEquals(0L, transport.bufferedBytes())

        // stop() before start() must be safe: the contract says both are idempotent.
        transport.stop()
        log("bleTransportConstructed=ok")
    }

    /**
     * The MTU arithmetic that forced a fragmentation layer, checked against the
     * constants the real stack uses rather than against my own notes.
     */
    @Test
    fun aFullPacketDoesNotFitOneBleWrite() {
        val maxWrite = com.insnaps.core.transport.AndroidBleTransport.MAX_MTU -
            com.insnaps.core.transport.AndroidBleTransport.ATT_HEADER_BYTES
        val packet = com.insnaps.core.packet.Packet.MAX_PACKET_SIZE

        assertTrue(
            "a $packet-byte packet unexpectedly fits a $maxWrite-byte write; " +
                "the fragmentation layer's premise has changed",
            packet > maxWrite,
        )
        assertTrue(
            "fragmentation must cope with the pre-negotiation MTU",
            com.insnaps.core.link.LinkFraming.fits(
                packet,
                com.insnaps.core.transport.AndroidBleTransport.DEFAULT_MTU -
                    com.insnaps.core.transport.AndroidBleTransport.ATT_HEADER_BYTES,
            ),
        )
        log("packetBytes=$packet maxBleWrite=$maxWrite fragmentationRequired=true")
    }
}
