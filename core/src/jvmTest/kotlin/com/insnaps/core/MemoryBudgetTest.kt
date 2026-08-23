package com.insnaps.core

import com.insnaps.core.crypto.JvmCryptoProvider
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.packet.Packet
import com.insnaps.core.packet.PacketId
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.session.SecureMesh
import com.insnaps.core.session.SessionManager
import com.insnaps.core.transport.PeerHandle
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for the two resource guarantees: the 25 MB ceiling, and RAM-only.
 *
 * Both are the kind of claim that quietly stops being true, so both are asserted
 * mechanically rather than documented and hoped for.
 */
class MemoryBudgetTest {

    private val crypto = JvmCryptoProvider()
    private val clock = TestClock()

    @Test
    fun `the default configuration fits inside 25 MB`() {
        val config = MeshConfig()
        val sessionBytes = SessionManager.DEFAULT_MAX_SESSIONS * 256L

        val total = config.worstCaseRelayBytes() + sessionBytes
        assertTrue(
            total <= 25L * 1024 * 1024,
            "worst-case footprint $total exceeds the 25 MB budget",
        )
    }

    @Test
    fun `a configuration that cannot fit its own budget is rejected at construction`() {
        // A misconfiguration like this would otherwise only surface under load.
        assertFailsWith<IllegalArgumentException> {
            MeshConfig(totalBudgetBytes = 1024 * 1024, relayBufferBytes = 1024 * 1024, duplicateCacheEntries = 100_000)
        }
    }

    @Test
    fun `sustained flooding from many peers never breaches the budget`() {
        val config = MeshConfig(
            totalBudgetBytes = 1024 * 1024,
            relayBufferBytes = 512 * 1024,
            duplicateCacheEntries = 2_000,
            peerTableEntries = 64,
        )
        val engine = engine(config)

        // 20 attackers, each sending far more than the whole buffer could hold, and
        // nowhere for any of it to go.
        var counter = 0
        repeat(6_000) {
            val peer = PeerHandle("flood-${counter % 20}")
            engine.onFrame(peer, packet(counter++).encode())
        }

        assertTrue(
            engine.estimatedMemoryBytes() <= config.totalBudgetBytes,
            "held ${engine.estimatedMemoryBytes()} bytes against a ${config.totalBudgetBytes} byte budget",
        )
        // Note that no per-peer quota trips here: twenty *equal* flooders each stay
        // under a 10% share, so the budget is held by eviction alone. The quota is
        // for a disproportionate sender, which the next test covers.
    }

    @Test
    fun `a single dominant flooder is capped by its quota`() {
        val config = MeshConfig(
            totalBudgetBytes = 1024 * 1024,
            relayBufferBytes = 512 * 1024,
            duplicateCacheEntries = 2_000,
            peerTableEntries = 64,
        )
        val engine = engine(config)

        var counter = 0
        // Ordinary traffic from a spread of peers first.
        repeat(400) { engine.onFrame(PeerHandle("normal-${counter % 10}"), packet(counter++).encode()) }
        // Then one peer tries to take the whole buffer.
        repeat(4_000) { engine.onFrame(PeerHandle("greedy"), packet(counter++).encode()) }

        assertTrue(engine.stats.quotaDropped > 0, "the dominant sender should have been refused")
        assertTrue(
            engine.estimatedMemoryBytes() <= config.totalBudgetBytes,
            "held ${engine.estimatedMemoryBytes()} bytes against a ${config.totalBudgetBytes} byte budget",
        )
    }

    @Test
    fun `the session manager is bounded no matter how many handshakes arrive`() {
        val manager = SessionManager(crypto, clock, crypto.generateX25519KeyPair(), maxSessions = 16)
        repeat(200) {
            val stranger = SessionManager(crypto, clock, crypto.generateX25519KeyPair())
            manager.acceptHandshake(stranger.beginHandshake(manager.identity))
        }
        assertTrue(manager.sessionCount <= 16, "held ${manager.sessionCount} sessions")
    }

    @Test
    fun `pending handshakes are bounded`() {
        val manager = SessionManager(crypto, clock, crypto.generateX25519KeyPair(), maxPendingHandshakes = 8)
        repeat(100) { manager.beginHandshake(crypto.generateX25519KeyPair().let {
            com.insnaps.core.crypto.PeerIdentity(it.publicKey)
        }) }
        assertTrue(manager.pendingCount <= 8, "held ${manager.pendingCount} pending handshakes")
    }

    @Test
    fun `everything is released on shutdown`() {
        val engine = engine(MeshConfig())
        repeat(50) { engine.onFrame(PeerHandle("p"), packet(it).encode()) }
        assertTrue(engine.estimatedMemoryBytes() > 0)

        engine.stop()
        assertEquals(0L, engine.estimatedMemoryBytes(), "stopping must release every buffer")
    }

    @Test
    fun `commonMain depends on no storage API`() {
        // The RAM-only guarantee is only as good as the dependencies allow. If
        // shared code ever imports a filesystem, database or preferences API, this
        // fails -- which is the moment to notice, not after shipping.
        val commonMain = listOf(File("src/commonMain"), File("core/src/commonMain")).first { it.isDirectory }
        val forbidden = listOf(
            "java.io", "java.nio", "java.sql", "kotlinx.io",
            "okio", "sqlite", "SharedPreferences", "NSUserDefaults", "NSFileManager",
            "androidx.datastore", "androidx.room",
        )

        val offences = commonMain.walkTopDown()
            .filter { it.extension == "kt" }
            .flatMap { file ->
                file.readLines().withIndex()
                    .filter { (_, line) -> line.trimStart().startsWith("import ") }
                    .filter { (_, line) -> forbidden.any { line.contains(it, ignoreCase = true) } }
                    .map { (index, line) -> "${file.name}:${index + 1}: ${line.trim()}" }
            }
            .toList()

        assertTrue(offences.isEmpty(), "commonMain reached for storage:\n${offences.joinToString("\n")}")
    }

    // ---- helpers -----------------------------------------------------------

    private fun engine(config: MeshConfig): MeshEngine {
        val staticKeys = crypto.generateX25519KeyPair()
        val sessions = SessionManager(crypto, clock, staticKeys)
        val secure = SecureMesh(sessions, clock, object : SecureMesh.Listener {
            override fun onMessage(from: com.insnaps.core.crypto.PeerIdentity, plaintext: ByteArray) {}
            override fun onSessionEstablished(peer: com.insnaps.core.crypto.PeerIdentity) {}
        })
        val engine = MeshEngine(
            config = config,
            clock = clock,
            random = crypto,
            addressing = RotatingTagAddressing(sessions, crypto, clock, ownStaticPublicKey = staticKeys.publicKey),
            transport = SimulatedMesh().transportFor("self"),
            listener = secure,
        )
        secure.engine = engine
        return engine
    }

    /** A maximum-size packet addressed to nobody, so it can only ever be buffered. */
    private fun packet(seed: Int) = Packet(
        header = Packet.Header(
            // The seed must occupy real byte positions: a formula that wraps mod 256
            // silently turns a flood into duplicates the dedupe cache eats first.
            packetId = PacketId(
                ByteArray(PacketId.SIZE).also {
                    it[0] = (seed ushr 24).toByte()
                    it[1] = (seed ushr 16).toByte()
                    it[2] = (seed ushr 8).toByte()
                    it[3] = seed.toByte()
                },
            ),
            ttl = 16,
            lifetimeSeconds = 3000,
            recipientTag = RecipientTag(ByteArray(RecipientTag.SIZE) { (it + 1).toByte() }),
            broadcast = false,
        ),
        payload = ByteArray(Packet.MAX_PAYLOAD_SIZE),
    )
}
