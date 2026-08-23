package com.insnaps.core

import com.insnaps.core.crypto.Mac
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RandomSource
import com.insnaps.core.crypto.SharedSecretProvider
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.ThroughputClass
import com.insnaps.core.transport.Transport
import com.insnaps.core.transport.TransportListener
import com.insnaps.core.util.Clock

/** Manually advanced clock, so expiry and rotation are tested without waiting. */
class TestClock(private var now: Long = 1_000_000L) : Clock {
    override fun nowMillis(): Long = now
    fun advance(millis: Long) { now += millis }
    fun advanceSeconds(seconds: Long) = advance(seconds * 1000L)
}

/** Deterministic counter-based byte source. Test-only: never acceptable in production. */
class TestRandom(private var counter: Long = 0) : RandomSource {
    override fun nextBytes(size: Int): ByteArray {
        val out = ByteArray(size)
        for (i in out.indices) {
            out[i] = ((counter shr ((i % 8) * 8)) xor (i.toLong() * 31)).toByte()
        }
        counter++
        return out
    }
}

/**
 * Deterministic stand-in for HMAC-SHA256.
 *
 * Test-only. It exercises the key/data mixing and 32-byte contract that
 * `RotatingTagAddressing` depends on; it is NOT a MAC and has none of the
 * security properties of one.
 */
class TestMac : Mac {
    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val out = ByteArray(32)
        var h = -0x340d631b7bdddcdbL // FNV-1a 64-bit offset basis
        for (b in key) { h = (h xor b.toLong()) * FNV_PRIME }
        for (b in data) { h = (h xor b.toLong()) * FNV_PRIME }
        for (i in out.indices) {
            h = (h xor (i.toLong() + 1)) * FNV_PRIME
            out[i] = (h ushr 32).toByte()
        }
        return out
    }
    private companion object { const val FNV_PRIME = 0x100000001b3L }
}

/** In-memory contact list of pairwise secrets. */
class TestSecrets : SharedSecretProvider {
    private val secrets = LinkedHashMap<PeerIdentity, ByteArray>()
    fun add(peer: PeerIdentity, secret: ByteArray) { secrets[peer] = secret }
    override fun secretFor(peer: PeerIdentity): ByteArray? = secrets[peer]
    override fun knownPeers(): List<PeerIdentity> = secrets.keys.toList()
}

fun identity(name: String) = PeerIdentity(name.encodeToByteArray())
fun secret(name: String) = "secret-$name".encodeToByteArray()

/**
 * A simulated radio environment.
 *
 * Nodes are connected by explicit links; a frame is delivered only if a link
 * exists. Delivery is synchronous, which makes assertions deterministic -- there
 * is no scheduler and no waiting anywhere in the suite.
 */
class SimulatedMesh {
    private val transports = LinkedHashMap<String, SimulatedTransport>()
    private val links = LinkedHashMap<String, MutableMap<String, PeerHandle>>()

    /** Frames dropped because no link existed. Detects accidental full-mesh assumptions in tests. */
    var undeliverableFrames = 0
        private set

    /** Total frames put on the air. The measure of whether flooding is under control. */
    var framesSent = 0
        private set

    /**
     * Every frame carried, exactly as a relay or eavesdropper would see it.
     *
     * Test-only, and the point of it is adversarial: it lets a test assert that
     * plaintext never appears in anything the mesh transmits.
     */
    val framesOnAir = mutableListOf<ByteArray>()

    fun transportFor(nodeId: String): SimulatedTransport =
        transports.getOrPut(nodeId) { SimulatedTransport(nodeId, this) }

    /** Connects two nodes. [reliability] and [throughput] are what the platform layer would report. */
    fun link(
        a: String,
        b: String,
        reliability: Double = 1.0,
        throughput: ThroughputClass = ThroughputClass.LOW,
    ) {
        connect(a, b, reliability, throughput)
        connect(b, a, reliability, throughput)
    }

    fun unlink(a: String, b: String) {
        links[a]?.remove(b)?.let { transports[a]?.listener?.onPeerLost(it) }
        links[b]?.remove(a)?.let { transports[b]?.listener?.onPeerLost(it) }
    }

    private fun connect(from: String, to: String, reliability: Double, throughput: ThroughputClass) {
        val handle = PeerHandle(id = to, reliabilityHint = reliability, throughputClass = throughput)
        links.getOrPut(from) { LinkedHashMap() }[to] = handle
        transports[from]?.listener?.onPeerFound(handle)
    }

    internal fun neighbours(nodeId: String): Collection<PeerHandle> =
        links[nodeId]?.values ?: emptyList()

    internal fun deliver(from: String, to: String, bytes: ByteArray): Boolean {
        if (links[from]?.containsKey(to) != true) {
            undeliverableFrames++
            return false
        }
        val target = transports[to] ?: return false
        val listener = target.listener ?: return false
        framesSent++
        framesOnAir += bytes
        // The receiving node sees a handle for the *sender*, which is how the router
        // knows not to forward the packet straight back where it came from.
        listener.onFrame(PeerHandle(from), bytes)
        return true
    }
}

class SimulatedTransport(private val nodeId: String, private val mesh: SimulatedMesh) : Transport {
    internal var listener: TransportListener? = null
        private set

    override val maxFrameSize: Int = 600

    override fun start(listener: TransportListener) {
        this.listener = listener
        // Announce neighbours that were linked before this node started.
        mesh.neighbours(nodeId).forEach(listener::onPeerFound)
    }

    override fun stop() { listener = null }

    override fun send(peer: PeerHandle, bytes: ByteArray): Boolean =
        mesh.deliver(nodeId, peer.id, bytes)
}
