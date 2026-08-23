package com.insnaps.core.sim

import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RandomSource
import com.insnaps.core.crypto.RecipientAddressing
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.ForwardingPolicy
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.ThroughputClass
import com.insnaps.core.transport.Transport
import com.insnaps.core.transport.TransportListener
import com.insnaps.core.util.Clock
import java.util.PriorityQueue
import kotlin.random.Random

/**
 * Deterministic, event-driven mesh simulator for scale and adversarial testing.
 *
 * ## Why not reuse `SimulatedMesh`
 *
 * The existing harness delivers frames synchronously on the calling thread, which
 * is fine for a five-node correctness test and impossible at scale: one broadcast
 * across a dense graph becomes a recursion thousands of frames deep and overflows
 * the stack. This one queues every transmission as a timestamped event and drains
 * the queue iteratively, so depth is bounded regardless of node count.
 *
 * ## Determinism
 *
 * Everything stochastic -- latency, loss, duplication, churn, gossip coin flips --
 * draws from one seeded generator, and events with equal timestamps break ties on
 * a monotonic sequence number rather than insertion order. A given seed therefore
 * replays exactly, which is what makes a stress failure reproducible instead of a
 * story about something that happened once.
 *
 * Test-only: this lives in `jvmTest` and is not part of the shipped core.
 */
class SimNetwork(
    val seed: Long,
    val config: SimConfig = SimConfig(),
) {

    data class SimConfig(
        /** Probability a transmitted frame never arrives. */
        val lossRate: Double = 0.0,
        /** Probability an arriving frame is delivered twice. */
        val duplicateRate: Double = 0.0,
        val minLatencyMillis: Long = 20,
        val maxLatencyMillis: Long = 120,
        val meshConfig: MeshConfig = MeshConfig(),
        val broadcastPolicy: ForwardingPolicy = ForwardingPolicy.AdaptiveFanout(),
        val unicastPolicy: ForwardingPolicy = ForwardingPolicy.BoundedFanout(3),
        /** Safety valve so a runaway topology fails the test rather than hanging it. */
        val maxEvents: Long = 50_000_000,
        /**
         * Cap on events in flight at once.
         *
         * Without it a test that injects heavily into a well-connected graph
         * exhausts the simulator's own heap before it ever measures the node --
         * failing as an OutOfMemoryError that looks like a protocol result. This
         * fails loudly instead, naming the harness as the thing that ran out.
         */
        val maxQueuedEvents: Int = 2_000_000,
    ) {
        init {
            require(lossRate in 0.0..1.0)
            require(duplicateRate in 0.0..1.0)
            require(minLatencyMillis in 0..maxLatencyMillis)
        }
    }

    private val random = Random(seed)

    /** Virtual time. Nothing sleeps; the clock jumps to the next scheduled event. */
    val clock = VirtualClock()

    private class Event(
        val time: Long,
        val sequence: Long,
        val from: Int,
        val to: Int,
        val bytes: ByteArray,
    )

    private val queue = PriorityQueue<Event>(compareBy({ it.time }, { it.sequence }))
    private var sequence = 0L

    private val nodes = ArrayList<SimNode>()
    private val links = ArrayList<MutableSet<Int>>()
    private val down = HashSet<Int>()

    val metrics = SimMetrics()
    val nodeCount: Int get() = nodes.size

    // ---- construction ------------------------------------------------------

    fun addNodes(count: Int) {
        repeat(count) {
            val id = nodes.size
            val transport = SimTransport(id, this)
            val node = SimNode(id, transport, this)
            nodes.add(node)
            // Explicit add: `+=` on a list of collections resolves to the wrong
            // overload and silently builds a new list instead of appending.
            links.add(HashSet())
        }
    }

    fun node(id: Int): SimNode = nodes[id]

    /** Bidirectional link. Reliability and throughput are what a platform layer would report. */
    fun link(a: Int, b: Int, reliability: Double = 0.9, throughput: ThroughputClass = ThroughputClass.LOW) {
        if (a == b || links[a].contains(b)) return
        links[a] += b
        links[b] += a
        nodes[a].transport.peerAppeared(handle(b, reliability, throughput))
        nodes[b].transport.peerAppeared(handle(a, reliability, throughput))
    }

    fun neighbours(id: Int): Set<Int> = links[id]

    fun degreeOf(id: Int): Int = links[id].size

    fun averageDegree(): Double = if (nodes.isEmpty()) 0.0 else links.sumOf { it.size }.toDouble() / nodes.size

    private fun handle(id: Int, reliability: Double, throughput: ThroughputClass) =
        PeerHandle(id.toString(), reliabilityHint = reliability, throughputClass = throughput)

    // ---- churn -------------------------------------------------------------

    /** Takes a node off the air: its neighbours see it vanish, as on a real radio. */
    fun disconnect(id: Int) {
        if (!down.add(id)) return
        for (peer in links[id]) {
            nodes[peer].transport.peerLost(PeerHandle(id.toString()))
        }
        nodes[id].transport.allPeersLost(links[id].map { PeerHandle(it.toString()) })
        metrics.disconnects++
    }

    fun reconnect(id: Int, reliability: Double = 0.9) {
        if (!down.remove(id)) return
        for (peer in links[id]) {
            nodes[peer].transport.peerAppeared(handle(id, reliability, ThroughputClass.LOW))
            nodes[id].transport.peerAppeared(handle(peer, reliability, ThroughputClass.LOW))
        }
        metrics.reconnects++
    }

    fun isDown(id: Int): Boolean = id in down

    // ---- transmission ------------------------------------------------------

    /**
     * Queues a frame for delivery, applying loss and duplication.
     *
     * Returns true even for a frame that will be lost: a BLE write without
     * response reports success once the link accepts it, and a transport that
     * claimed otherwise would be modelling a guarantee the radio does not give.
     */
    internal fun transmit(from: Int, to: Int, bytes: ByteArray): Boolean {
        if (from in down || to in down) return false
        if (!links[from].contains(to)) return false

        metrics.framesSent++
        metrics.bytesSent += bytes.size

        if (random.nextDouble() < config.lossRate) {
            metrics.framesLost++
            return true
        }

        schedule(from, to, bytes)
        if (random.nextDouble() < config.duplicateRate) {
            metrics.framesDuplicated++
            schedule(from, to, bytes)
        }
        return true
    }

    private fun schedule(from: Int, to: Int, bytes: ByteArray) {
        val latency = if (config.maxLatencyMillis == config.minLatencyMillis) {
            config.minLatencyMillis
        } else {
            random.nextLong(config.minLatencyMillis, config.maxLatencyMillis + 1)
        }
        enqueue(Event(clock.now + latency, sequence++, from, to, bytes))
    }

    private fun enqueue(event: Event) {
        check(queue.size < config.maxQueuedEvents) {
            "simulator queue exceeded ${config.maxQueuedEvents} events in flight -- " +
                "the harness ran out of room, not the node under test. Reduce the injection " +
                "count or use a smaller topology."
        }
        queue += event
    }

    /** Injects raw bytes at [to] as though [from] had sent them. Used for hostile traffic. */
    fun inject(from: Int, to: Int, bytes: ByteArray) {
        enqueue(Event(clock.now, sequence++, from, to, bytes))
    }

    // ---- running -----------------------------------------------------------

    /**
     * Drains the event queue, advancing virtual time.
     *
     * Returns the number of events processed. Fails loudly past
     * [SimConfig.maxEvents] rather than hanging a test run.
     */
    fun run(): Long {
        var processed = 0L
        while (queue.isNotEmpty()) {
            check(processed < config.maxEvents) {
                "event budget exhausted after $processed events -- likely a broadcast storm"
            }
            val event = queue.poll()
            clock.now = maxOf(clock.now, event.time)
            processed++
            if (event.to in down) continue
            metrics.framesDelivered++
            nodes[event.to].transport.receive(PeerHandle(event.from.toString()), event.bytes)
        }
        metrics.eventsProcessed += processed
        return processed
    }

    /**
     * Processes at most [maxEvents] events, so a test can interrupt a run to
     * disconnect nodes, inject traffic, or take a measurement mid-flight.
     */
    fun runSteps(maxEvents: Long): Long {
        var processed = 0L
        while (queue.isNotEmpty() && processed < maxEvents) {
            val event = queue.poll()
            clock.now = maxOf(clock.now, event.time)
            processed++
            if (event.to in down) continue
            metrics.framesDelivered++
            nodes[event.to].transport.receive(PeerHandle(event.from.toString()), event.bytes)
        }
        metrics.eventsProcessed += processed
        return processed
    }

    fun hasPendingEvents(): Boolean = queue.isNotEmpty()

    /** Advances virtual time without delivering anything, so timers and expiry fire. */
    fun advance(millis: Long) {
        clock.now += millis
    }

    /** Housekeeping tick on every node, as a real app would run on a timer. */
    fun tickAll() {
        nodes.forEach { it.engine.tick() }
    }

    // ---- measurement -------------------------------------------------------

    fun totalEstimatedMemory(): Long = nodes.sumOf { it.engine.estimatedMemoryBytes() }

    fun peakNodeMemory(): Long = nodes.maxOfOrNull { it.engine.estimatedMemoryBytes() } ?: 0

    fun aggregateStats(): MeshEngine.Stats {
        val total = MeshEngine.Stats()
        for (node in nodes) {
            val s = node.engine.stats
            total.framesReceived += s.framesReceived
            total.malformedDropped += s.malformedDropped
            total.duplicatesDropped += s.duplicatesDropped
            total.expiredDropped += s.expiredDropped
            total.hopLimitDropped += s.hopLimitDropped
            total.quotaDropped += s.quotaDropped
            total.delivered += s.delivered
            total.forwarded += s.forwarded
            total.originated += s.originated
        }
        return total
    }

    internal fun randomDouble(): Double = random.nextDouble()
    internal fun randomInt(bound: Int): Int = random.nextInt(bound)
}

/** Manually advanced clock shared by every node in a run. */
class VirtualClock(var now: Long = 1_000_000L) : Clock {
    override fun nowMillis(): Long = now
}

/** Counters describing a whole simulation run. */
class SimMetrics {
    var framesSent = 0L
    var framesDelivered = 0L
    var framesLost = 0L
    var framesDuplicated = 0L
    var bytesSent = 0L
    var eventsProcessed = 0L
    var disconnects = 0L
    var reconnects = 0L

    override fun toString(): String =
        "sent=$framesSent delivered=$framesDelivered lost=$framesLost dup=$framesDuplicated " +
            "bytes=$bytesSent events=$eventsProcessed"
}

/**
 * One simulated participant: a real [MeshEngine] over a simulated radio.
 *
 * The engine is the shipped one -- routing, buffering, expiry and quotas are all
 * production code paths. Only the transport and the addressing stub are synthetic.
 */
class SimNode(val id: Int, val transport: SimTransport, network: SimNetwork) {

    val identity = PeerIdentity(byteArrayOf(id.toByte(), (id shr 8).toByte(), (id shr 16).toByte(), 0x5A))

    /** messageId -> virtual time of first delivery. */
    val deliveries = LinkedHashMap<Int, Long>()

    private val clock = network.clock

    val engine: MeshEngine = MeshEngine(
        config = network.config.meshConfig,
        clock = clock,
        random = SimRandom(network),
        addressing = SimAddressing(identity),
        transport = transport,
        listener = object : MeshEngine.MeshListener {
            override fun onMessageDelivered(ciphertext: ByteArray, broadcast: Boolean) {
                if (ciphertext.size >= 4) {
                    val messageId = (ciphertext[0].toInt() and 0xFF shl 24) or
                        (ciphertext[1].toInt() and 0xFF shl 16) or
                        (ciphertext[2].toInt() and 0xFF shl 8) or
                        (ciphertext[3].toInt() and 0xFF)
                    deliveries.putIfAbsent(messageId, clock.nowMillis())
                }
            }
        },
        broadcastPolicy = network.config.broadcastPolicy,
        unicastPolicy = network.config.unicastPolicy,
    )

    fun start() = engine.start()

    /** Body large enough to carry a message id, padded to [size]. */
    fun payload(messageId: Int, size: Int = 32): ByteArray = ByteArray(size).also {
        it[0] = (messageId shr 24).toByte()
        it[1] = (messageId shr 16).toByte()
        it[2] = (messageId shr 8).toByte()
        it[3] = messageId.toByte()
    }
}

/** Seeded randomness for the engine, so gossip coin flips replay with the seed. */
private class SimRandom(private val network: SimNetwork) : RandomSource {
    override fun nextBytes(size: Int): ByteArray =
        ByteArray(size) { (network.randomInt(256)).toByte() }
}

/**
 * Addressing stub: a tag derived directly from the recipient's identity.
 *
 * Deliberately skips real cryptography. These tests ask a routing question --
 * whether traffic reaches its destination without flooding or exhausting memory --
 * and running 10,000 X25519 handshakes to ask it would measure the wrong thing.
 * Cryptographic behaviour is covered by the session-layer suites.
 */
private class SimAddressing(private val me: PeerIdentity) : RecipientAddressing {
    override fun tagFor(peer: PeerIdentity): RecipientTag = tag(peer)
    override fun handshakeTagFor(peer: PeerIdentity): RecipientTag = tag(peer)
    override fun isForMe(tag: RecipientTag): Boolean = tag.isBroadcast || tag == tag(me)

    private fun tag(identity: PeerIdentity): RecipientTag =
        RecipientTag(ByteArray(RecipientTag.SIZE) { index ->
            if (index < identity.publicKey.size) identity.publicKey[index] else 0x11
        })
}

/** Simulated radio for one node. Implements the same six-operation contract as a real transport. */
class SimTransport(private val id: Int, private val network: SimNetwork) : Transport {

    private var listener: TransportListener? = null
    private val pendingPeers = ArrayList<PeerHandle>()

    override val maxFrameSize: Int = 600

    override fun start(listener: TransportListener) {
        this.listener = listener
        pendingPeers.forEach(listener::onPeerFound)
        pendingPeers.clear()
    }

    override fun stop() { listener = null }

    override fun send(peer: PeerHandle, bytes: ByteArray): Boolean =
        network.transmit(id, peer.id.toInt(), bytes)

    internal fun peerAppeared(handle: PeerHandle) {
        val l = listener
        if (l == null) pendingPeers += handle else l.onPeerFound(handle)
    }

    internal fun peerLost(handle: PeerHandle) { listener?.onPeerLost(handle) }

    internal fun allPeersLost(handles: List<PeerHandle>) { handles.forEach { listener?.onPeerLost(it) } }

    internal fun receive(from: PeerHandle, bytes: ByteArray) { listener?.onFrame(from, bytes) }
}
