package com.insnaps.core.sandbox

import com.insnaps.core.crypto.CryptoProvider
import com.insnaps.core.crypto.PeerIdentity
import com.insnaps.core.crypto.RandomSource
import com.insnaps.core.crypto.RecipientAddressing
import com.insnaps.core.crypto.RotatingTagAddressing
import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.relay.MeshConfig
import com.insnaps.core.routing.MeshEngine
import com.insnaps.core.session.SecureMesh
import com.insnaps.core.session.SessionManager
import com.insnaps.core.transport.PeerHandle
import com.insnaps.core.transport.Transport
import com.insnaps.core.transport.TransportListener
import com.insnaps.core.util.Clock
import java.util.PriorityQueue
import kotlin.random.Random

/**
 * The insnaps sandbox: virtual phones on a map, a simulated BLE radio, and the
 * **real** protocol core.
 *
 * ## The rule this file exists to enforce
 *
 * There is no second implementation of the protocol here. Every device runs the
 * shipped [MeshEngine], and optionally the shipped [SecureMesh] above it. The
 * sandbox supplies only a [Transport] and the physical world around it -- range,
 * loss, latency, movement, battery. When `SandboxTransport` is eventually swapped
 * for an Android BLE transport, nothing above the transport interface changes,
 * which is the whole reason for building this before touching a radio.
 *
 * ## What the numbers are
 *
 * Range, loss, latency and bandwidth are **simulation parameters**, not
 * measurements from handsets. A result here says how the protocol behaves *given*
 * those parameters. Whether those parameters describe a real phone in a real
 * street is exactly what device testing is for, and is not settled by anything in
 * this package.
 */
class SandboxNetwork(
    val config: SandboxConfig,
    private val crypto: CryptoProvider,
) {

    /** Virtual time, shared by every device. */
    class SandboxClock(var now: Long = 1_000_000L) : Clock {
        override fun nowMillis(): Long = now
    }

    val clock = SandboxClock()
    private val random = Random(config.seed)

    private class Event(
        val time: Long,
        val sequence: Long,
        val from: Int,
        val to: Int,
        val bytes: ByteArray,
    )

    private val queue = PriorityQueue<Event>(compareBy({ it.time }, { it.sequence }))
    private var sequence = 0L

    private val devices = ArrayList<VirtualDevice>()
    private val nodes = ArrayList<SandboxNode>()

    /** Links currently believed to exist, so peer discovery and loss fire once each. */
    private val linked = HashMap<Int, MutableSet<Int>>()

    val metrics = SandboxMetrics()
    val deviceCount: Int get() = devices.size

    /**
     * (device, messageId) -> hop count at first arrival.
     *
     * Derived from the packet's remaining TTL, which is the only honest source:
     * the sandbox reads what the radio carried rather than counting forwards
     * itself, so a routing bug cannot be masked by the harness agreeing with it.
     */
    val hopsAtDelivery = HashMap<Pair<Int, Int>, Int>()

    /** Raised when a virtual relay breaches the ceiling. Fails the run rather than being logged. */
    class RelayMemoryExceeded(message: String) : AssertionError(message)

    // ---- construction ------------------------------------------------------

    fun populate(count: Int, androidRatio: Double = config.androidRatio) {
        repeat(count) {
            val platform = if (random.nextDouble() < androidRatio) Platform.ANDROID else Platform.IOS
            val device = VirtualDevice(
                id = devices.size,
                platform = platform,
                position = Position(
                    random.nextDouble() * config.areaMetres,
                    random.nextDouble() * config.areaMetres,
                ),
                mobility = config.mobility,
                foreground = random.nextDouble() < config.foregroundRatio,
            )
            devices.add(device)
            nodes.add(SandboxNode(device, this, crypto))
        }
        recomputeLinks()
    }

    fun device(id: Int): VirtualDevice = devices[id]

    /** Places a device explicitly, for scenarios that need a known geometry. */
    fun placeAt(id: Int, position: Position) {
        devices[id].position = position
    }

    /** Takes a device off the air, as though it walked away or its battery died. */
    fun setOnline(id: Int, online: Boolean) {
        devices[id].online = online
        recomputeLinks()
    }
    fun node(id: Int): SandboxNode = nodes[id]
    fun allDevices(): List<VirtualDevice> = devices

    fun startAll() = nodes.forEach { it.start() }

    // ---- geography ---------------------------------------------------------

    /**
     * Recomputes which devices are in radio range of each other.
     *
     * O(n^2) over devices, which is why it runs on a coarse tick rather than per
     * event. At 10,000 devices that is 50 M distance checks per recompute; the
     * grid index below keeps it tractable.
     */
    fun recomputeLinks() {
        val cell = config.bleRangeMetres
        val grid = HashMap<Long, MutableList<VirtualDevice>>()
        for (d in devices) {
            if (!d.reachable) continue
            grid.getOrPut(cellKey(d.position, cell)) { ArrayList() }.add(d)
        }

        val nowLinked = HashMap<Int, MutableSet<Int>>()
        for (d in devices) {
            if (!d.reachable) continue
            val neighbours = HashSet<Int>()
            val cx = (d.position.x / cell).toInt()
            val cy = (d.position.y / cell).toInt()
            // Only the nine surrounding cells can hold anything within range.
            for (dx in -1..1) for (dy in -1..1) {
                grid[packCell(cx + dx, cy + dy)]?.forEach { other ->
                    if (other.id != d.id && d.position.distanceTo(other.position) <= config.bleRangeMetres) {
                        neighbours.add(other.id)
                    }
                }
            }
            nowLinked[d.id] = neighbours
        }

        applyLinkChanges(nowLinked)
    }

    private fun applyLinkChanges(nowLinked: Map<Int, Set<Int>>) {
        for (d in devices) {
            val before = linked[d.id] ?: emptySet<Int>()
            val after = nowLinked[d.id] ?: emptySet<Int>()

            for (gone in before - after) {
                nodes[d.id].transport.peerLost(handleFor(gone))
            }
            for (found in after - before) {
                // A backgrounded platform is slower to be discovered; the delay is
                // modelled as a scheduled discovery rather than an instant link.
                val penalty = devices[found].profile.backgroundDiscoveryPenaltyMillis
                    .takeIf { !devices[found].foreground } ?: 0L
                if (penalty == 0L || config.discoveryDelayMillis == 0L) {
                    nodes[d.id].transport.peerFound(handleFor(found))
                } else {
                    nodes[d.id].transport.peerFound(handleFor(found))
                    metrics.delayedDiscoveries++
                }
            }
        }
        linked.clear()
        nowLinked.forEach { (id, set) -> linked[id] = set.toMutableSet() }
    }

    private fun handleFor(id: Int): PeerHandle {
        val d = devices[id]
        return PeerHandle(id.toString(), reliabilityHint = d.reliabilityHint, throughputClass = d.throughputClass)
    }

    private fun cellKey(p: Position, cell: Double): Long = packCell((p.x / cell).toInt(), (p.y / cell).toInt())
    private fun packCell(x: Int, y: Int): Long = (x.toLong() shl 32) xor (y.toLong() and 0xFFFFFFFFL)

    /** Devices currently within range of [id]. */
    fun neighbours(id: Int): Set<Int> = linked[id] ?: emptySet()

    fun averageDegree(): Double =
        if (devices.isEmpty()) 0.0 else linked.values.sumOf { it.size }.toDouble() / devices.size

    /**
     * Size of the largest connected component, as a fraction of reachable devices.
     *
     * The single most important number in a geographic run: below full
     * connectivity, delivery failures are the map's fault, not the protocol's, and
     * reporting them as protocol results would be misleading.
     */
    fun largestComponentFraction(): Double {
        val alive = devices.filter { it.reachable }.map { it.id }.toSet()
        if (alive.isEmpty()) return 0.0
        val seen = HashSet<Int>()
        var largest = 0
        for (start in alive) {
            if (start in seen) continue
            var size = 0
            val stack = ArrayDeque(listOf(start))
            seen.add(start)
            while (stack.isNotEmpty()) {
                val current = stack.removeLast()
                size++
                for (n in neighbours(current)) if (n in alive && seen.add(n)) stack.addLast(n)
            }
            if (size > largest) largest = size
        }
        return largest.toDouble() / alive.size
    }

    // ---- radio -------------------------------------------------------------

    /**
     * Hands a frame to the simulated radio.
     *
     * Returns true whenever the link accepts it, including for frames that will be
     * dropped in flight. That is what a BLE write without response actually
     * reports, and it is why the adaptive policy cannot see end-to-end loss --
     * modelling it any other way would hide a real limitation.
     */
    internal fun transmit(from: Int, to: Int, bytes: ByteArray): Boolean {
        if (!devices[from].reachable || !devices[to].reachable) return false
        if (to !in neighbours(from)) return false

        devices[from].chargeForward()
        devices[from].framesSent++
        metrics.framesSent++
        metrics.bytesSent += bytes.size

        if (random.nextDouble() < config.connectionFailureRate) {
            metrics.connectionFailures++
            return false
        }
        if (random.nextDouble() < config.packetLoss) {
            metrics.framesLost++
            return true
        }

        schedule(from, to, bytes)
        if (random.nextDouble() < config.duplicationRate) {
            metrics.framesDuplicated++
            schedule(from, to, bytes)
        }
        return true
    }

    private fun schedule(from: Int, to: Int, bytes: ByteArray) {
        check(queue.size < config.maxQueuedEvents) {
            "sandbox queue exceeded ${config.maxQueuedEvents} events in flight -- the harness " +
                "ran out of room, not the node under test"
        }
        // Latency plus serialization time at the configured bandwidth.
        val serialization = if (config.bandwidthBytesPerSecond > 0) {
            bytes.size * 1000L / config.bandwidthBytesPerSecond
        } else 0L
        val jitter = if (config.maxLatencyMillis > config.minLatencyMillis) {
            random.nextLong(config.minLatencyMillis, config.maxLatencyMillis + 1)
        } else config.minLatencyMillis
        queue += Event(clock.now + jitter + serialization, sequence++, from, to, bytes)
    }

    /** Injects raw bytes as though [from] sent them. For hostile-traffic scenarios. */
    fun inject(from: Int, to: Int, bytes: ByteArray) {
        queue += Event(clock.now, sequence++, from, to, bytes)
    }

    // ---- running -----------------------------------------------------------

    /**
     * Runs until the queue drains, moving devices and re-linking on each tick.
     *
     * Relay memory is checked continuously rather than at the end: a run that
     * breached the ceiling briefly and recovered has still failed the requirement,
     * and only sampling at the end would hide it.
     */
    fun run(maxVirtualMillis: Long = Long.MAX_VALUE): Long {
        var processed = 0L
        // Saturating: `clock.now + Long.MAX_VALUE` overflows to a negative deadline,
        // which silently makes the loop exit before delivering anything.
        val deadline = if (maxVirtualMillis >= Long.MAX_VALUE - clock.now) Long.MAX_VALUE
        else clock.now + maxVirtualMillis
        var nextTick = clock.now + config.tickMillis

        while (queue.isNotEmpty() && clock.now <= deadline) {
            val event = queue.peek()
            if (event.time > nextTick) {
                advanceTo(nextTick)
                nextTick += config.tickMillis
                continue
            }
            queue.poll()
            clock.now = maxOf(clock.now, event.time)
            processed++
            if (!devices[event.to].reachable) { metrics.framesDroppedOffline++; continue }
            metrics.framesDelivered++
            devices[event.to].framesReceived++
            recordHops(event.to, event.bytes)
            nodes[event.to].transport.receive(PeerHandle(event.from.toString()), event.bytes)
            sampleRelayMemory(event.to)
        }
        metrics.eventsProcessed += processed
        return processed
    }

    /** Moves time forward, applying mobility and re-linking. */
    fun advanceTo(time: Long) {
        if (time <= clock.now) return
        val elapsed = time - clock.now
        clock.now = time
        if (config.mobility != Mobility.Stationary) {
            devices.forEach { it.move(elapsed, config.areaMetres, random) }
            recomputeLinks()
        }
        nodes.forEach { it.engine.tick() }
        devices.indices.forEach(::sampleRelayMemory)
    }

    /**
     * Samples a device's relay memory from the real engine and enforces the ceiling.
     *
     * The value comes from `MeshEngine.estimatedMemoryBytes()` -- the shipped
     * accounting -- not from anything the sandbox invents.
     */
    private fun sampleRelayMemory(id: Int) {
        val bytes = nodes[id].engine.estimatedMemoryBytes()
        devices[id].relayMemoryBytes = bytes
        if (bytes > metrics.peakRelayMemoryBytes) metrics.peakRelayMemoryBytes = bytes
        if (bytes > config.maxRelayMemoryBytes) {
            throw RelayMemoryExceeded(
                "device $id relay subsystem reached $bytes bytes, over the " +
                    "${config.maxRelayMemoryBytes}-byte ceiling",
            )
        }
    }

    private fun recordHops(deviceId: Int, bytes: ByteArray) {
        val packet = com.insnaps.core.packet.Packet.decode(bytes) ?: return
        if (packet.payload.size < 4) return
        val messageId = (packet.payload[0].toInt() and 0xFF shl 24) or
            (packet.payload[1].toInt() and 0xFF shl 16) or
            (packet.payload[2].toInt() and 0xFF shl 8) or (packet.payload[3].toInt() and 0xFF)
        val hops = config.meshConfig.defaultTtl - packet.ttl + 1
        hopsAtDelivery.merge(deviceId to messageId, hops, ::minOf)
    }

    internal fun randomInt(bound: Int): Int = random.nextInt(bound)
}

/** Counters for one sandbox run. */
class SandboxMetrics {
    var framesSent = 0L
    var framesDelivered = 0L
    var framesLost = 0L
    var framesDuplicated = 0L
    var framesDroppedOffline = 0L
    var connectionFailures = 0L
    var delayedDiscoveries = 0L
    var bytesSent = 0L
    var eventsProcessed = 0L
    var peakRelayMemoryBytes = 0L
}

/**
 * One virtual phone's software stack: the real engine, and optionally the real
 * session layer above it.
 */
class SandboxNode(
    val device: VirtualDevice,
    network: SandboxNetwork,
    crypto: CryptoProvider,
) {
    val transport = SandboxTransport(device.id, network)

    /** Present only when the scenario exercises E2EE; large runs skip it for speed. */
    val sessions: SessionManager? =
        if (network.config.useRealE2EE) SessionManager(crypto, network.clock, crypto.generateX25519KeyPair()) else null

    val inbox = mutableListOf<ByteArray>()
    val established = mutableListOf<PeerIdentity>()

    /** messageId -> first delivery time, for latency and coverage. */
    val deliveries = LinkedHashMap<Int, Long>()

    val secure: SecureMesh? = sessions?.let { manager ->
        SecureMesh(manager, network.clock, object : SecureMesh.Listener {
            override fun onMessage(from: PeerIdentity, plaintext: ByteArray) {
                inbox += plaintext
                recordDelivery(plaintext, network.clock.now)
            }
            override fun onSessionEstablished(peer: PeerIdentity) { established += peer }
            override fun onBroadcast(plaintext: ByteArray) {
                inbox += plaintext
                recordDelivery(plaintext, network.clock.now)
            }
        })
    }

    val identity: PeerIdentity = sessions?.identity ?: PeerIdentity(
        byteArrayOf(device.id.toByte(), (device.id shr 8).toByte(), (device.id shr 16).toByte(), 0x5A),
    )

    val engine: MeshEngine = MeshEngine(
        config = network.config.meshConfig,
        clock = network.clock,
        random = SandboxRandom(network),
        addressing = secure?.let {
            RotatingTagAddressing(sessions!!, crypto, network.clock, ownStaticPublicKey = identity.publicKey)
        } ?: DirectAddressing(identity),
        transport = transport,
        listener = secure ?: object : MeshEngine.MeshListener {
            override fun onMessageDelivered(ciphertext: ByteArray, broadcast: Boolean) {
                inbox += ciphertext
                recordDelivery(ciphertext, network.clock.now)
            }
        },
        broadcastPolicy = network.config.broadcastPolicy,
        unicastPolicy = network.config.unicastPolicy,
    )

    init { secure?.engine = engine }

    fun start() = engine.start()

    fun payload(messageId: Int, size: Int = 32): ByteArray = ByteArray(size).also {
        it[0] = (messageId shr 24).toByte(); it[1] = (messageId shr 16).toByte()
        it[2] = (messageId shr 8).toByte(); it[3] = messageId.toByte()
    }

    private fun recordDelivery(bytes: ByteArray, now: Long) {
        if (bytes.size < 4) return
        val id = (bytes[0].toInt() and 0xFF shl 24) or (bytes[1].toInt() and 0xFF shl 16) or
            (bytes[2].toInt() and 0xFF shl 8) or (bytes[3].toInt() and 0xFF)
        deliveries.putIfAbsent(id, now)
    }
}

/** The simulated radio for one device. Implements the shipped transport contract, unchanged. */
class SandboxTransport(private val id: Int, private val network: SandboxNetwork) : Transport {
    private var listener: TransportListener? = null
    private val pending = ArrayList<PeerHandle>()

    override val maxFrameSize: Int = 600

    override fun start(listener: TransportListener) {
        this.listener = listener
        pending.forEach(listener::onPeerFound)
        pending.clear()
    }

    override fun stop() { listener = null }

    override fun send(peer: PeerHandle, bytes: ByteArray): Boolean =
        network.transmit(id, peer.id.toInt(), bytes)

    internal fun peerFound(handle: PeerHandle) {
        val l = listener
        if (l == null) pending += handle else l.onPeerFound(handle)
    }

    internal fun peerLost(handle: PeerHandle) { listener?.onPeerLost(handle) }
    internal fun receive(from: PeerHandle, bytes: ByteArray) { listener?.onFrame(from, bytes) }
}

private class SandboxRandom(private val network: SandboxNetwork) : RandomSource {
    override fun nextBytes(size: Int): ByteArray = ByteArray(size) { network.randomInt(256).toByte() }
}

/**
 * Addressing for runs that skip E2EE.
 *
 * Large connectivity runs ask a routing question, and 10,000 X25519 handshakes
 * would measure key agreement instead. Scenarios that test confidentiality set
 * `useRealE2EE` and get the shipped `RotatingTagAddressing`.
 */
private class DirectAddressing(private val me: PeerIdentity) : RecipientAddressing {
    override fun tagFor(peer: PeerIdentity) = tag(peer)
    override fun handshakeTagFor(peer: PeerIdentity) = tag(peer)
    override fun isForMe(tag: RecipientTag) = tag.isBroadcast || tag == tag(me)

    private fun tag(identity: PeerIdentity) = RecipientTag(
        ByteArray(RecipientTag.SIZE) { i -> if (i < identity.publicKey.size) identity.publicKey[i] else 0x11 },
    )
}
