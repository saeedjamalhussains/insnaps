package com.insnaps.core.transport

/**
 * The complete boundary between the protocol core and the radios.
 *
 * The core does not know that BLE, Wi-Fi Aware, Wi-Fi Direct or
 * MultipeerConnectivity exist. It sends opaque bytes to a [PeerHandle] and
 * receives opaque bytes back. This is what keeps `commonMain` testable on the
 * JVM with a simulated mesh and no radios at all.
 *
 * Platform notes that must NOT leak upward through this interface:
 *
 *  - BLE is the only link that carries Android <-> iOS traffic. Wi-Fi Aware /
 *    Wi-Fi Direct (Android) and MultipeerConnectivity (iOS) do not interoperate,
 *    so they are same-platform accelerators only. Choosing among them is the
 *    implementation's job, reported upward only as [PeerHandle.throughputClass].
 *  - A backgrounded iOS app advertises without its local name and with service
 *    UUIDs in the overflow area, and a suspended one does not relay at all. That
 *    unreliability is reported upward only as [PeerHandle.reliabilityHint].
 *
 * ## Threading contract (binding on every implementation)
 *
 * The protocol core is **not** thread-safe and is not going to be: its state is a
 * set of plain maps, and locking every access would cost more than it buys on a
 * workload this small.
 *
 * Implementations MUST therefore deliver every [TransportListener] callback on a
 * single thread, and callers MUST invoke [start], [stop] and [send] on that same
 * thread. In practice that means one serial dispatch queue or handler owning the
 * node.
 *
 * This matters because the platform APIs do not do it by default: Android's
 * `BluetoothGattCallback` fires on binder threads, and CoreBluetooth delivers on
 * whichever queue was passed to `CBCentralManager`. Both must be funnelled onto
 * the node's own queue before reaching the core. Getting this wrong produces
 * `ConcurrentModificationException` under load rather than at first light.
 */
interface Transport {
    /** Begins advertising this device and scanning for peers. Idempotent. */
    fun start(listener: TransportListener)

    /** Stops advertising, scanning and all links. Idempotent. */
    fun stop()

    /**
     * Attempts to hand [bytes] to [peer].
     *
     * Returns false if the link is unusable right now; the caller keeps the packet
     * queued and retries. Implementations must not block.
     */
    fun send(peer: PeerHandle, bytes: ByteArray): Boolean

    /** Largest payload this transport will carry in one call, in bytes. */
    val maxFrameSize: Int
}

interface TransportListener {
    fun onPeerFound(peer: PeerHandle)
    fun onPeerLost(peer: PeerHandle)

    /** A frame arrived from [peer]. [bytes] is untrusted and may be malformed. */
    fun onFrame(peer: PeerHandle, bytes: ByteArray)
}

/**
 * An opaque handle to a currently reachable neighbour.
 *
 * [id] is a transport-scoped ephemeral identifier, not an identity: it is the
 * local handle for a radio link and must not be derived from, or correlate with,
 * the peer's long-term identity key.
 */
class PeerHandle(
    val id: String,
    /**
     * How much the router should trust this neighbour to still be there, and to
     * actually forward, on a 0.0..1.0 scale.
     *
     * The platform implementation owns this number, precisely so the core never
     * has to reason about background execution limits. A backgrounded iOS peer
     * scores low; a foreground Android peer holding a foreground service scores
     * high.
     */
    val reliabilityHint: Double = 0.5,
    val throughputClass: ThroughputClass = ThroughputClass.LOW,
) {
    init {
        require(reliabilityHint in 0.0..1.0) { "reliabilityHint must be in 0.0..1.0" }
    }

    override fun equals(other: Any?): Boolean = this === other || (other is PeerHandle && id == other.id)
    override fun hashCode(): Int = id.hashCode()
    override fun toString(): String = "Peer($id)"
}

/** Coarse link speed, used to prefer accelerated links without naming the radio. */
enum class ThroughputClass {
    /** BLE-class: the universal, slow path. Assume single-digit KB/s. */
    LOW,

    /** A same-platform Wi-Fi accelerator. */
    HIGH,
}
