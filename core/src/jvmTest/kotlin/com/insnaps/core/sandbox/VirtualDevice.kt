package com.insnaps.core.sandbox

import com.insnaps.core.transport.ThroughputClass
import kotlin.math.hypot
import kotlin.random.Random

/** Which mobile platform a virtual phone is running. There is no desktop option, by design. */
enum class Platform { ANDROID, IOS }

/**
 * How a platform behaves as a relay.
 *
 * The two platforms are not interchangeable and the sandbox must not pretend they
 * are: a backgrounded iOS app advertises in a degraded form and a suspended one
 * stops relaying, while Android can hold a foreground service. Modelling both as
 * "a phone" would make every result optimistic in exactly the way that matters.
 *
 * These are *simulation parameters*, not measurements from real handsets. They
 * encode the documented platform asymmetry so its consequences show up in
 * results; they do not claim to predict a specific device.
 */
data class PlatformProfile(
    val platform: Platform,
    val foregroundReliability: Double,
    val backgroundReliability: Double,
    /** Whether the OS lets the app relay at all while backgrounded. */
    val relaysInBackground: Boolean,
    /** Extra delay before a peer is discovered while backgrounded, in milliseconds. */
    val backgroundDiscoveryPenaltyMillis: Long,
) {
    fun reliability(foreground: Boolean): Double =
        if (foreground) foregroundReliability else backgroundReliability

    companion object {
        /**
         * Android with a foreground service: a dependable relay in both states,
         * at the cost of a persistent notification.
         */
        val ANDROID = PlatformProfile(
            platform = Platform.ANDROID,
            foregroundReliability = 0.95,
            backgroundReliability = 0.75,
            relaysInBackground = true,
            backgroundDiscoveryPenaltyMillis = 500,
        )

        /**
         * iOS backgrounded: still advertising, but degraded and interruptible.
         *
         * `relaysInBackground` is true because a backgrounded app can still be
         * woken for BLE events -- but the low reliability and discovery penalty
         * reflect that it cannot be counted on.
         */
        val IOS = PlatformProfile(
            platform = Platform.IOS,
            foregroundReliability = 0.95,
            backgroundReliability = 0.30,
            relaysInBackground = true,
            backgroundDiscoveryPenaltyMillis = 3_000,
        )

        fun of(platform: Platform) = if (platform == Platform.ANDROID) ANDROID else IOS
    }
}

/** A position in metres inside the simulated area. */
data class Position(val x: Double, val y: Double) {
    fun distanceTo(other: Position): Double = hypot(x - other.x, y - other.y)
}

/** How a virtual user moves. Speeds are metres per second. */
sealed interface Mobility {
    data object Stationary : Mobility

    /** Aimless drift, e.g. someone milling around a venue. */
    data class RandomWalk(val speedMetresPerSecond: Double = 1.4) : Mobility

    /** Walking pace, roughly 5 km/h. */
    data class Walking(val speedMetresPerSecond: Double = 1.4) : Mobility

    /** Vehicle pace, roughly 50 km/h. Fast enough to break links between ticks. */
    data class Vehicle(val speedMetresPerSecond: Double = 13.9) : Mobility

    val speed: Double
        get() = when (this) {
            is Stationary -> 0.0
            is RandomWalk -> speedMetresPerSecond
            is Walking -> speedMetresPerSecond
            is Vehicle -> speedMetresPerSecond
        }
}

/**
 * One virtual phone.
 *
 * Models a device's *network-relevant* state only. It does not emulate Android or
 * iOS APIs, and nothing here should be read as doing so -- it captures where a
 * phone is, whether it can currently relay, and how dependable it is.
 */
class VirtualDevice(
    val id: Int,
    val platform: Platform,
    var position: Position,
    var mobility: Mobility = Mobility.Stationary,
    /** 0.0..1.0. Drains with forwarding and gates relaying when depleted. */
    var battery: Double = 1.0,
    var online: Boolean = true,
    var bleEnabled: Boolean = true,
    var foreground: Boolean = true,
    var relayEnabled: Boolean = true,
) {
    val profile: PlatformProfile = PlatformProfile.of(platform)

    /** Heading in radians, kept between ticks so movement is smooth rather than jittery. */
    internal var heading: Double = 0.0

    /** Relay memory in bytes, sampled from the real engine. Never estimated by the sandbox. */
    var relayMemoryBytes: Long = 0
        internal set

    var framesSent: Long = 0
        internal set
    var framesReceived: Long = 0
        internal set

    /** True if this device can currently take part in the mesh at all. */
    val reachable: Boolean
        get() = online && bleEnabled && battery > BATTERY_CUTOFF

    /** True if it will forward for others, as opposed to only sending its own traffic. */
    val relaying: Boolean
        get() = reachable && relayEnabled && (foreground || profile.relaysInBackground)

    /** What the transport reports upward. The core never learns the platform itself. */
    val reliabilityHint: Double
        get() = if (!relaying) 0.0 else profile.reliability(foreground) * batteryFactor()

    val throughputClass: ThroughputClass get() = ThroughputClass.LOW

    /**
     * Charges a forward against the battery.
     *
     * A crude proxy: a fixed cost per frame. It exists so that a node relaying
     * heavily becomes less attractive over time, which is the behaviour that
     * matters for routing. It is not a power model and must not be reported as
     * battery consumption in hours.
     */
    fun chargeForward(frames: Int = 1) {
        battery = (battery - frames * BATTERY_COST_PER_FRAME).coerceAtLeast(0.0)
    }

    /** Advances position by [elapsedMillis] under the mobility model. */
    fun move(elapsedMillis: Long, areaMetres: Double, random: Random) {
        if (mobility is Mobility.Stationary) return
        val seconds = elapsedMillis / 1000.0
        if (mobility is Mobility.RandomWalk || random.nextDouble() < HEADING_CHANGE_CHANCE) {
            heading = random.nextDouble() * 2 * Math.PI
        }
        val distance = mobility.speed * seconds
        var nx = position.x + distance * kotlin.math.cos(heading)
        var ny = position.y + distance * kotlin.math.sin(heading)

        // Reflect at the boundary rather than wrapping: wrapping would teleport a
        // device across the map and manufacture links that geography forbids.
        if (nx < 0 || nx > areaMetres) { heading = Math.PI - heading; nx = nx.coerceIn(0.0, areaMetres) }
        if (ny < 0 || ny > areaMetres) { heading = -heading; ny = ny.coerceIn(0.0, areaMetres) }
        position = Position(nx, ny)
    }

    private fun batteryFactor(): Double = when {
        battery > 0.5 -> 1.0
        battery > 0.2 -> 0.8
        else -> 0.5
    }

    override fun toString(): String = "Device($id, $platform, ${if (relaying) "relaying" else "passive"})"

    private companion object {
        const val BATTERY_CUTOFF = 0.02
        const val BATTERY_COST_PER_FRAME = 0.000002
        const val HEADING_CHANGE_CHANCE = 0.1
    }
}
