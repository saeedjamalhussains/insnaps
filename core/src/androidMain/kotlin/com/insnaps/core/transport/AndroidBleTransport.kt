package com.insnaps.core.transport

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelUuid
import com.insnaps.core.link.LinkFraming
import com.insnaps.core.link.LinkReassembler
import com.insnaps.core.packet.Packet
import com.insnaps.core.util.Clock
import java.util.UUID

/**
 * Android BLE implementation of [Transport].
 *
 * Nothing above this class knows BLE exists. It satisfies the same six-operation
 * contract the sandbox does, so `MeshEngine`, `SecureMesh` and the E2EE layer are
 * untouched by its arrival — which is the payoff of having built the sandbox
 * against the same interface.
 *
 * ## Every device is both central and peripheral
 *
 * A mesh has no clients and servers. Each node advertises a GATT service *and*
 * scans for others, so any two phones in range can link whichever way round they
 * discover each other. The peer id is the device address, which Android already
 * randomises for privacy.
 *
 * ## Threading
 *
 * The core is single-threaded by contract (PROTOCOL.md §12). Android delivers GATT
 * callbacks on binder threads, so **every** callback here is re-posted onto one
 * private [HandlerThread] before it reaches the listener. Getting this wrong
 * produces `ConcurrentModificationException` under load rather than at first
 * light, which is the worst possible failure mode to debug on a phone.
 *
 * ## Fragmentation
 *
 * A full insnaps packet is 543 bytes and the largest possible ATT write is 514 —
 * 20 before MTU negotiation. [LinkFraming] splits and reassembles; the protocol is
 * unchanged.
 *
 * ## Not yet validated on hardware
 *
 * This compiles and its logic is unit-tested, but no two phones have run it. MTU
 * negotiation, connection stability, OEM stack quirks, background behaviour and
 * throughput are all unmeasured — see docs/TESTING.md layer 3.
 */
@SuppressLint("MissingPermission")
class AndroidBleTransport(
    private val context: Context,
    private val clock: Clock,
    /**
     * Reported upward for routing decisions. The platform layer owns this figure
     * precisely so the core never learns what "backgrounded" means.
     */
    private val reliabilityHint: () -> Double = { 0.9 },
) : Transport {

    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter get() = bluetoothManager.adapter

    private val thread = HandlerThread("insnaps-ble").apply { start() }
    private val handler = Handler(thread.looper)

    private val reassembler = LinkReassembler(clock)
    private val connections = HashMap<String, BluetoothGatt>()
    private val serverLinks = HashMap<String, BluetoothDevice>()
    private val mtus = HashMap<String, Int>()
    private var sequence = 0

    private var listener: TransportListener? = null
    private var gattServer: BluetoothGattServer? = null
    private var writeCharacteristic: BluetoothGattCharacteristic? = null

    /**
     * Conservative until a peer negotiates upward.
     *
     * The core asks this once, so it must be a figure that always works rather
     * than the best case: a packet is fragmented to whatever the link turns out
     * to support at send time.
     */
    override val maxFrameSize: Int = Packet.MAX_PACKET_SIZE

    // ---- lifecycle ---------------------------------------------------------

    override fun start(listener: TransportListener) {
        handler.post {
            if (this.listener != null) return@post // idempotent, as the contract requires
            this.listener = listener
            startGattServer()
            startAdvertising()
            startScanning()
        }
    }

    override fun stop() {
        handler.post {
            stopAdvertising()
            stopScanning()
            connections.values.forEach { runCatching { it.close() } }
            connections.clear()
            serverLinks.clear()
            mtus.clear()
            runCatching { gattServer?.close() }
            gattServer = null
            reassembler.clear()
            listener = null
        }
    }

    override fun send(peer: PeerHandle, bytes: ByteArray): Boolean {
        // Called on the core's thread, which is this handler's thread.
        val characteristic = writeCharacteristic ?: return false
        val frameSize = (mtus[peer.id] ?: DEFAULT_MTU) - ATT_HEADER_BYTES
        if (!LinkFraming.fits(bytes.size, frameSize)) return false

        val frames = LinkFraming.fragment(bytes, frameSize, sequence++ and 0xFF)

        // A connected central takes a notification; otherwise we are the central
        // and write to the peer's characteristic. Either direction carries the
        // same bytes, which is what lets any two phones link either way round.
        serverLinks[peer.id]?.let { device ->
            val server = gattServer ?: return false
            return frames.all { frame -> notify(server, device, characteristic, frame) }
        }
        val gatt = connections[peer.id] ?: return false
        return frames.all { frame -> write(gatt, frame) }
    }

    // ---- peripheral role ---------------------------------------------------

    private fun startGattServer() {
        val characteristic = BluetoothGattCharacteristic(
            CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or
                BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        writeCharacteristic = characteristic

        val service = BluetoothGattService(SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        service.addCharacteristic(characteristic)

        gattServer = bluetoothManager.openGattServer(context, serverCallback)?.apply { addService(service) }
    }

    private val serverCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            handler.post {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    serverLinks[device.address] = device
                    listener?.onPeerFound(handleFor(device.address))
                } else {
                    serverLinks.remove(device.address)
                    reassembler.forget(device.address)
                    listener?.onPeerLost(handleFor(device.address))
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            // Copy: the framework may reuse this buffer once we return.
            val frame = value.copyOf()
            handler.post { deliver(device.address, frame) }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            handler.post { mtus[device.address] = mtu }
        }
    }

    // ---- central role ------------------------------------------------------

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device
            handler.post {
                if (connections.containsKey(device.address) || serverLinks.containsKey(device.address)) return@post
                connections[device.address] = device.connectGatt(
                    context, false, gattCallback, BluetoothDevice.TRANSPORT_LE,
                )
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            handler.post {
                val address = gatt.device.address
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    // Ask for the largest MTU up front; without this every packet
                    // fragments into 20-byte pieces.
                    gatt.requestMtu(MAX_MTU)
                } else {
                    connections.remove(address)?.close()
                    reassembler.forget(address)
                    listener?.onPeerLost(handleFor(address))
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            handler.post {
                mtus[gatt.device.address] = mtu
                gatt.discoverServices()
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            handler.post {
                val characteristic = gatt.getService(SERVICE_UUID)?.getCharacteristic(CHARACTERISTIC_UUID)
                if (characteristic == null) {
                    // Not an insnaps node after all.
                    connections.remove(gatt.device.address)?.close()
                    return@post
                }
                gatt.setCharacteristicNotification(characteristic, true)
                listener?.onPeerFound(handleFor(gatt.device.address))
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            val frame = value.copyOf()
            handler.post { deliver(gatt.device.address, frame) }
        }
    }

    // ---- shared ------------------------------------------------------------

    /** Reassembles, then hands whole packets up. The core never sees a fragment. */
    private fun deliver(address: String, frame: ByteArray) {
        val packet = reassembler.offer(address, frame) ?: return
        listener?.onFrame(handleFor(address), packet)
    }

    private fun handleFor(address: String) = PeerHandle(
        id = address,
        reliabilityHint = reliabilityHint(),
        throughputClass = ThroughputClass.LOW,
    )

    private fun startAdvertising() {
        adapter?.bluetoothLeAdvertiser?.startAdvertising(
            AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
                .setConnectable(true)
                .build(),
            // The service UUID only. No device name: it is a stable identifier
            // that would let anyone in range track the handset across sessions.
            AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(SERVICE_UUID))
                .build(),
            advertiseCallback,
        )
    }

    private fun stopAdvertising() {
        runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
    }

    private val advertiseCallback = object : AdvertiseCallback() {}

    private fun startScanning() {
        adapter?.bluetoothLeScanner?.startScan(
            listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()),
            ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
            scanCallback,
        )
    }

    private fun stopScanning() {
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCallback) }
    }

    @Suppress("DEPRECATION")
    private fun write(gatt: BluetoothGatt, frame: ByteArray): Boolean {
        val characteristic = gatt.getService(SERVICE_UUID)?.getCharacteristic(CHARACTERISTIC_UUID)
            ?: return false
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeCharacteristic(
                characteristic, frame, BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE,
            ) == BluetoothGatt.GATT_SUCCESS
        } else {
            characteristic.value = frame
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            gatt.writeCharacteristic(characteristic)
        }
    }

    @Suppress("DEPRECATION")
    private fun notify(
        server: BluetoothGattServer,
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        frame: ByteArray,
    ): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        server.notifyCharacteristicChanged(device, characteristic, false, frame) == BluetoothGatt.GATT_SUCCESS
    } else {
        characteristic.value = frame
        server.notifyCharacteristicChanged(device, characteristic, false)
    }

    /** Bytes held in reassembly, so link buffers count toward the relay budget. */
    fun bufferedBytes(): Long = reassembler.estimatedBytes()

    companion object {
        /** Randomly generated for insnaps; nothing else should answer to it. */
        val SERVICE_UUID: UUID = UUID.fromString("6e2f0a1c-9d47-4b8e-a1f3-5c7d0b2e8a94")
        val CHARACTERISTIC_UUID: UUID = UUID.fromString("6e2f0a1d-9d47-4b8e-a1f3-5c7d0b2e8a94")

        /** Pre-negotiation MTU every BLE device must support. */
        const val DEFAULT_MTU = 23

        /** Largest MTU the spec allows; Android caps requests here. */
        const val MAX_MTU = 517

        /** ATT opcode + handle. */
        const val ATT_HEADER_BYTES = 3
    }
}
