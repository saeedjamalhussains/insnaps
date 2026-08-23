package com.insnaps.core.crypto

/**
 * The single intentional persistence point in insnaps.
 *
 * insnaps stores exactly one durable value: the long-term identity private key.
 * Messages, routing state, relay buffers, session keys, peer records and
 * conversation state are volatile and never reach this interface.
 *
 * ## Normative deletion behaviour
 *
 * Uninstalling insnaps must destroy the identity. The platforms do not agree on
 * this by default and implementations must reconcile it:
 *
 *  - **Android Keystore** clears key material on uninstall. Nothing extra needed.
 *  - **iOS Keychain** items *survive* app deletion. An iOS implementation must
 *    store the key with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and clear
 *    any existing item on first launch after install, so that a reinstall issues
 *    a new identity rather than resurrecting the old one.
 *
 * [regenerate] must be exposed in the UI regardless of platform: a user who
 * believes their identity is compromised needs to discard it without uninstalling.
 */
interface IdentityStore {
    /** Loads the stored identity, or null if this install has none yet. */
    fun load(): IdentityKeyPair?

    /** Creates and persists a new identity, replacing any existing one. */
    fun regenerate(): IdentityKeyPair

    /** Destroys the stored identity. After this, [load] returns null. */
    fun clear()

    fun loadOrCreate(): IdentityKeyPair = load() ?: regenerate()
}

class IdentityKeyPair(
    val publicKey: ByteArray,
    /**
     * Held in memory only for the lifetime of a session. Implementations backed by
     * a hardware-isolated keystore may expose an opaque handle here instead of raw
     * key bytes; the core never interprets this value.
     */
    val privateKey: ByteArray,
) {
    val identity: PeerIdentity get() = PeerIdentity(publicKey)
}
