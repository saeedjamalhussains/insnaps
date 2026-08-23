package com.insnaps.core.crypto

import com.insnaps.core.packet.RecipientTag

/**
 * Decides which packets are addressed to this device, and stamps outbound packets
 * with a tag the intended recipient will recognise.
 *
 * This interface is the *entire* addressing surface of the protocol. The router
 * asks only "is this mine?" and never learns how the answer is computed, so the
 * scheme below can be replaced by an onion-routed header -- a strictly stronger
 * but heavier design -- without changing the router, the relay buffer or the
 * packet codec.
 */
interface RecipientAddressing {
    /** Tag to stamp on a packet addressed to [peer]. */
    fun tagFor(peer: PeerIdentity): RecipientTag

    /**
     * Tag to stamp on handshake traffic addressed to [peer].
     *
     * Handshake packets cannot use a pairwise tag in either direction. The
     * initiator has no session yet, and the responder -- which *does* have one by
     * the time it replies -- must not use it either, because the initiator cannot
     * recognise a pairwise tag until its own handshake completes. Both messages
     * therefore use the bootstrap derivation, which depends only on the
     * recipient's public key.
     */
    fun handshakeTagFor(peer: PeerIdentity): RecipientTag

    /** True if [tag] addresses this device in the current rotation period. */
    fun isForMe(tag: RecipientTag): Boolean
}

/**
 * Long-term public identity of a peer.
 *
 * The private half of this keypair is the *only* value insnaps intentionally
 * persists (see `IdentityStore`). Everything else in the system is volatile.
 */
class PeerIdentity(val publicKey: ByteArray) {
    init { require(publicKey.isNotEmpty()) { "public key must not be empty" } }

    override fun equals(other: Any?): Boolean =
        this === other || (other is PeerIdentity && publicKey.contentEquals(other.publicKey))

    override fun hashCode(): Int = publicKey.contentHashCode()
}
