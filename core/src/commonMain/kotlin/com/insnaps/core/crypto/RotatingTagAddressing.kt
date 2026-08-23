package com.insnaps.core.crypto

import com.insnaps.core.packet.RecipientTag
import com.insnaps.core.util.Clock
import com.insnaps.core.util.constantTimeEquals

/**
 * Recipient addressing by short rotating tag.
 *
 * The tag for a peer in a given time period is
 *
 *     tag = truncate_8( HMAC-SHA256(pairwiseSecret, "insnaps-tag-v1" || epoch) )
 *
 * Only the two endpoints hold `pairwiseSecret`, so only the recipient can tell
 * that a tag is theirs. Relays see an 8-byte value that changes every
 * [rotationSeconds] and cannot be tied to an identity or, across rotations, to
 * another tag.
 *
 * ## What this does and does not protect
 *
 * It does **not** hide that *some* conversation is happening, and within a single
 * rotation period a relay can see that several packets share a destination. That
 * residual linkability is the accepted price of letting relays route without
 * flooding. It is confined entirely to this class: replacing it with onion-routed
 * per-hop headers changes nothing above [RecipientAddressing].
 *
 * ## Cost
 *
 * [isForMe] is O(known peers) MACs per inbound packet, because a tag is only
 * recognisable by trying it. That is acceptable for a personal contact list and
 * would not be for thousands of peers; if the contact list ever grows that far,
 * cache the current epoch's tags in a set and rebuild them on rotation.
 */
class RotatingTagAddressing(
    private val secrets: SharedSecretProvider,
    private val mac: Mac,
    private val clock: Clock,
    private val rotationSeconds: Long = DEFAULT_ROTATION_SECONDS,
    /**
     * This device's long-term static public key, if handshake traffic should be
     * addressable. Required to receive a first contact; null makes the device
     * reachable only by peers that already have a session with it.
     */
    private val ownStaticPublicKey: ByteArray? = null,
) : RecipientAddressing {

    /**
     * Tag for [peer], using the pairwise session secret when one exists.
     *
     * With no session yet there is no shared secret to derive from, so a
     * *bootstrap* tag is used instead: a MAC keyed by the peer's own static
     * public key. This is what lets a handshake be addressed at all, and it is
     * weaker by construction -- anyone who knows the peer's public key can
     * recognise their bootstrap tags and track when they are being contacted.
     * That exposure is confined to handshake packets; every subsequent message
     * uses the pairwise tag.
     */
    override fun tagFor(peer: PeerIdentity): RecipientTag {
        val secret = secrets.secretFor(peer)
        return if (secret != null) derive(secret, currentEpoch()) else bootstrapTag(peer.publicKey, currentEpoch())
    }

    override fun handshakeTagFor(peer: PeerIdentity): RecipientTag =
        bootstrapTag(peer.publicKey, currentEpoch())

    /**
     * Accepts the current epoch and its immediate neighbours.
     *
     * Peers have no synchronised clock, and a packet may also spend a while in a
     * relay buffer, so a sender near a rotation boundary can legitimately stamp
     * the adjacent epoch. Checking +/- 1 epoch avoids dropping that traffic; the
     * cost is that a tag stays valid for three rotation periods rather than one.
     */
    override fun isForMe(tag: RecipientTag): Boolean {
        if (tag.isBroadcast) return true
        val epoch = currentEpoch()

        val ownKey = ownStaticPublicKey
        if (ownKey != null) {
            for (candidate in longArrayOf(epoch, epoch - 1, epoch + 1)) {
                if (bootstrapTag(ownKey, candidate).bytes.constantTimeEquals(tag.bytes)) return true
            }
        }

        for (peer in secrets.knownPeers()) {
            val secret = secrets.secretFor(peer) ?: continue
            for (candidate in longArrayOf(epoch, epoch - 1, epoch + 1)) {
                if (derive(secret, candidate).bytes.constantTimeEquals(tag.bytes)) return true
            }
        }
        return false
    }

    /** Handshake-time tag, keyed by a public value and therefore publicly computable. */
    private fun bootstrapTag(staticPublicKey: ByteArray, epoch: Long): RecipientTag =
        derive(staticPublicKey, epoch, BOOTSTRAP_CONTEXT)

    private fun currentEpoch(): Long = clock.nowMillis() / (rotationSeconds * 1000L)

    private fun derive(secret: ByteArray, epoch: Long, context: ByteArray = TAG_CONTEXT): RecipientTag {
        val input = ByteArray(context.size + 8)
        context.copyInto(input)
        for (i in 0 until 8) {
            input[context.size + i] = (epoch ushr (56 - 8 * i)).toByte()
        }
        val full = mac.hmacSha256(secret, input)
        return RecipientTag(full.copyOf(RecipientTag.SIZE))
    }

    companion object {
        const val DEFAULT_ROTATION_SECONDS = 900L

        /** Domain separation, so this MAC output can never collide with another use of the same secret. */
        private val TAG_CONTEXT = "insnaps-tag-v1".encodeToByteArray()

        /** Separate context so a bootstrap tag can never collide with a pairwise one. */
        private val BOOTSTRAP_CONTEXT = "insnaps-init-v1".encodeToByteArray()
    }
}
