package com.insnaps.core

import com.insnaps.core.app.ConversationMode
import com.insnaps.core.privacy.DefaultCopyProtection
import com.insnaps.core.privacy.NotificationPolicy
import com.insnaps.core.privacy.PrivateContentGuard
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PrivacyGuardTest {

    private fun guard() = PrivateContentGuard().also { it.enterPrivateMode() }

    @Test
    fun `private content is hidden until private mode is entered`() {
        val guard = PrivateContentGuard()
        assertFalse(guard.visible)
        guard.enterPrivateMode()
        assertTrue(guard.visible)
    }

    @Test
    fun `capture hides content and clearing it restores`() {
        val guard = guard()
        guard.onCaptureStateChanged(true)
        assertFalse(guard.visible)
        assertTrue(PrivateContentGuard.Reason.CAPTURE_ACTIVE in guard.currentReasons())

        guard.onCaptureStateChanged(false)
        assertTrue(guard.visible)
    }

    @Test
    fun `mirroring hides content`() {
        val guard = guard()
        guard.onMirroringStateChanged(true)
        assertFalse(guard.visible)
    }

    @Test
    fun `backgrounding hides content so it stays out of app switcher snapshots`() {
        val guard = guard()
        guard.onForegroundStateChanged(false)
        assertFalse(guard.visible, "content must be hidden before the OS snapshots the app")
        guard.onForegroundStateChanged(true)
        assertTrue(guard.visible)
    }

    @Test
    fun `overlapping reasons must all clear before content returns`() {
        // The failure mode this guards against: clearing one condition reveals
        // content while another still applies.
        val guard = guard()
        guard.onCaptureStateChanged(true)
        guard.onForegroundStateChanged(false)
        assertEquals(2, guard.currentReasons().size)

        guard.onCaptureStateChanged(false)
        assertFalse(guard.visible, "still backgrounded, so still hidden")

        guard.onForegroundStateChanged(true)
        assertTrue(guard.visible)
    }

    @Test
    fun `leaving private mode hides content regardless of other state`() {
        val guard = guard()
        guard.leavePrivateMode()
        assertFalse(guard.visible)
    }

    @Test
    fun `visibility changes are reported once per transition`() {
        var changes = 0
        val guard = PrivateContentGuard(object : PrivateContentGuard.Listener {
            override fun onVisibilityChanged(visible: Boolean, reasons: Set<PrivateContentGuard.Reason>) {
                changes++
            }
        })
        guard.enterPrivateMode()
        guard.onCaptureStateChanged(true)
        guard.onMirroringStateChanged(true)  // already hidden: no transition
        guard.onMirroringStateChanged(false)
        guard.onCaptureStateChanged(false)
        assertEquals(3, changes, "only real transitions should be reported")
    }

    @Test
    fun `copy clipboard and sharing are blocked in private mode only`() {
        assertTrue(DefaultCopyProtection.allowsSelection(ConversationMode.NORMAL))
        assertTrue(DefaultCopyProtection.allowsClipboard(ConversationMode.NORMAL))
        assertTrue(DefaultCopyProtection.allowsSharing(ConversationMode.NORMAL))

        assertFalse(DefaultCopyProtection.allowsSelection(ConversationMode.PRIVATE))
        assertFalse(DefaultCopyProtection.allowsClipboard(ConversationMode.PRIVATE))
        assertFalse(DefaultCopyProtection.allowsSharing(ConversationMode.PRIVATE))
    }

    @Test
    fun `private notifications never carry message content`() {
        val secret = "the launch code is 1234"
        val body = NotificationPolicy.notificationBody(ConversationMode.PRIVATE, secret)
        assertEquals(NotificationPolicy.PRIVATE_NOTIFICATION_TEXT, body)
        assertFalse(body.contains("launch"), "private plaintext leaked into a notification")
        assertEquals(secret, NotificationPolicy.notificationBody(ConversationMode.NORMAL, secret))
    }
}
