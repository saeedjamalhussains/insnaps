package com.insnaps.core.privacy

/**
 * Decides whether private content may be on screen right now.
 *
 * The decision is kept in `commonMain`, and platform code only reports events and
 * applies the result. That way the *policy* -- what counts as unsafe, and what
 * happens when several unsafe conditions overlap -- is written once and tested
 * without a device, and the Android and iOS layers stay thin enough to review.
 *
 * The state is deliberately conservative: any single reason to hide wins, and
 * content returns only when every reason has cleared. Getting this backwards is
 * how private content ends up in a screen recording.
 */
class PrivateContentGuard(private val listener: Listener? = null) {

    interface Listener {
        /** Called whenever visibility changes, so the UI can swap in a protected view. */
        fun onVisibilityChanged(visible: Boolean, reasons: Set<Reason>)
    }

    /** Why private content is currently hidden. */
    enum class Reason {
        /** A screen recording or capture is in progress. */
        CAPTURE_ACTIVE,

        /** The display is being mirrored or cast to another screen. */
        SCREEN_MIRRORED,

        /** The app is backgrounded, so the OS may snapshot it for the app switcher. */
        BACKGROUNDED,

        /** The user has left private mode, or it was never entered. */
        NOT_IN_PRIVATE_MODE,
    }

    private val reasons = mutableSetOf(Reason.NOT_IN_PRIVATE_MODE)

    /** True only when private content may be rendered. */
    val visible: Boolean get() = reasons.isEmpty()

    fun currentReasons(): Set<Reason> = reasons.toSet()

    fun enterPrivateMode() = update { reasons.remove(Reason.NOT_IN_PRIVATE_MODE) }

    fun leavePrivateMode() = update { reasons.add(Reason.NOT_IN_PRIVATE_MODE) }

    /**
     * The platform reported that capture started or stopped.
     *
     * On iOS this is `UIScreen.isCaptured`; on Android there is no equivalent
     * query, and `FLAG_SECURE` prevents the capture instead of reporting it (see
     * the class docs on `ScreenProtector`).
     */
    fun onCaptureStateChanged(capturing: Boolean) = update { set(Reason.CAPTURE_ACTIVE, capturing) }

    fun onMirroringStateChanged(mirrored: Boolean) = update { set(Reason.SCREEN_MIRRORED, mirrored) }

    /**
     * The app moved between foreground and background.
     *
     * Hiding on background is what keeps private content out of the Android
     * recents snapshot and the iOS app-switcher preview: both are taken as the
     * app leaves the foreground, so the content must already be gone by then.
     */
    fun onForegroundStateChanged(foreground: Boolean) = update { set(Reason.BACKGROUNDED, !foreground) }

    private fun set(reason: Reason, active: Boolean) {
        if (active) reasons.add(reason) else reasons.remove(reason)
    }

    private inline fun update(block: () -> Unit) {
        val before = visible
        block()
        if (visible != before) listener?.onVisibilityChanged(visible, currentReasons())
    }
}

/**
 * Platform capture protections, applied by the Android and iOS layers.
 *
 * ## What each platform actually provides
 *
 * **Android.** `WindowManager.LayoutParams.FLAG_SECURE` on the window blocks
 * screenshots and excludes the window from screen recording and from the recents
 * snapshot. It is a genuine block, not a notification: the app is not told that a
 * capture was attempted.
 *
 * **iOS.** There is no equivalent block for arbitrary views. `UIScreen.isCaptured`
 * reports that recording or mirroring is active, and
 * `userDidTakeScreenshotNotification` fires *after* a screenshot has been taken.
 * So on iOS the app can react, and can hide content while a recording is running,
 * but cannot prevent the screenshot that has already happened. Implementations
 * MUST NOT present iOS behaviour as equivalent to `FLAG_SECURE`.
 *
 * ## What neither provides
 *
 * Nothing here stops a second physical device photographing the screen. insnaps
 * prevents application- and OS-level capture where the platform offers the
 * control, and cannot prevent a camera pointed at the display. This limitation is
 * to be stated plainly in the UI and documentation, never implied away.
 */
interface ScreenProtector {
    /** Applies the strongest capture protection the platform offers. */
    fun enableProtection()

    /** Removes it, when leaving private content. */
    fun disableProtection()

    /** True if the platform can actually *block* capture rather than only detect it. */
    val canBlockCapture: Boolean

    /** True if the platform reports capture/mirroring state to the app. */
    val canDetectCapture: Boolean
}

/**
 * Clipboard and selection policy for private content.
 *
 * Enforced by the UI layer, which must disable selection, copy, cut, drag and
 * share affordances on private views. Stated as an interface so the requirement
 * is visible in the core rather than living only in two platform codebases.
 */
interface CopyProtection {
    fun allowsSelection(mode: com.insnaps.core.app.ConversationMode): Boolean
    fun allowsClipboard(mode: com.insnaps.core.app.ConversationMode): Boolean
    fun allowsSharing(mode: com.insnaps.core.app.ConversationMode): Boolean
}

/** The policy insnaps requires: everything permitted in normal mode, nothing in private. */
object DefaultCopyProtection : CopyProtection {
    override fun allowsSelection(mode: com.insnaps.core.app.ConversationMode) =
        mode == com.insnaps.core.app.ConversationMode.NORMAL

    override fun allowsClipboard(mode: com.insnaps.core.app.ConversationMode) =
        mode == com.insnaps.core.app.ConversationMode.NORMAL

    override fun allowsSharing(mode: com.insnaps.core.app.ConversationMode) =
        mode == com.insnaps.core.app.ConversationMode.NORMAL
}

/**
 * What a notification may reveal.
 *
 * Private message content never reaches a notification, a lock screen, a
 * notification history, or a paired wearable. The redacted text carries no
 * sender name either: knowing *who* is messaging is itself the metadata private
 * mode is meant to protect.
 */
object NotificationPolicy {
    const val PRIVATE_NOTIFICATION_TEXT = "New private message"

    /** Body text safe to hand the OS notification system. */
    fun notificationBody(mode: com.insnaps.core.app.ConversationMode, plaintextPreview: String): String =
        when (mode) {
            com.insnaps.core.app.ConversationMode.NORMAL -> plaintextPreview
            com.insnaps.core.app.ConversationMode.PRIVATE -> PRIVATE_NOTIFICATION_TEXT
        }
}
