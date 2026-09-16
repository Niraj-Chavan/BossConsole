package ai.rever.boss.crash

import io.github.jan.supabase.auth.exception.TokenExpiredException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for [CrashHandler.isIgnorable] — recoverable background failures
 * must not pop the crash dialog (dismissing it exits the app).
 */
class CrashHandlerIgnorableTest {
    private fun staleRealtimeRejoin(): IllegalStateException =
        IllegalStateException("Websocket not yet initialized").apply {
            stackTrace =
                arrayOf(
                    StackTraceElement(
                        "io.github.jan.supabase.realtime.RealtimeImpl",
                        "getWebsocket",
                        "RealtimeImpl.kt",
                        58,
                    ),
                    StackTraceElement(
                        "io.github.jan.supabase.realtime.RealtimeChannelImpl",
                        "unsubscribe",
                        "RealtimeChannelImpl.kt",
                        196,
                    ),
                    StackTraceElement(
                        "io.github.jan.supabase.realtime.RealtimeChannelImpl",
                        "resubscribe",
                        "RealtimeChannelImpl.kt",
                        356,
                    ),
                    StackTraceElement(
                        "io.github.jan.supabase.realtime.RealtimeChannelImpl",
                        "scheduleRejoin",
                        "RealtimeChannelImpl.kt",
                        190,
                    ),
                )
        }

    @Test
    fun `issue 28 stale realtime rejoin is recoverable`() {
        assertTrue(CrashHandler.isIgnorable(staleRealtimeRejoin()))
        assertTrue(CrashHandler.isIgnorable(RuntimeException("background retry failed", staleRealtimeRejoin())))
    }

    @Test
    fun `matching message from application code is still a crash`() {
        assertFalse(CrashHandler.isIgnorable(IllegalStateException("Websocket not yet initialized")))
    }

    @Test
    fun `direct unsubscribe without a connection is still a crash`() {
        val failure = staleRealtimeRejoin().apply { stackTrace = stackTrace.take(2).toTypedArray() }
        assertFalse(CrashHandler.isIgnorable(failure))
    }

    @Test
    fun `other errors on the retry path remain visible`() {
        val frames = staleRealtimeRejoin().stackTrace
        assertFalse(CrashHandler.isIgnorable(IllegalStateException("another failure").apply { stackTrace = frames }))
        val wrongType = RuntimeException("Websocket not yet initialized").apply { stackTrace = frames }
        assertFalse(CrashHandler.isIgnorable(wrongType))
        assertFalse(
            CrashHandler.isIgnorable(
                IllegalStateException("Websocket not yet initialized").apply {
                    stackTrace =
                        frames
                            .map {
                                StackTraceElement("other.library.Channel", it.methodName, it.fileName, it.lineNumber)
                            }
                            .toTypedArray()
                },
            ),
        )
    }

    @Test
    fun `supabase token expiry is ignorable`() {
        assertTrue(CrashHandler.isIgnorable(TokenExpiredException()))
    }

    @Test
    fun `token expiry nested in cause chain is ignorable`() {
        assertTrue(CrashHandler.isIgnorable(RuntimeException("request failed", TokenExpiredException())))
    }

    @Test
    fun `coroutine cancellation is ignorable`() {
        assertTrue(CrashHandler.isIgnorable(kotlinx.coroutines.CancellationException("cancelled")))
    }

    @Test
    fun `broken pipe io exception is ignorable`() {
        assertTrue(CrashHandler.isIgnorable(java.io.IOException("Broken pipe")))
    }

    @Test
    fun `generic runtime exception is not ignorable`() {
        assertFalse(CrashHandler.isIgnorable(RuntimeException("actual crash")))
    }
}
