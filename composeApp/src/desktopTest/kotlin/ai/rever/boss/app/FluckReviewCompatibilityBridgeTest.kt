package ai.rever.boss.app

import ai.rever.boss.plugin.api.CustomPluginEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FluckReviewCompatibilityBridgeTest {
    @Test
    fun `accepts a current terminal request for the exact window`() {
        val request = event().toSetupFluckOpenRequest(expectedWindowId = "window-1", nowMs = 1_000)

        assertEquals("request-1", request?.requestId)
        assertEquals("terminal-1", request?.terminalId)
        assertEquals("Inspect this setup terminal", request?.prompt)
    }

    @Test
    fun `rejects spoofed wrong-window expired and oversized requests`() {
        assertNull(event(source = "another-plugin").toSetupFluckOpenRequest("window-1", 1_000))
        assertNull(event(windowId = "window-2").toSetupFluckOpenRequest("window-1", 1_000))
        assertNull(event(expiresAtMs = 999).toSetupFluckOpenRequest("window-1", 1_000))
        assertNull(event(prompt = "x".repeat(16_001)).toSetupFluckOpenRequest("window-1", 1_000))
    }

    @Test
    fun `probe is accepted only from terminal for the exact window`() {
        val probe =
            CustomPluginEvent(
                TERMINAL_PLUGIN_ID,
                SETUP_FLUCK_PROBE_EVENT,
                mapOf("windowId" to "window-1", "requestId" to "probe-1"),
            )

        assertEquals("probe-1", probe.toSetupFluckProbeRequest("window-1"))
        assertNull(probe.toSetupFluckProbeRequest("window-2"))
    }

    @Test
    fun `setup open is routed only to its exact host window`() {
        val request = CustomPluginEvent(TERMINAL_PLUGIN_ID, SETUP_OPEN_EVENT, mapOf("windowId" to "window-2"))

        assertEquals(true, request.isSetupOpenRequest("window-2"))
        assertEquals(false, request.isSetupOpenRequest("window-1"))
    }

    private fun event(
        source: String = TERMINAL_PLUGIN_ID,
        windowId: String = "window-1",
        expiresAtMs: Long = 2_000,
        prompt: String = "Inspect this setup terminal",
    ): CustomPluginEvent =
        CustomPluginEvent(
            sourcePluginId = source,
            eventName = SETUP_DEBUG_OPEN_EVENT,
            payload =
                mapOf(
                    "windowId" to windowId,
                    "requestId" to "request-1",
                    "terminalId" to "terminal-1",
                    "expiresAtMs" to expiresAtMs,
                    "prompt" to prompt,
                ),
        )
}
