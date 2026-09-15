package ai.rever.boss.app

import ai.rever.boss.plugin.api.CustomPluginEvent

internal const val TERMINAL_PLUGIN_ID = "ai.rever.boss.plugin.dynamic.terminaltab"
internal const val CODEBASE_PLUGIN_ID = "ai.rever.boss.plugin.dynamic.codebase"
internal const val HOST_PLUGIN_ID = "ai.rever.boss"
internal const val FLUCK_REVIEW_EVENT = "atlas.review"
internal const val SETUP_DEBUG_OPEN_EVENT = "bossterm.setup.fluck.open"
internal const val SETUP_DEBUG_OPENED_EVENT = "bossterm.setup.fluck.opened"
internal const val SETUP_FLUCK_PROBE_EVENT = "bossterm.setup.fluck.probe"
internal const val SETUP_FLUCK_AVAILABILITY_EVENT = "bossterm.setup.fluck.availability"
internal const val SETUP_OPEN_EVENT = "bossterm.setup.open"

internal data class SetupFluckOpenRequest(
    val requestId: String,
    val terminalId: String,
    val prompt: String,
)

internal fun CustomPluginEvent.toSetupFluckProbeRequest(expectedWindowId: String): String? {
    val matchesRoute = sourcePluginId == TERMINAL_PLUGIN_ID && eventName == SETUP_FLUCK_PROBE_EVENT
    return (payload["requestId"] as? String)
        ?.takeIf { matchesRoute && payload["windowId"] == expectedWindowId && validOpaqueId(it) }
}

internal fun CustomPluginEvent.isSetupOpenRequest(expectedWindowId: String): Boolean =
    sourcePluginId == TERMINAL_PLUGIN_ID &&
        eventName == SETUP_OPEN_EVENT &&
        payload["windowId"] == expectedWindowId

/** Validate the terminal plugin's request before the host lends it the legacy review ingress. */
internal fun CustomPluginEvent.toSetupFluckOpenRequest(
    expectedWindowId: String,
    nowMs: Long = System.currentTimeMillis(),
): SetupFluckOpenRequest? {
    val requestId = payload["requestId"] as? String
    val terminalId = payload["terminalId"] as? String
    val prompt = payload["prompt"] as? String
    val expiresAtMs = payload["expiresAtMs"] as? Long
    val valid =
        sourcePluginId == TERMINAL_PLUGIN_ID &&
            eventName == SETUP_DEBUG_OPEN_EVENT &&
            payload["windowId"] == expectedWindowId &&
            expiresAtMs != null && expiresAtMs in nowMs..(nowMs + MAX_REQUEST_LIFETIME_MS) &&
            requestId != null && validOpaqueId(requestId) &&
            terminalId != null && validOpaqueId(terminalId) &&
            prompt != null && prompt.isNotBlank() && prompt.length <= MAX_PROMPT_LENGTH
    return if (valid) {
        SetupFluckOpenRequest(requireNotNull(requestId), requireNotNull(terminalId), requireNotNull(prompt))
    } else {
        null
    }
}

private fun validOpaqueId(value: String): Boolean = value.length in 1..MAX_ID_LENGTH && value.all(::validIdCharacter)

private fun validIdCharacter(character: Char): Boolean = character.isLetterOrDigit() || character in ID_PUNCTUATION

private const val MAX_ID_LENGTH = 160
private const val MAX_PROMPT_LENGTH = 16_000
private const val MAX_REQUEST_LIFETIME_MS = 30_000L
private const val ID_PUNCTUATION = "-_:"
