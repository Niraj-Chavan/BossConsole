package ai.rever.boss.plugin.browser

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SwipeNavParityTest {
    private val root =
        generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "scripts/test/test-swipe-nav.js").isFile }

    @Test
    fun `native cancellation constants stay coupled to the page`() {
        val source = File(root, "composeApp/src/desktopMain/resources/browser/swipe-nav.js").readText()
        val constants =
            mapOf(
                "COMMIT_PX" to SWIPE_COMMIT_PX,
                "MIN_EVENTS" to SWIPE_MIN_EVENTS.toDouble(),
                "CANCEL_STRONG_RATIO" to SWIPE_CANCEL_STRONG_RATIO,
                "CANCEL_MIXED_RATIO" to SWIPE_CANCEL_MIXED_RATIO,
                "CANCEL_VERTICAL_LOW" to SWIPE_CANCEL_VERTICAL_LOW,
                "CANCEL_VERTICAL_HIGH" to SWIPE_CANCEL_VERTICAL_HIGH,
            )
        constants.forEach { (name, value) ->
            val expression = if (name.startsWith("CANCEL_VERTICAL")) "COMMIT_PX \\* " else ""
            val match = Regex("var $name = $expression([0-9.]+);").find(source)
            assertEquals(value, match?.groupValues?.get(1)?.toDouble(), name)
        }
    }

    @Test
    fun `real native terminal evidence passes the page regression scenarios`() {
        val cases = Json.parseToJsonElement(File(root, "scripts/test/swipe-nav-cases.json").readText()).jsonArray
        val results =
            buildJsonObject {
                cases.forEach { fixture ->
                    val fields = fixture.jsonObject
                    var state = scrollGestureTransition(ScrollGestureSnapshot(0, false), 1, 0).first
                    fields.getValue("samples").jsonArray.forEach { sample ->
                        state =
                            scrollGestureTransition(
                                state,
                                2,
                                0,
                                sample.jsonArray[0].jsonPrimitive.double,
                                sample.jsonArray[1].jsonPrimitive.double,
                            ).first
                    }
                    val cancelled = fields.getValue("cancelled").jsonPrimitive.content == "true"
                    val end = scrollGestureTransition(state, if (cancelled) 8 else 4, 0).second!!
                    put(
                        fields.getValue("name").jsonPrimitive.content,
                        buildJsonObject {
                            put("statement", BrowserSwipeNavScript.release(end))
                            put("rejected", end.rejected)
                            put("cancelled", end.cancelled)
                        },
                    )
                }
            }
        val evidence = File.createTempFile("swipe-native-results", ".json")
        val output = File.createTempFile("swipe-native-page", ".log")
        try {
            evidence.writeText(results.toString(), Charsets.UTF_8)
            val process = runEvidenceProbe(File(root, "scripts/test/test-swipe-nav.js"), evidence, output)
            awaitProbe(process, output)
        } finally {
            evidence.delete()
            output.delete()
        }
    }

    private fun runEvidenceProbe(
        script: File,
        evidenceFile: File,
        outputFile: File,
    ): Process {
        val isWindows = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)
        val command =
            listOf(
                if (isWindows) "node.exe" else "node",
                script.absolutePath,
                "--native-results",
                evidenceFile.absolutePath,
            )

        return try {
            ProcessBuilder(command)
                .directory(root)
                .redirectErrorStream(true)
                .redirectOutput(outputFile)
                .start()
        } catch (error: IOException) {
            throw IOException("SwipeNavParityTest requires node on PATH", error)
        }
    }

    private fun awaitProbe(
        process: Process,
        output: File,
        timeoutSeconds: Long = 120,
    ) {
        val completed =
            try {
                process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS), "page parity process did not terminate")
                }
            }
        // Node has exited and closed its redirected output; no file polling is needed.
        val actualEvidence = output.readText(Charsets.UTF_8)
        assertTrue(completed, "page parity suite timed out after ${timeoutSeconds}s; partial output:\n$actualEvidence")
        assertEquals(
            0,
            process.exitValue(),
            "Native terminal evidence did not match swipe-navigation page scenarios:\n$actualEvidence",
        )
        assertTrue(actualEvidence.contains("all checks passed"), "Page parity suite did not finish:\n$actualEvidence")
    }

    @Test
    fun `timed out probe terminates Node before returning`() {
        val script = File.createTempFile("swipe-timeout-probe", ".js")
        val output = File.createTempFile("swipe-timeout-probe", ".log")
        try {
            script.writeText("setInterval(() => {}, 1000);", Charsets.UTF_8)
            val process = runEvidenceProbe(script, script, output)
            val failure = assertFailsWith<AssertionError> { awaitProbe(process, output, timeoutSeconds = 1) }
            assertTrue(failure.message.orEmpty().contains("page parity suite timed out"))
            assertFalse(process.isAlive, "Timed out Node process must be reaped before temporary files are deleted")
        } finally {
            script.delete()
            output.delete()
        }
    }

    @Test
    fun `success text cannot hide a failed probe`() {
        val script = File.createTempFile("swipe-failed-probe", ".js")
        val output = File.createTempFile("swipe-failed-probe", ".log")
        try {
            script.writeText("console.log('all checks passed'); process.exitCode = 7;", Charsets.UTF_8)
            val process = runEvidenceProbe(script, script, output)
            val failure = assertFailsWith<AssertionError> { awaitProbe(process, output) }
            assertTrue(failure.message.orEmpty().contains("Native terminal evidence did not match"))
            assertEquals(7, process.exitValue())
        } finally {
            script.delete()
            output.delete()
        }
    }
}
