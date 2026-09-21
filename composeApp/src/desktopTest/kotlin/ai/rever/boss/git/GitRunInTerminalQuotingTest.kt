package ai.rever.boss.git

import ai.rever.boss.components.events.GitTerminalEventBus
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins the quoting on [GitService.runInTerminal]: it builds a shell command string, so an
 * argument containing `;`, `|` or `$()` must arrive single-quoted and inert rather than
 * live shell. There is no in-repo caller today - the test exists so the first one does not
 * open an injection hole.
 */
class GitRunInTerminalQuotingTest {
    @Test
    fun `every argument reaches the terminal shell-quoted`() =
        runTest {
            val dir = Files.createTempDirectory("git-run-in-terminal").toFile()
            try {
                // runInTerminal returns early without a bound project path; refresh is what
                // binds one, and the git probing it does afterwards is irrelevant to what
                // the bus sees.
                GitService.refresh(dir.absolutePath)
                val received = async { GitTerminalEventBus.openEvents.first() }

                GitService.runInTerminal("win-1", "status;", "$(touch /tmp/x)")

                val event = withTimeout(5_000) { received.await() }
                // Single-quote-literal quoting is identical on POSIX and PowerShell for
                // arguments without an embedded quote, so this string holds on every host.
                assertEquals("git 'status;' '\$(touch /tmp/x)'", event.command)
            } finally {
                dir.deleteRecursively()
            }
        }
}
