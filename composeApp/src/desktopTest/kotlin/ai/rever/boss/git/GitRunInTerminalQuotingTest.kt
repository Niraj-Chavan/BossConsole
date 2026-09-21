package ai.rever.boss.git

import ai.rever.boss.components.events.GitTerminalEventBus
import ai.rever.boss.components.events.GitTerminalOpenEvent
import ai.rever.boss.ipc.IpcEventBridge
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicReference
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
            // Capture through the IPC bridge rather than the shared flow: openGitTerminal
            // awaits forward() inline, so the event is captured deterministically inside
            // runInTerminal with no SharedFlow subscriber timing involved.
            val captured = AtomicReference<GitTerminalOpenEvent>()
            GitTerminalEventBus.ipcBridge =
                object : IpcEventBridge {
                    override suspend fun forward(
                        eventType: String,
                        payload: Any,
                        sourceWindowId: String,
                    ) {
                        (payload as? GitTerminalOpenEvent)?.let(captured::set)
                    }
                }
            try {
                // GitService is a shared singleton - a concurrent clear() in the suite can
                // null currentProjectPath, and runInTerminal early-returns without it.
                // Rebind and re-emit until the bridge captures our event; every emission
                // carries the same command, so repeated emits are harmless.
                withTimeout(15_000) {
                    while (captured.get() == null) {
                        GitService.refresh(dir.absolutePath)
                        GitService.runInTerminal("win-1", "status;", "$(touch /tmp/x)")
                        delay(100)
                    }
                }
                // Single-quote-literal quoting is identical on POSIX and PowerShell for
                // arguments without an embedded quote, so this string holds on every host.
                assertEquals("git 'status;' '\$(touch /tmp/x)'", captured.get().command)
            } finally {
                GitTerminalEventBus.ipcBridge = null
                dir.deleteRecursively()
            }
        }
}
