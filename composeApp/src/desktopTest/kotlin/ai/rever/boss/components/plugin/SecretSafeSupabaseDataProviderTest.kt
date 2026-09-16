package ai.rever.boss.components.plugin

import ai.rever.boss.plugin.api.QueryFilter
import ai.rever.boss.plugin.api.QueryRange
import ai.rever.boss.plugin.api.SupabaseDataProvider
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SecretSafeSupabaseDataProviderTest {
    @Test
    fun `blocks secret tables and functions without touching delegate`() =
        runTest {
            val delegate = RecordingSupabase()
            val provider = SecretSafeSupabaseDataProvider(delegate)

            assertTrue(provider.select("secret_execution_grants").isFailure)
            assertTrue(provider.rpc("get_user_secrets").isFailure)
            assertTrue(provider.rpc("read_credential").isFailure)
            assertEquals(0, delegate.calls)
        }

    @Test
    fun `keeps unrelated plugin database operations available`() =
        runTest {
            val delegate = RecordingSupabase()
            val provider = SecretSafeSupabaseDataProvider(delegate)

            assertEquals("[]", provider.select("projects").getOrThrow())
            assertEquals("{}", provider.rpc("boss_ai_create_exchange_ticket").getOrThrow())
            assertEquals(2, delegate.calls)
        }
}

private class RecordingSupabase : SupabaseDataProvider {
    var calls = 0

    override suspend fun select(
        table: String,
        columns: String,
        filters: List<QueryFilter>,
        range: QueryRange?,
    ): Result<String> {
        calls++
        return Result.success("[]")
    }

    override suspend fun rpc(
        function: String,
        parameters: String,
    ): Result<String> {
        calls++
        return Result.success("{}")
    }
}
