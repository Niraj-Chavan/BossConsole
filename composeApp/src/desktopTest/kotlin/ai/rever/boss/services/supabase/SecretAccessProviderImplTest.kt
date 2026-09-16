package ai.rever.boss.services.supabase

import ai.rever.boss.plugin.api.CreateSecretRequestData
import ai.rever.boss.plugin.api.UpdateSecretRequestData
import ai.rever.boss.services.supabase.models.ExecutionSecretMetadata
import ai.rever.boss.services.supabase.models.SecretEntry
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals

class SecretAccessProviderImplTest {
    @Test
    fun `plugin calls use bound host principal`() =
        runTest {
            val backend = RecordingBackend()
            val provider = SecretAccessProviderImpl(SecretExecutionPrincipal.plugin("plugin-a"), backend)

            provider.listSecrets()
            provider.getSecret("secret-1")
            provider.createSecret(CreateSecretRequestData("example.com", "user", "value"))

            assertEquals(List(3) { SecretExecutionPrincipal.plugin("plugin-a") }, backend.principals)
        }

    @Test
    fun `mcp invocation narrows a captured plugin provider to exact tool principal`() =
        runTest {
            val backend = RecordingBackend()
            val provider = SecretAccessProviderImpl(SecretExecutionPrincipal.plugin("secret-manager"), backend)
            val tool = SecretExecutionPrincipal.mcpTool("secret-manager", "secret_get")

            withContext(SecretExecutionPrincipalContext(tool)) {
                provider.getSecret("secret-1")
            }

            assertEquals(listOf(tool), backend.principals)
        }

    @Test
    fun `list bounds untrusted pagination`() =
        runTest {
            val backend = RecordingBackend()
            val provider = SecretAccessProviderImpl(SecretExecutionPrincipal.plugin("plugin-a"), backend)

            provider.listSecrets(limit = Int.MAX_VALUE, offset = -10)

            assertEquals(500, backend.limit)
            assertEquals(0, backend.offset)
        }
}

private class RecordingBackend : ExecutionSecretBackend {
    val principals = mutableListOf<SecretExecutionPrincipal>()
    var limit = 0
    var offset = 0

    override suspend fun list(
        principal: SecretExecutionPrincipal,
        query: String?,
        limit: Int,
        offset: Int,
    ): Result<List<ExecutionSecretMetadata>> {
        principals += principal
        this.limit = limit
        this.offset = offset
        return Result.success(emptyList())
    }

    override suspend fun get(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<SecretEntry?> {
        principals += principal
        return Result.success(null)
    }

    override suspend fun create(
        principal: SecretExecutionPrincipal,
        request: CreateSecretRequestData,
    ): Result<String> {
        principals += principal
        return Result.success("created")
    }

    override suspend fun update(
        principal: SecretExecutionPrincipal,
        request: UpdateSecretRequestData,
    ): Result<Unit> {
        principals += principal
        return Result.success(Unit)
    }

    override suspend fun delete(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<Unit> {
        principals += principal
        return Result.success(Unit)
    }
}
