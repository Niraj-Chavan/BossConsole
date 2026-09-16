package ai.rever.boss.services.supabase

import ai.rever.boss.plugin.api.AccessibleSecretMetadata
import ai.rever.boss.plugin.api.CreateSecretRequestData
import ai.rever.boss.plugin.api.PaginatedAccessibleSecrets
import ai.rever.boss.plugin.api.SecretAccessProvider
import ai.rever.boss.plugin.api.SecretEntryData
import ai.rever.boss.plugin.api.SecretGrantManager
import ai.rever.boss.plugin.api.SecretMetadataData
import ai.rever.boss.plugin.api.SecretPrincipalData
import ai.rever.boss.plugin.api.SecretPrincipalGrantData
import ai.rever.boss.plugin.api.UpdateSecretRequestData
import ai.rever.boss.services.supabase.models.ExecutionSecretGrant
import ai.rever.boss.services.supabase.models.ExecutionSecretMetadata
import ai.rever.boss.services.supabase.models.SecretEntry
import kotlinx.coroutines.currentCoroutineContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/** Host-derived identity used for secret authorization. Never constructed from plugin arguments. */
data class SecretExecutionPrincipal(
    val type: String,
    val id: String,
) {
    init {
        require(type.isNotBlank()) { "Secret principal type cannot be blank" }
        require(id.isNotBlank()) { "Secret principal id cannot be blank" }
    }

    companion object {
        fun plugin(pluginId: String) = SecretExecutionPrincipal("plugin", pluginId)

        fun mcpTool(
            providerId: String,
            toolName: String,
        ) = SecretExecutionPrincipal("mcp_tool", "$providerId/$toolName")
    }
}

/** Invocation-scoped narrowing installed by trusted host dispatchers such as the MCP registry. */
class SecretExecutionPrincipalContext(
    val principal: SecretExecutionPrincipal,
) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<SecretExecutionPrincipalContext>
}

/** Principal-bound implementation exposed to ordinary plugin contexts. */
class SecretAccessProviderImpl internal constructor(
    private val pluginPrincipal: SecretExecutionPrincipal,
    private val backend: ExecutionSecretBackend = SupabaseExecutionSecretBackend,
) : SecretAccessProvider {
    override suspend fun listSecrets(
        limit: Int,
        offset: Int,
    ): Result<PaginatedAccessibleSecrets> = list(query = null, limit = limit, offset = offset)

    override suspend fun searchSecrets(
        query: String,
        limit: Int,
        offset: Int,
    ): Result<PaginatedAccessibleSecrets> = list(query = query, limit = limit, offset = offset)

    override suspend fun getSecret(secretId: String): Result<SecretEntryData?> =
        backend.get(principal(), secretId).map { it?.toPluginData() }

    override suspend fun createSecret(request: CreateSecretRequestData): Result<String> = backend.create(principal(), request)

    override suspend fun updateOwnedSecret(request: UpdateSecretRequestData): Result<Unit> = backend.update(principal(), request)

    override suspend fun deleteOwnedSecret(secretId: String): Result<Unit> = backend.delete(principal(), secretId)

    private suspend fun list(
        query: String?,
        limit: Int,
        offset: Int,
    ): Result<PaginatedAccessibleSecrets> {
        val bounded = limit.coerceIn(1, 500)
        return backend.list(principal(), query, bounded, offset.coerceAtLeast(0)).map {
            PaginatedAccessibleSecrets(
                data = it.map(ExecutionSecretMetadata::toPluginData),
                hasMore = it.size >= bounded,
            )
        }
    }

    private suspend fun principal(): SecretExecutionPrincipal =
        currentCoroutineContext()[SecretExecutionPrincipalContext]?.principal ?: pluginPrincipal
}

internal interface ExecutionSecretBackend {
    suspend fun list(
        principal: SecretExecutionPrincipal,
        query: String?,
        limit: Int,
        offset: Int,
    ): Result<List<ExecutionSecretMetadata>>

    suspend fun get(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<SecretEntry?>

    suspend fun create(
        principal: SecretExecutionPrincipal,
        request: CreateSecretRequestData,
    ): Result<String>

    suspend fun update(
        principal: SecretExecutionPrincipal,
        request: UpdateSecretRequestData,
    ): Result<Unit>

    suspend fun delete(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<Unit>
}

private object SupabaseExecutionSecretBackend : ExecutionSecretBackend {
    override suspend fun list(
        principal: SecretExecutionPrincipal,
        query: String?,
        limit: Int,
        offset: Int,
    ) = ExecutionSecretService.list(principal, query, limit, offset)

    override suspend fun get(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ) = ExecutionSecretService.get(principal, secretId)

    override suspend fun create(
        principal: SecretExecutionPrincipal,
        request: CreateSecretRequestData,
    ) = ExecutionSecretService.create(principal, request)

    override suspend fun update(
        principal: SecretExecutionPrincipal,
        request: UpdateSecretRequestData,
    ) = ExecutionSecretService.update(principal, request)

    override suspend fun delete(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ) = ExecutionSecretService.delete(principal, secretId)
}

/** Human-only grant administration, exposed solely to the trusted Secret Manager context. */
class SecretGrantManagerImpl(
    private val principalCatalog: () -> List<SecretPrincipalData>,
) : SecretGrantManager {
    override suspend fun listPrincipals(): Result<List<SecretPrincipalData>> =
        Result.success(
            principalCatalog()
                .distinctBy { it.principalType to it.principalId }
                .sortedWith(compareBy(SecretPrincipalData::displayName, SecretPrincipalData::principalId)),
        )

    override suspend fun listGrants(secretId: String): Result<List<SecretPrincipalGrantData>> =
        ExecutionSecretService.listGrants(secretId).map { grants ->
            grants.map(ExecutionSecretGrant::toPluginData)
        }

    override suspend fun grantSecret(
        secretId: String,
        principalType: String,
        principalId: String,
    ): Result<Unit> {
        val known =
            principalCatalog().any {
                it.principalType == principalType && it.principalId == principalId
            }
        if (!known) return Result.failure(IllegalArgumentException("Unknown secret principal"))
        return ExecutionSecretService.grant(secretId, principalType, principalId)
    }

    override suspend fun revokeSecret(
        secretId: String,
        principalType: String,
        principalId: String,
    ): Result<Unit> = ExecutionSecretService.revoke(secretId, principalType, principalId)
}

private fun ExecutionSecretMetadata.toPluginData(): AccessibleSecretMetadata =
    AccessibleSecretMetadata(
        id = id,
        website = website,
        username = username,
        expirationDate = expirationDate,
        tags = tags,
        createdAt = createdAt,
        updatedAt = updatedAt,
        accessLevel = accessLevel,
    )

private fun SecretEntry.toPluginData(): SecretEntryData =
    SecretEntryData(
        id = id,
        website = website,
        username = username,
        password = password,
        notes = notes,
        expirationDate = expirationDate,
        tags = tags,
        metadata =
            metadata?.let {
                SecretMetadataData(
                    twofaEnabled = it.twofaEnabled,
                    twofaType = it.twofaType,
                    twofaSecret = it.twofaSecret,
                    recoveryCodes = it.recoveryCodes,
                )
            },
        createdAt = createdAt,
        updatedAt = updatedAt,
    )

private fun ExecutionSecretGrant.toPluginData(): SecretPrincipalGrantData =
    SecretPrincipalGrantData(
        principalType = principalType,
        principalId = principalId,
        grantedAt = grantedAt,
        grantedByUserId = grantedByUserId,
        accessLevel = accessLevel,
    )
