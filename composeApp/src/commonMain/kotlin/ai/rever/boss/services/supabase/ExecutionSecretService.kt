package ai.rever.boss.services.supabase

import ai.rever.boss.plugin.api.CreateSecretRequestData
import ai.rever.boss.plugin.api.UpdateSecretRequestData
import ai.rever.boss.services.supabase.models.ExecutionSecretGrant
import ai.rever.boss.services.supabase.models.ExecutionSecretMetadata
import ai.rever.boss.services.supabase.models.SecretEntry
import ai.rever.boss.utils.logging.BossLogger
import ai.rever.boss.utils.logging.LogCategory
import io.github.jan.supabase.postgrest.postgrest
import io.github.jan.supabase.postgrest.rpc
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.put

/** Supabase RPC client for the execution-principal secret boundary. */
object ExecutionSecretService {
    private val logger = BossLogger.forComponent("ExecutionSecretService")

    private val client
        get() = SupabaseConfig.client

    suspend fun list(
        principal: SecretExecutionPrincipal,
        query: String?,
        limit: Int,
        offset: Int,
    ): Result<List<ExecutionSecretMetadata>> =
        rpcList("list_execution_secrets") {
            principalParameters(principal)
            if (query != null) put("p_query", query)
            put("p_limit", limit)
            put("p_offset", offset)
        }

    suspend fun get(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<SecretEntry?> =
        rpcList<SecretEntry>("get_execution_secret") {
            principalParameters(principal)
            put("p_secret_id", secretId)
        }.map { it.firstOrNull() }

    suspend fun create(
        principal: SecretExecutionPrincipal,
        request: CreateSecretRequestData,
    ): Result<String> =
        mutation("create_execution_secret") {
            principalParameters(principal)
            requestParameters(request)
        }.mapCatching { it.secretId ?: error("Secret store returned no id") }

    suspend fun update(
        principal: SecretExecutionPrincipal,
        request: UpdateSecretRequestData,
    ): Result<Unit> =
        mutation("update_execution_secret") {
            principalParameters(principal)
            put("p_secret_id", request.secretId)
            requestParameters(request)
        }.map { }

    suspend fun delete(
        principal: SecretExecutionPrincipal,
        secretId: String,
    ): Result<Unit> =
        mutation("delete_execution_secret") {
            principalParameters(principal)
            put("p_secret_id", secretId)
        }.map { }

    suspend fun listGrants(secretId: String): Result<List<ExecutionSecretGrant>> =
        rpcList("list_secret_execution_grants") { put("p_secret_id", secretId) }

    suspend fun grant(
        secretId: String,
        principalType: String,
        principalId: String,
    ): Result<Unit> = grantMutation("grant_secret_to_execution_principal", secretId, principalType, principalId)

    suspend fun revoke(
        secretId: String,
        principalType: String,
        principalId: String,
    ): Result<Unit> = grantMutation("revoke_secret_from_execution_principal", secretId, principalType, principalId)

    private suspend fun grantMutation(
        operation: String,
        secretId: String,
        principalType: String,
        principalId: String,
    ): Result<Unit> =
        mutation(operation) {
            put("p_secret_id", secretId)
            put("p_principal_type", principalType)
            put("p_principal_id", principalId)
        }.map { }

    private suspend inline fun <reified T> rpcList(
        operation: String,
        parameters: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
    ): Result<List<T>> =
        try {
            val response = client.postgrest.rpc(operation, buildJsonObject(parameters))
            Result.success(
                supabaseJson.decodeFromJsonElement(
                    supabaseJson.parseToJsonElement(response.data),
                ),
            )
        } catch (error: Exception) {
            failed(operation, error)
        }

    private suspend fun mutation(
        operation: String,
        parameters: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
    ): Result<MutationResponse> =
        try {
            val response = client.postgrest.rpc(operation, buildJsonObject(parameters))
            val decoded =
                supabaseJson.decodeFromJsonElement<MutationResponse>(
                    supabaseJson.parseToJsonElement(response.data),
                )
            if (decoded.success) {
                Result.success(decoded)
            } else {
                Result.failure(IllegalStateException(decoded.error ?: "Secret operation refused"))
            }
        } catch (error: Exception) {
            failed(operation, error)
        }

    private fun kotlinx.serialization.json.JsonObjectBuilder.principalParameters(principal: SecretExecutionPrincipal) {
        put("p_principal_type", principal.type)
        put("p_principal_id", principal.id)
    }

    private fun kotlinx.serialization.json.JsonObjectBuilder.requestParameters(request: CreateSecretRequestData) {
        put("p_website", request.website)
        put("p_username", request.username)
        put("p_password", request.password)
        request.notes?.let { put("p_notes", it) }
        request.expirationDate?.let { put("p_expiration_date", it) }
        if (request.tags.isNotEmpty()) put("p_tags", JsonArray(request.tags.map(::JsonPrimitive)))
        put("p_twofa_enabled", request.twofaEnabled)
        request.twofaType?.let { put("p_twofa_type", it) }
        if (request.recoveryCodes.isNotEmpty()) {
            put("p_recovery_codes", JsonArray(request.recoveryCodes.map(::JsonPrimitive)))
        }
    }

    private fun kotlinx.serialization.json.JsonObjectBuilder.requestParameters(request: UpdateSecretRequestData) =
        requestParameters(
            CreateSecretRequestData(
                website = request.website,
                username = request.username,
                password = request.password,
                notes = request.notes,
                expirationDate = request.expirationDate,
                tags = request.tags,
                twofaEnabled = request.twofaEnabled,
                twofaType = request.twofaType,
                recoveryCodes = request.recoveryCodes,
            ),
        )

    private fun <T> failed(
        operation: String,
        error: Exception,
    ): Result<T> {
        logger.warn(
            LogCategory.NETWORK,
            "Execution-principal secret RPC failed",
            data = mapOf("operation" to operation, "errorType" to error::class.simpleName),
        )
        return Result.failure(sanitizeSupabaseFailure(operation, error))
    }

    @Serializable
    private data class MutationResponse(
        val success: Boolean,
        val error: String? = null,
        @kotlinx.serialization.SerialName("secret_id")
        val secretId: String? = null,
    )
}
