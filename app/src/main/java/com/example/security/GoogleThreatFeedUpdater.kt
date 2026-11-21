package com.example.security

import android.content.Context
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.ThreatCatalogSeeder
import com.example.data.local.ThreatType
import com.google.android.gms.security.ProviderInstaller
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

data class GoogleHttpResponse(
  val statusCode: Int,
  val body: String,
  val serverTimestampMillis: Long,
)

data class AntivirusUpdateResult(
  val catalogEntries: List<ThreatCatalogEntity>,
  val googleAdvisoriesCount: Int,
  val totalCatalogCount: Int,
  val versionLabel: String,
  val serverHost: String,
  val providerVerified: Boolean,
  val updatedAtMillis: Long,
  val summaryMessagePt: String,
)

class GoogleThreatFeedUpdater(
  private val context: Context,
  private val httpPostExecutor: (url: String, jsonBody: String) -> GoogleHttpResponse = ::defaultHttpsPost,
) {

  companion object {
    const val GOOGLE_OSV_ENDPOINT = "https://api.osv.dev/v1/query"
    const val GOOGLE_SERVER_LABEL = "Servidor Google OSV (api.osv.dev)"
    private const val ANDROID_OSV_QUERY_PAYLOAD =
      """{"package":{"name":"platform/frameworks/base","ecosystem":"Android"}}"""
    private const val MAX_GOOGLE_ADVISORIES = 20

    fun defaultHttpsPost(urlString: String, jsonBody: String): GoogleHttpResponse {
      val url = URL(urlString)
      val conn =
        (url.openConnection() as? HttpsURLConnection)
          ?: throw IOException("Conexão HTTPS segura obrigatória com o servidor do Google.")
      return try {
        conn.requestMethod = "POST"
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.doInput = true
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        conn.setRequestProperty("Accept", "application/json")
        conn.setRequestProperty("User-Agent", "SentinelaAndroidSecurity/1.0")

        conn.outputStream.use { out ->
          out.write(jsonBody.toByteArray(Charsets.UTF_8))
          out.flush()
        }

        val statusCode = conn.responseCode
        val stream =
          if (statusCode in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
        val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
        val serverDate = conn.date.takeIf { it > 0L } ?: System.currentTimeMillis()
        GoogleHttpResponse(
          statusCode = statusCode,
          body = body,
          serverTimestampMillis = serverDate,
        )
      } finally {
        conn.disconnect()
      }
    }
  }

  fun verifyGoogleSecurityProvider(): Boolean {
    return runCatching {
        ProviderInstaller.installIfNeeded(context)
        true
      }
      .getOrDefault(false)
  }

  suspend fun fetchLatestDefinitions(): Result<AntivirusUpdateResult> =
    withContext(Dispatchers.IO) {
      val providerVerified = verifyGoogleSecurityProvider()
      try {
        val response = httpPostExecutor(GOOGLE_OSV_ENDPOINT, ANDROID_OSV_QUERY_PAYLOAD)
        if (response.statusCode !in HttpURLConnection.HTTP_OK..299) {
          return@withContext Result.failure(
            IOException("Servidor do Google respondeu com código HTTP ${response.statusCode}.")
          )
        }
        val now = System.currentTimeMillis()
        val googleEntries = parseGoogleOsvResponse(response.body, now)
        val baseEntries =
          ThreatCatalogSeeder.defaultCatalogEntries().map { entry -> entry.copy(updatedAt = now) }
        val combined = (baseEntries + googleEntries).distinctBy { it.threatKey }
        val dateStamp = SimpleDateFormat("yyyy.MM.dd", Locale.US).format(Date(now))
        val versionLabel = "OSV-$dateStamp • ${combined.size} regras"
        val msg =
          if (googleEntries.isNotEmpty()) {
            "Antivírus atualizado via Google: ${googleEntries.size} boletins Android sincronizados (${combined.size} regras ativas)."
          } else {
            "Base verificada no servidor do Google (${combined.size} regras ativas)."
          }

        Result.success(
          AntivirusUpdateResult(
            catalogEntries = combined,
            googleAdvisoriesCount = googleEntries.size,
            totalCatalogCount = combined.size,
            versionLabel = versionLabel,
            serverHost = GOOGLE_SERVER_LABEL,
            providerVerified = providerVerified,
            updatedAtMillis = now,
            summaryMessagePt = msg,
          )
        )
      } catch (e: Exception) {
        Result.failure(
          IOException(
            "Não foi possível conectar ao servidor do Google (${e.message ?: "sem conexão"}).",
            e,
          )
        )
      }
    }

  internal fun parseGoogleOsvResponse(rawJson: String, updatedAtMillis: Long): List<ThreatCatalogEntity> {
    if (rawJson.isBlank()) return emptyList()
    val root = JSONObject(rawJson)
    val vulns: JSONArray = root.optJSONArray("vulns") ?: return emptyList()
    val parsed = mutableListOf<Pair<String, ThreatCatalogEntity>>()

    for (i in 0 until vulns.length()) {
      val item = vulns.optJSONObject(i) ?: continue
      val id = item.optString("id").trim()
      if (id.isBlank()) continue

      val summary = item.optString("summary").trim()
      val details = item.optString("details").trim()
      val modified = item.optString("modified").trim()
      val combinedText = "$summary $details".lowercase(Locale.ROOT)

      val severityScore = extractSeverityScore(item, combinedText)
      val threatType = classifyThreatType(combinedText)
      val titleText =
        summary.takeIf { it.isNotBlank() }
          ?: details.lineSequence().firstOrNull()?.trim()?.take(90)
          ?: "Boletim de Segurança Android"
      val cleanTitle = "Google $id: ${titleText.take(72)}"

      val plainDesc =
        buildString {
          append("Aviso oficial catalogado no servidor Google OSV ($id). ")
          if (summary.isNotBlank()) {
            append(summary.take(220))
          } else if (details.isNotBlank()) {
            append(details.take(220))
          } else {
            append("Vulnerabilidade ou vetor de exploração monitorado para Android.")
          }
        }

      val entry =
        ThreatCatalogEntity(
          threatKey = "GOOGLE_OSV_${id.replace(Regex("[^A-Za-z0-9_-]"), "_")}",
          name = cleanTitle,
          threatType = threatType.name,
          severityScore = severityScore,
          packagePatterns = "",
          sha256Signatures = "",
          permissionSignature = inferPermissionHint(combinedText),
          indicatorTokens = inferIndicatorTokens(id, combinedText),
          descriptionPt = plainDesc,
          recommendationPt =
            "Mantenha o sistema Android atualizado e evite instalar APKs externos não verificados.",
          sourceReference = GOOGLE_SERVER_LABEL,
          isActive = true,
          updatedAt = updatedAtMillis,
        )
      parsed.add(modified to entry)
    }

    return parsed
      .sortedByDescending { it.first }
      .take(MAX_GOOGLE_ADVISORIES)
      .map { it.second }
  }

  private fun extractSeverityScore(item: JSONObject, lowerText: String): Int {
    val dbSpecific = item.optJSONObject("database_specific")
    val severityStr = dbSpecific?.optString("severity")?.uppercase(Locale.ROOT).orEmpty()
    return when {
      severityStr.contains("CRITICAL") || lowerText.contains("critical") -> 92
      severityStr.contains("HIGH") || lowerText.contains("remote code execution") -> 84
      severityStr.contains("MODERATE") || severityStr.contains("MEDIUM") -> 72
      severityStr.contains("LOW") -> 60
      else -> 76
    }
  }

  private fun classifyThreatType(lowerText: String): ThreatType {
    return when {
      lowerText.contains("adware") || lowerText.contains("popup") -> ThreatType.ADWARE
      lowerText.contains("spy") ||
        lowerText.contains("sms") ||
        lowerText.contains("microphone") ||
        lowerText.contains("camera") ||
        lowerText.contains("location") ||
        lowerText.contains("clipboard") -> ThreatType.SPYWARE
      lowerText.contains("trojan") ||
        lowerText.contains("ransom") ||
        lowerText.contains("remote code") ||
        lowerText.contains("elevation of privilege") -> ThreatType.VIRUS
      else -> ThreatType.ARQUIVO_MALICIOSO
    }
  }

  private fun inferPermissionHint(lowerText: String): String {
    val hints = mutableListOf<String>()
    if (lowerText.contains("accessibility")) hints.add("BIND_ACCESSIBILITY_SERVICE")
    if (lowerText.contains("sms")) hints.add("READ_SMS")
    if (lowerText.contains("install")) hints.add("REQUEST_INSTALL_PACKAGES")
    if (lowerText.contains("overlay") || lowerText.contains("window")) {
      hints.add("SYSTEM_ALERT_WINDOW")
    }
    return hints.joinToString(",")
  }

  private fun inferIndicatorTokens(id: String, lowerText: String): String {
    val tokens = mutableListOf(id)
    if (lowerText.contains("dex")) tokens.add("DexClassLoader")
    if (lowerText.contains("webview")) tokens.add("hidden_webview")
    return tokens.joinToString(",")
  }
}
