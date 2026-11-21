package com.example.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import com.example.data.local.ScanAuditEntity
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class ApkInspectionReport(
  val audit: ScanAuditEntity,
  val fileName: String,
  val fileSizeBytes: Long,
  val dexCount: Int,
  val nativeAbis: List<String>,
  val findings: List<String>,
  val dangerousPermissions: List<String>,
  val signatureAnalysis: SignatureAnalysis,
  val fileSha256: String = "",
  val staticIndicators: List<String> = emptyList(),
)

class ApkGatekeeperAnalyzer(private val context: Context) {

  suspend fun inspectApkUri(
    uri: Uri,
    settings: SecuritySettings,
    catalogThreats: List<ThreatCatalogEntity> = emptyList(),
    trustLookup: suspend (String) -> TrustStatus,
    installedSigLookup: suspend (String) -> String?,
  ): Result<ApkInspectionReport> =
    withContext(Dispatchers.IO) {
      val tempApk = File(context.cacheDir, "gatekeeper_${System.currentTimeMillis()}.apk")
      try {
        val fileName = resolveDisplayName(uri)
        context.contentResolver.openInputStream(uri)?.use { input ->
          tempApk.outputStream().use { output -> input.copyTo(output) }
        } ?: return@withContext Result.failure(IllegalStateException("Não foi possível abrir o arquivo APK."))

        if (tempApk.length() == 0L) {
          return@withContext Result.failure(IllegalArgumentException("O arquivo selecionado está vazio."))
        }

        val fileSha256 = computeFileSha256(tempApk)

        val pm = context.packageManager
        val flags =
          PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SERVICES or
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              PackageManager.GET_SIGNING_CERTIFICATES
            } else {
              @Suppress("DEPRECATION")
              PackageManager.GET_SIGNATURES
            }

        val pkgInfo: PackageInfo =
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageArchiveInfo(tempApk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
          } else {
            @Suppress("DEPRECATION")
            pm.getPackageArchiveInfo(tempApk.absolutePath, flags)
          }
            ?: return@withContext Result.failure(
              IllegalArgumentException("Arquivo inválido: não contém um AndroidManifest.xml de APK válido.")
            )

        pkgInfo.applicationInfo?.apply {
          sourceDir = tempApk.absolutePath
          publicSourceDir = tempApk.absolutePath
        }

        val appName =
          pkgInfo.applicationInfo?.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() }
            ?: fileName.removeSuffix(".apk")
        val packageName = pkgInfo.packageName ?: "pacote.desconhecido"
        val versionName = pkgInfo.versionName ?: "1.0"
        val targetSdk = pkgInfo.applicationInfo?.targetSdkVersion ?: 0
        val isDebuggable =
          ((pkgInfo.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val permissions = pkgInfo.requestedPermissions?.toList().orEmpty()
        val declaresAccessibilityService =
          pkgInfo.services?.any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE } == true

        // Inspect static archive entries & bounded DEX strings without loading or executing any code
        var dexCount = 0
        val nativeAbis = mutableSetOf<String>()
        val staticIndicators = mutableSetOf<String>()
        var bytesScannedForStrings = 0L
        val maxDexScanBytes = 4L * 1024L * 1024L

        ZipFile(tempApk).use { zip ->
          val entries = zip.entries()
          while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            val name = entry.name
            val lower = name.lowercase()
            if (name.startsWith("classes") && name.endsWith(".dex")) {
              dexCount++
              if (bytesScannedForStrings < maxDexScanBytes) {
                val remaining = (maxDexScanBytes - bytesScannedForStrings).toInt().coerceAtMost(2 * 1024 * 1024)
                val readBytes = zip.getInputStream(entry).use { it.readNBytesCompat(remaining) }
                bytesScannedForStrings += readBytes.size
                val contentText = String(readBytes, Charsets.ISO_8859_1)
                scanStaticIndicators(contentText, staticIndicators)
              }
            } else if (name.startsWith("lib/") && name.endsWith(".so")) {
              val parts = name.split("/")
              if (parts.size >= 2) nativeAbis += parts[1]
              if (lower.contains("triada")) staticIndicators += "libtriada.so"
            } else if ((lower.startsWith("assets/") || lower.startsWith("res/raw/")) && lower.endsWith(".apk")) {
              staticIndicators += "nested_apk_in_assets"
            } else if ((lower.startsWith("assets/") || lower.startsWith("res/raw/")) && lower.endsWith(".jar")) {
              staticIndicators += "nested_jar_payload"
            }
          }
        }

        val sigAnalysis = SignatureVerifier.analyze(pkgInfo)
        val trustStatus =
          if (sigAnalysis.hasSignature) trustLookup(sigAnalysis.sha256Fingerprint)
          else TrustStatus.NEUTRAL

        // Check installed package signature directly from PackageManager first, then DB
        val installedSha256 = getInstalledPackageSha256(pm, packageName) ?: installedSigLookup(packageName)

        val extraFindings = mutableListOf<String>()
        var extraScore = 0
        if (dexCount > 4) {
          extraScore += 10
          extraFindings += "Múltiplos arquivos DEX ($dexCount) — complexidade elevada de código"
        }
        if (dexCount == 0) {
          extraScore += 25
          staticIndicators += "missing_classes_dex"
          extraFindings += "Nenhum classes.dex encontrado no pacote"
        }

        val riskResult =
          RiskHeuristicEngine.evaluate(
            RiskAssessmentInput(
              packageName = packageName,
              signature = sigAnalysis,
              requestedPermissions = permissions,
              targetSdk = targetSdk,
              isDebuggableApp = isDebuggable,
              isSystemApp = false,
              installerSource = "Inspeção Pré-Instalação",
              installedSignatureSha256 = installedSha256,
              certificateTrustStatus = trustStatus,
              settings = settings,
              behavioralAnomalyScore = extraScore,
              behavioralFindings = extraFindings,
              appName = appName,
              declaresAccessibilityService = declaresAccessibilityService,
              staticIndicators = staticIndicators.toList(),
              fileSha256 = fileSha256,
              catalogThreats = catalogThreats,
            )
          )

        val audit =
          ScanAuditEntity(
            packageName = packageName,
            appName = appName,
            versionName = versionName,
            sourceType = "APK_PRE_INSTALL",
            verdict = riskResult.verdict.name,
            riskScore = riskResult.riskScore,
            sha256Fingerprint = sigAnalysis.sha256Fingerprint,
            sha1Fingerprint = sigAnalysis.sha1Fingerprint,
            signerSubject = sigAnalysis.subject,
            signerIssuer = sigAnalysis.issuer,
            keyAlgorithmInfo = sigAnalysis.keyAlgorithmInfo,
            validUntilMillis = sigAnalysis.validUntilMillis,
            isDebugCert = sigAnalysis.isDebugCert,
            isExpiredCert = sigAnalysis.isExpired,
            isSelfSigned = sigAnalysis.isSelfSigned,
            signatureMismatch = riskResult.signatureMismatch,
            installerSource = "APK Externo ($fileName)",
            targetSdk = targetSdk,
            isDebuggableApp = isDebuggable,
            isSystemApp = false,
            txBytes = 0L,
            rxBytes = 0L,
            findingsSummary = riskResult.findings.joinToString("\n• ", prefix = "• "),
            dangerousPermissions = riskResult.dangerousPermissions.joinToString(","),
            threatCategory = riskResult.threatCategory.name,
            isPlayStoreApp = false,
            hasAccessibilityAbuse = riskResult.hasAccessibilityAbuse,
            hasPermissionAbuse = riskResult.hasPermissionAbuse,
            hasHiddenCommunication = riskResult.hasHiddenCommunication,
            matchedThreatName = riskResult.matchedThreatName,
          )

        Result.success(
          ApkInspectionReport(
            audit = audit,
            fileName = fileName,
            fileSizeBytes = tempApk.length(),
            dexCount = dexCount,
            nativeAbis = nativeAbis.sorted(),
            findings = riskResult.findings,
            dangerousPermissions = riskResult.dangerousPermissions,
            signatureAnalysis = sigAnalysis,
            fileSha256 = fileSha256,
            staticIndicators = staticIndicators.sorted(),
          )
        )
      } catch (e: Exception) {
        Result.failure(e)
      } finally {
        if (tempApk.exists()) tempApk.delete()
      }
    }

  private fun scanStaticIndicators(text: String, out: MutableSet<String>) {
    if (RAW_IP_URL_REGEX.containsMatchIn(text)) {
      out += "raw_ip_http_endpoint"
    }
    if (text.contains(".onion", ignoreCase = true)) {
      out += "onion_tor_c2"
    }
    if (text.contains("api.telegram.org/bot", ignoreCase = true)) {
      out += "api.telegram.org/bot"
    }
    if (text.contains("discord.com/api/webhooks", ignoreCase = true)) {
      out += "discord.com/api/webhooks"
    }
    if (text.contains("DexClassLoader") || text.contains("InMemoryDexClassLoader")) {
      out += "DexClassLoader"
    }
    if (text.contains("performGlobalAction") && text.contains("AccessibilityNodeInfo")) {
      out += "performGlobalAction"
      out += "AccessibilityNodeInfo"
    }
  }

  private fun computeFileSha256(file: File): String {
    return runCatching {
      val digest = MessageDigest.getInstance("SHA-256")
      val buffer = ByteArray(8192)
      file.inputStream().use { input ->
        var read = input.read(buffer)
        while (read > 0) {
          digest.update(buffer, 0, read)
          read = input.read(buffer)
        }
      }
      digest.digest().joinToString(":") { "%02X".format(it) }
    }.getOrDefault("")
  }

  private fun java.io.InputStream.readNBytesCompat(maxBytes: Int): ByteArray {
    val buffer = ByteArray(8192)
    val out = java.io.ByteArrayOutputStream()
    var total = 0
    while (total < maxBytes) {
      val toRead = minOf(buffer.size, maxBytes - total)
      val count = read(buffer, 0, toRead)
      if (count <= 0) break
      out.write(buffer, 0, count)
      total += count
    }
    return out.toByteArray()
  }

  private fun getInstalledPackageSha256(pm: PackageManager, packageName: String): String? {
    return try {
      val flags =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          PackageManager.GET_SIGNING_CERTIFICATES
        } else {
          @Suppress("DEPRECATION")
          PackageManager.GET_SIGNATURES
        }
      val info =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
          @Suppress("DEPRECATION")
          pm.getPackageInfo(packageName, flags)
        }
      val sig = SignatureVerifier.analyze(info)
      if (sig.hasSignature) sig.sha256Fingerprint else null
    } catch (_: Exception) {
      null
    }
  }

  private fun resolveDisplayName(uri: Uri): String {
    var result = "pacote_externo.apk"
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
      val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
      if (index >= 0 && cursor.moveToFirst()) {
        cursor.getString(index)?.let { result = it }
      }
    }
    return result
  }

  companion object {
    private val RAW_IP_URL_REGEX =
      Regex("""https?://(?!127\.0\.0\.1|10\.0\.2\.2|192\.168\.)\d{1,3}(?:\.\d{1,3}){3}""")
  }
}
