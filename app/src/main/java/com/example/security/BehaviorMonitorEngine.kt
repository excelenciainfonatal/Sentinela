package com.example.security

import android.Manifest
import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.TrafficStats
import android.os.Build
import android.os.Process
import android.provider.Settings
import com.example.data.local.BehaviorEventEntity
import com.example.data.local.EventSeverity
import com.example.data.local.ScanAuditEntity
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class BehavioralTelemetryResult(
  val launchCountByPackage: Map<String, Int>,
  val eventsDetected: List<BehaviorEventEntity>,
  val usageAccessGranted: Boolean,
)

class BehaviorMonitorEngine(private val context: Context) {

  fun hasUsageStatsPermission(): Boolean {
    val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
    val mode =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        appOps.unsafeCheckOpNoThrow(
          AppOpsManager.OPSTR_GET_USAGE_STATS,
          Process.myUid(),
          context.packageName,
        )
      } else {
        @Suppress("DEPRECATION")
        appOps.checkOpNoThrow(
          AppOpsManager.OPSTR_GET_USAGE_STATS,
          Process.myUid(),
          context.packageName,
        )
      }
    return mode == AppOpsManager.MODE_ALLOWED
  }

  private fun queryRecentLaunchCounts(hasUsage: Boolean): Map<String, Int> {
    if (!hasUsage) return emptyMap()
    return try {
      val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
      val end = System.currentTimeMillis()
      val start = end - 30 * 60 * 1000L
      val usageEvents = usm.queryEvents(start, end)
      val event = UsageEvents.Event()
      val foregroundEventType =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) UsageEvents.Event.ACTIVITY_RESUMED
        else @Suppress("DEPRECATION") UsageEvents.Event.MOVE_TO_FOREGROUND
      val counts = mutableMapOf<String, Int>()
      while (usageEvents.hasNextEvent()) {
        usageEvents.getNextEvent(event)
        if (event.eventType == foregroundEventType && event.packageName != null) {
          val pkg = event.packageName
          if (pkg != context.packageName) {
            counts[pkg] = (counts[pkg] ?: 0) + 1
          }
        }
      }
      counts
    } catch (_: Exception) {
      emptyMap()
    }
  }

  private fun resolveEnabledAccessibilityPackages(): Set<String> {
    return try {
      val enabled =
        Settings.Secure.getString(
          context.contentResolver,
          Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return emptySet()
      enabled
        .split(":")
        .mapNotNull { component ->
          component.substringBefore('/', "").trim().takeIf { it.isNotEmpty() }
        }
        .toSet()
    } catch (_: Exception) {
      emptySet()
    }
  }

  suspend fun collectRealTimeTelemetry(
    installedAudits: List<ScanAuditEntity>,
    whitelistedPackages: Set<String> = emptySet(),
  ): BehavioralTelemetryResult =
    withContext(Dispatchers.IO) {
      val hasUsage = hasUsageStatsPermission()
      val launchCounts = queryRecentLaunchCounts(hasUsage)
      val enabledAccessibility = resolveEnabledAccessibilityPackages()
      val detectedEvents = mutableListOf<BehaviorEventEntity>()
      val auditByPkg =
        installedAudits
          .filter { it.packageName !in whitelistedPackages }
          .associateBy { it.packageName }

      // 1. Rapid activity hijacking / excessive foreground bursts
      if (hasUsage) {
        launchCounts.forEach { (pkg, count) ->
          val audit = auditByPkg[pkg]
          if (count >= 12 && audit != null && !audit.isSystemApp) {
            detectedEvents +=
              BehaviorEventEntity(
                packageName = pkg,
                appName = audit.appName,
                eventType = "RAPID_LAUNCH",
                severity =
                  if (audit.riskScore >= 40) EventSeverity.CRITICAL.name
                  else EventSeverity.WARNING.name,
                details =
                  "Comportamento anômalo em tempo real: $count ativações de tela em 30 min (possível sequestro de foco/adware).",
                txBytes = audit.txBytes,
                rxBytes = audit.rxBytes,
              )
          }
        }
      }

      // 2. Real-time Accessibility Service active check & Silent Background Exfiltration check
      val pm = context.packageManager
      installedAudits.forEach { audit ->
        if (
          !audit.isSystemApp &&
            audit.packageName != context.packageName &&
            audit.packageName !in whitelistedPackages
        ) {
          if (audit.packageName in enabledAccessibility) {
            detectedEvents +=
              BehaviorEventEntity(
                packageName = audit.packageName,
                appName = audit.appName,
                eventType = "ACCESSIBILITY_ACTIVE",
                severity = EventSeverity.CRITICAL.name,
                details =
                  "Serviço de Acessibilidade ativo em segundo plano: este app pode ler sua tela e clicar em botões automaticamente.",
                txBytes = audit.txBytes,
                rxBytes = audit.rxBytes,
              )
          }

          val uid =
            try {
              pm.getApplicationInfo(audit.packageName, 0).uid
            } catch (_: Exception) {
              -1
            }
          if (uid > 0) {
            val tx = TrafficStats.getUidTxBytes(uid).coerceAtLeast(0L)
            val rx = TrafficStats.getUidRxBytes(uid).coerceAtLeast(0L)
            val twoMb = 2L * 1024L * 1024L
            val fiveMb = 5L * 1024L * 1024L
            val launches = if (hasUsage) (launchCounts[audit.packageName] ?: 0) else -1
            val originLabel =
              if (audit.installerSource == "com.android.vending") "Google Play Store"
              else "app fora da loja oficial"

            if (tx >= twoMb && launches == 0) {
              detectedEvents +=
                BehaviorEventEntity(
                  packageName = audit.packageName,
                  appName = audit.appName,
                  eventType = "NETWORK_ANOMALY",
                  severity = EventSeverity.CRITICAL.name,
                  details =
                    "Comunicação oculta ($originLabel): enviou ${formatBytes(tx)} para fora sem você abrir o aplicativo.",
                  txBytes = tx,
                  rxBytes = rx,
                )
            } else if (tx > fiveMb && tx > (rx * 2 + 1_048_576L)) {
              detectedEvents +=
                BehaviorEventEntity(
                  packageName = audit.packageName,
                  appName = audit.appName,
                  eventType = "NETWORK_ANOMALY",
                  severity = EventSeverity.WARNING.name,
                  details =
                    "Comunicação oculta ($originLabel): tráfego de saída elevado (${formatBytes(tx)} enviados vs ${formatBytes(rx)} recebidos).",
                  txBytes = tx,
                  rxBytes = rx,
                )
            }
          }
        }
      }

      BehavioralTelemetryResult(
        launchCountByPackage = launchCounts,
        eventsDetected = detectedEvents,
        usageAccessGranted = hasUsage,
      )
    }

  suspend fun auditLauncherPackages(
    settings: SecuritySettings,
    whitelistedPackages: Set<String> = emptySet(),
    catalogThreats: List<ThreatCatalogEntity> = emptyList(),
    trustLookup: suspend (String) -> TrustStatus,
    previousSigLookup: suspend (String) -> String?,
  ): List<ScanAuditEntity> =
    withContext(Dispatchers.IO) {
      val pm = context.packageManager
      val hasUsage = hasUsageStatsPermission()
      val launchCounts = queryRecentLaunchCounts(hasUsage)
      val enabledAccessibility = resolveEnabledAccessibilityPackages()
      val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
      val resolveInfos =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          pm.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0L))
        } else {
          @Suppress("DEPRECATION")
          pm.queryIntentActivities(launcherIntent, 0)
        }

      val uniquePackages = resolveInfos.mapNotNull { it.activityInfo?.packageName }.distinct()
      val results = mutableListOf<ScanAuditEntity>()

      for (pkg in uniquePackages) {
        if (pkg == context.packageName || pkg in whitelistedPackages) continue
        val launches = if (hasUsage) (launchCounts[pkg] ?: 0) else -1
        auditSingleInstalledPackage(
          packageName = pkg,
          sourceType = "INSTALLED_APP",
          settings = settings,
          catalogThreats = catalogThreats,
          enabledAccessibilityPackages = enabledAccessibility,
          foregroundLaunchCount = launches,
          trustLookup = trustLookup,
          previousSigLookup = previousSigLookup,
        )?.let { results += it }
      }

      results
    }

  suspend fun auditSingleInstalledPackage(
    packageName: String,
    sourceType: String,
    settings: SecuritySettings,
    catalogThreats: List<ThreatCatalogEntity> = emptyList(),
    enabledAccessibilityPackages: Set<String> = resolveEnabledAccessibilityPackages(),
    foregroundLaunchCount: Int = -1,
    trustLookup: suspend (String) -> TrustStatus,
    previousSigLookup: suspend (String) -> String?,
  ): ScanAuditEntity? =
    withContext(Dispatchers.IO) {
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
        try {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
          } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, flags)
          }
        } catch (_: Exception) {
          return@withContext null
        }

      val appInfo = pkgInfo.applicationInfo
      val appName = appInfo?.loadLabel(pm)?.toString()?.takeIf { it.isNotBlank() } ?: packageName
      val versionName = pkgInfo.versionName ?: "1.0"
      val targetSdk = appInfo?.targetSdkVersion ?: 0
      val appFlags = appInfo?.flags ?: 0
      val isSystem = (appFlags and ApplicationInfo.FLAG_SYSTEM) != 0
      val isDebuggable = (appFlags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
      val uid = appInfo?.uid ?: -1
      val txBytes = if (uid > 0) TrafficStats.getUidTxBytes(uid).coerceAtLeast(0L) else 0L
      val rxBytes = if (uid > 0) TrafficStats.getUidRxBytes(uid).coerceAtLeast(0L) else 0L

      val declaresAccessibilityService =
        pkgInfo.services?.any { it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE } == true
      val isAccessibilityEnabled = packageName in enabledAccessibilityPackages

      val installerSource = resolveInstallerSource(pm, packageName, isSystem)
      val sigAnalysis = SignatureVerifier.analyze(pkgInfo)
      val trustStatus =
        if (sigAnalysis.hasSignature) trustLookup(sigAnalysis.sha256Fingerprint)
        else TrustStatus.NEUTRAL

      val previousSig = previousSigLookup(packageName)
      val permissions = pkgInfo.requestedPermissions?.toList().orEmpty()

      val riskResult =
        RiskHeuristicEngine.evaluate(
          RiskAssessmentInput(
            packageName = packageName,
            signature = sigAnalysis,
            requestedPermissions = permissions,
            targetSdk = targetSdk,
            isDebuggableApp = isDebuggable,
            isSystemApp = isSystem,
            installerSource = installerSource,
            installedSignatureSha256 = previousSig,
            certificateTrustStatus = trustStatus,
            settings = settings,
            appName = appName,
            declaresAccessibilityService = declaresAccessibilityService,
            isAccessibilityServiceEnabled = isAccessibilityEnabled,
            txBytes = txBytes,
            rxBytes = rxBytes,
            foregroundLaunchCount = foregroundLaunchCount,
            catalogThreats = catalogThreats,
          )
        )

      ScanAuditEntity(
        packageName = packageName,
        appName = appName,
        versionName = versionName,
        sourceType = sourceType,
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
        installerSource = installerSource,
        targetSdk = targetSdk,
        isDebuggableApp = isDebuggable,
        isSystemApp = isSystem,
        txBytes = txBytes,
        rxBytes = rxBytes,
        findingsSummary = riskResult.findings.joinToString("\n• ", prefix = "• "),
        dangerousPermissions = riskResult.dangerousPermissions.joinToString(","),
        threatCategory = riskResult.threatCategory.name,
        isPlayStoreApp = riskResult.isPlayStoreApp,
        hasAccessibilityAbuse = riskResult.hasAccessibilityAbuse,
        hasPermissionAbuse = riskResult.hasPermissionAbuse,
        hasHiddenCommunication = riskResult.hasHiddenCommunication,
        matchedThreatName = riskResult.matchedThreatName,
      )
    }

  private fun resolveInstallerSource(
    pm: PackageManager,
    packageName: String,
    isSystem: Boolean,
  ): String {
    if (isSystem) return "Sistema Android"
    return try {
      val installer =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
          pm.getInstallSourceInfo(packageName).installingPackageName
        } else {
          @Suppress("DEPRECATION")
          pm.getInstallerPackageName(packageName)
        }
      when (installer) {
        null -> "Sideload / Instalador Manual"
        "com.android.vending" -> "com.android.vending"
        "com.google.android.packageinstaller",
        "com.android.packageinstaller" -> "Instalador Local (APK)"
        else -> installer
      }
    } catch (_: Exception) {
      "Origem Desconhecida"
    }
  }

  companion object {
    fun formatBytes(bytes: Long): String {
      if (bytes <= 0L) return "0 B"
      val kb = bytes / 1024.0
      val mb = kb / 1024.0
      val gb = mb / 1024.0
      return when {
        gb >= 1.0 -> String.format("%.1f GB", gb)
        mb >= 1.0 -> String.format("%.1f MB", mb)
        kb >= 1.0 -> String.format("%.0f KB", kb)
        else -> "$bytes B"
      }
    }
  }
}
