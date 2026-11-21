package com.example.data

import android.content.Context
import android.net.Uri
import com.example.data.local.BehaviorEventEntity
import com.example.data.local.CertificateRuleEntity
import com.example.data.local.EventSeverity
import com.example.data.local.ScanAuditEntity
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.SentinelaDao
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.ThreatCatalogSeeder
import com.example.data.local.ThreatType
import com.example.data.local.TrustStatus
import com.example.data.local.WhitelistedAppEntity
import com.example.data.preferences.SecurityPreferences
import com.example.data.preferences.SecuritySettings
import com.example.security.AntivirusUpdateResult
import com.example.security.ApkGatekeeperAnalyzer
import com.example.security.ApkInspectionReport
import com.example.security.BehaviorMonitorEngine
import com.example.security.GoogleThreatFeedUpdater
import com.example.service.MonitorServiceState
import com.example.service.SecurityNotifier
import com.example.service.ThreatAlertType
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first

data class ThreatStatsSummary(
  val totalAppsAudited: Int = 0,
  val totalApkInspected: Int = 0,
  val blockedCount: Int = 0,
  val suspiciousCount: Int = 0,
  val safeCount: Int = 0,
  val invalidSignatureCount: Int = 0,
  val playStoreFlaggedCount: Int = 0,
  val externalFlaggedCount: Int = 0,
  val accessibilityRiskCount: Int = 0,
  val permissionAbuseCount: Int = 0,
  val hiddenCommCount: Int = 0,
  val totalHistoricalScans: Int = 0,
  val historicalThreatsFound: Int = 0,
  val criticalBehaviorEvents: Int = 0,
  val warningBehaviorEvents: Int = 0,
  val lastScanTimestamp: Long = 0L,
)

class SecurityRepository(
  private val context: Context,
  private val dao: SentinelaDao,
  private val preferences: SecurityPreferences,
  private val apkAnalyzer: ApkGatekeeperAnalyzer,
  val behaviorEngine: BehaviorMonitorEngine,
  private val googleUpdater: GoogleThreatFeedUpdater = GoogleThreatFeedUpdater(context),
) {

  private val recentPackageEvents = ConcurrentHashMap<String, Long>()

  val allAudits: Flow<List<ScanAuditEntity>> = dao.observeAllAudits()
  val apkGatekeeperAudits: Flow<List<ScanAuditEntity>> = dao.observeApkGatekeeperAudits()
  val installedAppAudits: Flow<List<ScanAuditEntity>> = dao.observeInstalledAppAudits()
  val certificateRules: Flow<List<CertificateRuleEntity>> = dao.observeAllCertificateRules()
  val behaviorEvents: Flow<List<BehaviorEventEntity>> = dao.observeBehaviorEvents()
  val scanHistory: Flow<List<ScanHistoryEntity>> = dao.observeScanHistory()
  val whitelistedApps: Flow<List<WhitelistedAppEntity>> = dao.observeWhitelistedApps()
  val threatCatalog: Flow<List<ThreatCatalogEntity>> = dao.observeThreatCatalog()
  val threatStatsSummary: Flow<ThreatStatsSummary> =
    combine(dao.observeAuditStats(), dao.observeHistoryStats(), dao.observeBehaviorStats()) {
      auditStats,
      historyStats,
      behaviorStats ->
      ThreatStatsSummary(
        totalAppsAudited = auditStats.totalAppsAudited,
        totalApkInspected = auditStats.totalApkInspected,
        blockedCount = auditStats.blockedCount,
        suspiciousCount = auditStats.suspiciousCount,
        safeCount = auditStats.safeCount,
        invalidSignatureCount = auditStats.invalidSignatureCount,
        playStoreFlaggedCount = auditStats.playStoreFlaggedCount,
        externalFlaggedCount = auditStats.externalFlaggedCount,
        accessibilityRiskCount = auditStats.accessibilityRiskCount,
        permissionAbuseCount = auditStats.permissionAbuseCount,
        hiddenCommCount = auditStats.hiddenCommCount,
        totalHistoricalScans = historyStats.totalScans,
        historicalThreatsFound = historyStats.historicalThreatsFound,
        criticalBehaviorEvents = behaviorStats.criticalCount,
        warningBehaviorEvents = behaviorStats.warningCount,
        lastScanTimestamp = historyStats.lastScanTimestamp,
      )
    }
  val settings: Flow<SecuritySettings> = preferences.settingsFlow

  fun observeAuditById(id: Long): Flow<ScanAuditEntity?> = dao.observeAuditById(id)

  fun observeAuditWithFallback(id: Long, packageName: String): Flow<ScanAuditEntity?> =
    dao.observeAuditWithFallback(id, packageName)

  suspend fun ensureCatalogSeeded() {
    if (dao.countThreatCatalog() == 0) {
      dao.upsertThreatCatalog(ThreatCatalogSeeder.defaultCatalogEntries())
    }
  }

  suspend fun restoreDefaultCatalog() {
    dao.upsertThreatCatalog(ThreatCatalogSeeder.defaultCatalogEntries())
  }

  suspend fun addCustomThreatCatalogEntry(entry: ThreatCatalogEntity) {
    dao.upsertThreatCatalogEntry(entry)
  }

  suspend fun deleteThreatCatalogEntry(threatKey: String) {
    dao.deleteThreatCatalogEntry(threatKey)
  }

  suspend fun setAutoAntivirusUpdatesEnabled(enabled: Boolean) {
    preferences.setAutoAntivirusUpdatesEnabled(enabled)
  }

  suspend fun updateAntivirusDefinitionsFromGoogle(isAutomatic: Boolean): Result<AntivirusUpdateResult> {
    ensureCatalogSeeded()
    val result = googleUpdater.fetchLatestDefinitions()
    result
      .onSuccess { update ->
        dao.upsertThreatCatalog(update.catalogEntries)
        preferences.recordAntivirusUpdateSuccess(
          updatedAt = update.updatedAtMillis,
          versionLabel = update.versionLabel,
          statusMessage = update.summaryMessagePt,
          sourceName = update.serverHost,
          newDefinitionsCount = update.googleAdvisoriesCount,
          providerVerified = update.providerVerified,
        )
        val originLabel = if (isAutomatic) "rotina automática (Google)" else "atualização manual"
        dao.insertBehaviorEvent(
          BehaviorEventEntity(
            packageName = "com.aistudio.sentinela",
            appName = "Sentinela Antivírus",
            eventType = "ANTIVIRUS_DEFINITIONS_UPDATED",
            severity = EventSeverity.INFO.name,
            details =
              "Base de ameaças atualizada via $originLabel (${update.serverHost}): ${update.totalCatalogCount} definições ativas.",
            txBytes = 0L,
            rxBytes = 0L,
          )
        )
        scanAllInstalledApps()
      }
      .onFailure { error ->
        val providerOk = googleUpdater.verifyGoogleSecurityProvider()
        preferences.recordAntivirusUpdateFailure(
          statusMessage = error.message ?: "Falha ao sincronizar com servidor do Google.",
          providerVerified = providerOk,
        )
      }
    return result
  }

  suspend fun inspectApkForInstallation(uri: Uri): Result<ApkInspectionReport> {
    ensureCatalogSeeded()
    val currentSettings = settings.first()
    val catalog = dao.getActiveThreatCatalog()
    val result =
      apkAnalyzer.inspectApkUri(
        uri = uri,
        settings = currentSettings,
        catalogThreats = catalog,
        trustLookup = { sha -> getTrustStatus(sha) },
        installedSigLookup = { pkg -> dao.getLatestInstalledAuditForPackage(pkg)?.sha256Fingerprint },
      )

    result.onSuccess { report ->
      val insertedId = dao.insertAudit(report.audit)
      dao.insertScanHistory(
        report.audit.toScanHistory(
          auditId = insertedId,
          scanSource = "GATEKEEPER_APK",
        )
      )
      val verdict = SecurityVerdict.valueOf(report.audit.verdict)
      if (verdict == SecurityVerdict.BLOQUEADO) {
        dao.insertBehaviorEvent(
          BehaviorEventEntity(
            packageName = report.audit.packageName,
            appName = report.audit.appName,
            eventType = "INSTALL_BLOCKED",
            severity = EventSeverity.CRITICAL.name,
            details =
              "Instalação bloqueada no Gatekeeper (${report.fileName}) — Score ${report.audit.riskScore}/100. ${report.findings.firstOrNull().orEmpty()}",
            txBytes = 0L,
            rxBytes = 0L,
          )
        )
        if (currentSettings.pushAlertsEnabled) {
          val alertType =
            if (report.audit.signatureMismatch || report.audit.isExpiredCert || report.audit.isDebugCert) {
              ThreatAlertType.INVALID_SIGNATURE
            } else {
              ThreatAlertType.BLOCKED_INSTALL
            }
          SecurityNotifier.postSecurityThreatPushAlert(
            context = context,
            alertType = alertType,
            title = "Instalação Bloqueada: ${report.audit.appName}",
            message =
              "O Sentinela impediu o APK ${report.fileName} (Risco ${report.audit.riskScore}/100). Motivo: ${report.findings.firstOrNull().orEmpty()}",
            appName = report.audit.appName,
            packageName = report.audit.packageName,
            sha256Fingerprint = report.audit.sha256Fingerprint,
            auditId = insertedId,
            idOffset = 3000,
          )
        }
      } else if (verdict == SecurityVerdict.SUSPEITO) {
        dao.insertBehaviorEvent(
          BehaviorEventEntity(
            packageName = report.audit.packageName,
            appName = report.audit.appName,
            eventType = "SENSITIVE_PERMISSION_COMBO",
            severity = EventSeverity.WARNING.name,
            details =
              "APK suspeito analisado (${report.fileName}) — Score ${report.audit.riskScore}/100.",
            txBytes = 0L,
            rxBytes = 0L,
          )
        )
        if (currentSettings.pushAlertsEnabled) {
          val alertType =
            resolveThreatAlertType(report.audit, defaultForBlocked = ThreatAlertType.BLOCKED_INSTALL)
          SecurityNotifier.postSecurityThreatPushAlert(
            context = context,
            alertType = alertType,
            title = "APK Suspeito: ${report.audit.appName}",
            message =
              "Risco ${report.audit.riskScore}/100 em ${report.fileName}. ${report.findings.firstOrNull().orEmpty()}",
            appName = report.audit.appName,
            packageName = report.audit.packageName,
            sha256Fingerprint = report.audit.sha256Fingerprint,
            auditId = insertedId,
            idOffset = 3000,
          )
        }
      }
    }
    return result
  }

  suspend fun scanAllInstalledApps(): Int {
    ensureCatalogSeeded()
    val currentSettings = settings.first()
    val whitelisted = dao.observeWhitelistedPackageNames().first().toSet()
    val catalog = dao.getActiveThreatCatalog()
    val scanned =
      behaviorEngine.auditLauncherPackages(
        settings = currentSettings,
        whitelistedPackages = whitelisted,
        catalogThreats = catalog,
        trustLookup = { sha -> getTrustStatus(sha) },
        previousSigLookup = { pkg -> dao.getLatestInstalledAuditForPackage(pkg)?.sha256Fingerprint },
      )

    if (scanned.isNotEmpty()) {
      dao.replaceInstalledAuditsAndRecordHistory(
        audits = scanned,
        scanSource = "VARREDURA_DISPOSITIVO",
      )
      if (currentSettings.pushAlertsEnabled) {
        val persistedAudits = installedAppAudits.first()
        notifyDetectedThreatsForAudits(persistedAudits, whitelisted)
      }
    }

    runBehavioralSweep()
    return scanned.size
  }

  suspend fun runBehavioralSweep(): Boolean {
    val currentSettings = settings.first()
    val whitelisted = dao.observeWhitelistedPackageNames().first().toSet()
    val installed = installedAppAudits.first()
    val auditByPkg = installed.associateBy { it.packageName }
    val telemetry = behaviorEngine.collectRealTimeTelemetry(installed, whitelisted)
    val cutoff = System.currentTimeMillis() - 15 * 60 * 1000L

    telemetry.eventsDetected.forEach { event ->
      val recent = dao.findRecentEvent(event.packageName, event.eventType, cutoff)
      if (recent == null) {
        dao.insertBehaviorEvent(event)
        if (
          currentSettings.pushAlertsEnabled &&
            (event.severity == EventSeverity.CRITICAL.name ||
              event.severity == EventSeverity.WARNING.name)
        ) {
          val matchedAudit = auditByPkg[event.packageName]
          SecurityNotifier.postSecurityThreatPushAlert(
            context = context,
            alertType = ThreatAlertType.SUSPICIOUS_BEHAVIOR,
            title =
              if (event.severity == EventSeverity.CRITICAL.name)
                "Comportamento Crítico: ${event.appName}"
              else "Comportamento Suspeito: ${event.appName}",
            message = event.details,
            appName = event.appName,
            packageName = event.packageName,
            sha256Fingerprint = matchedAudit?.sha256Fingerprint,
            auditId = matchedAudit?.id ?: -1L,
            idOffset = 4000,
          )
        }
      }
    }

    // Also alert on installed non-system apps with invalid digital signatures
    val sigCutoff = System.currentTimeMillis() - 6 * 60 * 60 * 1000L
    installed
      .filter {
        !it.isSystemApp &&
          it.packageName !in whitelisted &&
          (it.signatureMismatch ||
            it.isExpiredCert ||
            it.isDebugCert ||
            it.sha256Fingerprint == "SEM ASSINATURA")
      }
      .forEach { badApp ->
        val recentSigAlert =
          dao.findRecentEvent(badApp.packageName, "INVALID_SIGNATURE_ALERT", sigCutoff)
        if (recentSigAlert == null) {
          val reason =
            when {
              badApp.signatureMismatch -> "Assinatura divergente da versão anterior"
              badApp.sha256Fingerprint == "SEM ASSINATURA" -> "Aplicativo sem certificado digital"
              badApp.isExpiredCert -> "Certificado digital expirado"
              else -> "Assinado com chave de depuração/teste (Debug/TestKey)"
            }
          dao.insertBehaviorEvent(
            BehaviorEventEntity(
              packageName = badApp.packageName,
              appName = badApp.appName,
              eventType = "INVALID_SIGNATURE_ALERT",
              severity = EventSeverity.CRITICAL.name,
              details = "Assinatura digital inválida detectada: $reason.",
              txBytes = badApp.txBytes,
              rxBytes = badApp.rxBytes,
            )
          )
          if (currentSettings.pushAlertsEnabled) {
            SecurityNotifier.postSecurityThreatPushAlert(
              context = context,
              alertType = ThreatAlertType.INVALID_SIGNATURE,
              title = "Assinatura Inválida: ${badApp.appName}",
              message = "$reason. Risco avaliado: ${badApp.riskScore}/100.",
              appName = badApp.appName,
              packageName = badApp.packageName,
              sha256Fingerprint = badApp.sha256Fingerprint,
              auditId = badApp.id,
              idOffset = 6000,
            )
          }
        }
      }

    return telemetry.usageAccessGranted
  }

  suspend fun handlePackageInstalledEvent(packageName: String, isUpdate: Boolean) {
    ensureCatalogSeeded()
    val now = System.currentTimeMillis()
    val previousEventTime = recentPackageEvents[packageName]
    if (previousEventTime != null && (now - previousEventTime) < 4_000L) {
      return
    }
    recentPackageEvents[packageName] = now

    if (dao.isAppWhitelisted(packageName)) {
      MonitorServiceState.recordPackageVerified(packageName, "Lista Branca (Ignorado)")
      return
    }

    val currentSettings = settings.first()
    val previousSig = dao.getLatestInstalledAuditForPackage(packageName)?.sha256Fingerprint
    val catalog = dao.getActiveThreatCatalog()
    val audit =
      behaviorEngine.auditSingleInstalledPackage(
        packageName = packageName,
        sourceType = "PACKAGE_ADDED",
        settings = currentSettings,
        catalogThreats = catalog,
        trustLookup = { sha -> getTrustStatus(sha) },
        previousSigLookup = { previousSig },
      ) ?: return

    dao.deleteInstalledAuditsForPackage(packageName)
    val insertedId = dao.insertAudit(audit)
    dao.insertScanHistory(
      audit.toScanHistory(auditId = insertedId, scanSource = "TEMPO_REAL")
    )

    val verdict = SecurityVerdict.valueOf(audit.verdict)
    MonitorServiceState.recordPackageVerified(audit.appName, verdict.labelPt)
    SecurityNotifier.updateMonitorNotification(
      context = context,
      bodyText =
        "Última verificação: ${audit.appName} • ${verdict.labelPt} (${audit.riskScore}/100)",
    )
    val eventType =
      when {
        audit.signatureMismatch -> "SIGNATURE_CHANGE"
        verdict == SecurityVerdict.BLOQUEADO -> "INSTALL_BLOCKED"
        audit.installerSource != "com.android.vending" && !audit.isSystemApp -> "SIDELOAD_DETECTED"
        else -> "PACKAGE_VERIFIED"
      }
    val severity =
      when {
        audit.signatureMismatch || verdict == SecurityVerdict.BLOQUEADO -> EventSeverity.CRITICAL
        verdict == SecurityVerdict.SUSPEITO -> EventSeverity.WARNING
        else -> EventSeverity.INFO
      }

    val actionLabel = if (isUpdate) "Atualização" else "Instalação"
    dao.insertBehaviorEvent(
      BehaviorEventEntity(
        packageName = audit.packageName,
        appName = audit.appName,
        eventType = eventType,
        severity = severity.name,
        details =
          "$actionLabel detectada (${audit.installerSource}) • Score ${audit.riskScore}/100 • SHA-256 ${audit.sha256Fingerprint.take(17)}...",
        txBytes = audit.txBytes,
        rxBytes = audit.rxBytes,
      )
    )

    val hasInvalidSignature =
      audit.signatureMismatch ||
        audit.isExpiredCert ||
        audit.isDebugCert ||
        audit.sha256Fingerprint == "SEM ASSINATURA"

    if (currentSettings.pushAlertsEnabled && (severity != EventSeverity.INFO || hasInvalidSignature)) {
      val alertType =
        resolveThreatAlertType(audit, defaultForBlocked = ThreatAlertType.MALWARE_DETECTED)
      val title =
        when {
          hasInvalidSignature -> "Assinatura Inválida Detectada: ${audit.appName}"
          verdict == SecurityVerdict.BLOQUEADO -> "Ameaça Bloqueada: ${audit.appName}"
          else -> "Alerta em Tempo Real: ${audit.appName}"
        }
      val reasonHint =
        audit.findingsSummary.lineSequence().firstOrNull()?.removePrefix("• ")?.trim().orEmpty()
      SecurityNotifier.postSecurityThreatPushAlert(
        context = context,
        alertType = alertType,
        title = title,
        message =
          "$actionLabel classificada como ${verdict.labelPt} (${audit.riskScore}/100). $reasonHint",
        appName = audit.appName,
        packageName = audit.packageName,
        sha256Fingerprint = audit.sha256Fingerprint,
        auditId = insertedId,
        idOffset = 5000,
      )
    }
  }

  suspend fun handlePackageRemovedEvent(packageName: String) {
    dao.deleteInstalledAuditsForPackage(packageName)
  }

  suspend fun setCertificateTrust(
    sha256: String,
    label: String,
    packageNameHint: String,
    status: TrustStatus,
    notes: String = "",
  ) {
    if (sha256.isBlank() || sha256 == "SEM ASSINATURA") return
    if (status == TrustStatus.NEUTRAL) {
      dao.deleteCertificateRule(sha256)
    } else {
      dao.upsertCertificateRule(
        CertificateRuleEntity(
          sha256Fingerprint = sha256,
          label = label,
          trustStatus = status.name,
          packageNameHint = packageNameHint,
          notes = notes,
        )
      )
    }
    scanAllInstalledApps()
  }

  suspend fun blockThreatFromNotification(
    packageName: String,
    appName: String,
    sha256Fingerprint: String,
  ) {
    val cleanPkg = packageName.trim()
    val cleanSha = sha256Fingerprint.trim()
    val displayLabel = appName.ifBlank { cleanPkg }.ifBlank { "Aplicativo bloqueado" }

    if (cleanPkg.isNotBlank()) {
      dao.removeWhitelistedApp(cleanPkg)
      dao.upsertThreatCatalogEntry(
        ThreatCatalogEntity(
          threatKey = "USER_BLOCK_${cleanPkg.replace(Regex("[^A-Za-z0-9._-]"), "_")}",
          name = "Bloqueado pelo usuário: $displayLabel",
          threatType = ThreatType.ARQUIVO_MALICIOSO.name,
          severityScore = 95,
          packagePatterns = cleanPkg,
          sha256Signatures =
            if (cleanSha.isNotBlank() && cleanSha != "SEM ASSINATURA") cleanSha else "",
          permissionSignature = "",
          indicatorTokens = "",
          descriptionPt = "Aplicativo bloqueado diretamente pela ação rápida na notificação.",
          recommendationPt = "Mantenha bloqueado ou desinstale o aplicativo do aparelho.",
          sourceReference = "Bloqueio Rápido via Notificação",
        )
      )
      dao.markAuditBlockedFromNotification(
        packageName = cleanPkg,
        summary = "• Bloqueado imediatamente pelo usuário através da notificação de alerta.",
      )
    }

    if (cleanSha.isNotBlank() && cleanSha != "SEM ASSINATURA") {
      dao.upsertCertificateRule(
        CertificateRuleEntity(
          sha256Fingerprint = cleanSha,
          label = displayLabel,
          trustStatus = TrustStatus.BLOCKED.name,
          packageNameHint = cleanPkg,
          notes = "Bloqueado diretamente a partir do alerta local do Sentinela",
        )
      )
    }

    dao.insertBehaviorEvent(
      BehaviorEventEntity(
        packageName = cleanPkg.ifBlank { "com.aistudio.sentinela" },
        appName = displayLabel,
        eventType = "THREAT_BLOCKED_NOTIFICATION",
        severity = EventSeverity.CRITICAL.name,
        details = "Ação rápida aplicada pela notificação: $displayLabel bloqueado pelo usuário.",
        txBytes = 0L,
        rxBytes = 0L,
      )
    )
  }

  suspend fun deleteAudit(id: Long) {
    dao.deleteAuditById(id)
  }

  suspend fun clearBehaviorEvents() {
    dao.clearBehaviorEvents()
  }

  suspend fun deleteScanHistoryEntry(id: Long) {
    dao.deleteScanHistoryById(id)
  }

  suspend fun clearScanHistory() {
    dao.clearScanHistory()
  }

  suspend fun addToWhitelist(
    packageName: String,
    appName: String,
    sha256Fingerprint: String,
    reason: String = "Marcado pelo usuário como aplicativo confiável",
  ) {
    dao.upsertWhitelistedApp(
      WhitelistedAppEntity(
        packageName = packageName,
        appName = appName,
        sha256Fingerprint = sha256Fingerprint,
        reason = reason,
      )
    )
    dao.markAuditSafeForWhitelist(
      packageName = packageName,
      summary = "• Aplicativo na Lista Branca — ignorado pelo scanner em tempo real",
    )
  }

  suspend fun removeFromWhitelist(packageName: String) {
    dao.removeWhitelistedApp(packageName)
    ensureCatalogSeeded()
    val currentSettings = settings.first()
    val catalog = dao.getActiveThreatCatalog()
    val audit =
      behaviorEngine.auditSingleInstalledPackage(
        packageName = packageName,
        sourceType = "INSTALLED_APP",
        settings = currentSettings,
        catalogThreats = catalog,
        trustLookup = { sha -> getTrustStatus(sha) },
        previousSigLookup = { null },
      )
    if (audit != null) {
      dao.deleteInstalledAuditsForPackage(packageName)
      dao.insertAudit(audit)
    }
  }

  suspend fun clearWhitelist() {
    dao.clearWhitelist()
    scanAllInstalledApps()
  }

  suspend fun setRealTimeMonitor(enabled: Boolean) = preferences.setRealTimeMonitor(enabled)
  suspend fun setPushAlertsEnabled(enabled: Boolean) = preferences.setPushAlertsEnabled(enabled)
  suspend fun setBlockDebugCerts(enabled: Boolean) = preferences.setBlockDebugCerts(enabled)
  suspend fun setBlockSignatureMismatch(enabled: Boolean) = preferences.setBlockSignatureMismatch(enabled)
  suspend fun setBlockHighRiskPermissions(enabled: Boolean) = preferences.setBlockHighRiskPermissions(enabled)
  suspend fun setStrictSideloadBlocking(enabled: Boolean) = preferences.setStrictSideloadBlocking(enabled)

  suspend fun restoreFromCloudBackup(
    whitelist: List<WhitelistedAppEntity>,
    rules: List<CertificateRuleEntity>,
    history: List<ScanHistoryEntity>,
  ): Int {
    var restoredCount = 0
    whitelist.forEach { item ->
      dao.upsertWhitelistedApp(item)
      dao.markAuditSafeForWhitelist(
        packageName = item.packageName,
        summary = "• Aplicativo na Lista Branca (restaurado da nuvem)",
      )
      restoredCount++
    }
    rules.forEach { rule ->
      dao.upsertCertificateRule(rule)
      restoredCount++
    }
    val existingHistoryKeys =
      dao.observeScanHistory().first().map { "${it.packageName}|${it.scannedAt}" }.toHashSet()
    val newHistoryEntries =
      history.filter { "${it.packageName}|${it.scannedAt}" !in existingHistoryKeys }
    if (newHistoryEntries.isNotEmpty()) {
      dao.insertScanHistoryBatch(newHistoryEntries)
      restoredCount += newHistoryEntries.size
    }
    return restoredCount
  }

  fun sendTestPushAlert(): Boolean {
    val posted =
      SecurityNotifier.postSecurityThreatPushAlert(
        context = context,
        alertType = ThreatAlertType.MALWARE_DETECTED,
        title = "Teste de Alerta Imediato: Sentinela",
        message =
          "Simulação de ameaça detectada. Em ocorrências reais você pode usar Desinstalar, Bloquear ou Inspecionar direto na notificação.",
        appName = "Sentinela Verificação",
        packageName = null,
        sha256Fingerprint = "TEST:AA:BB:CC:DD:EE:FF:00:11:22:33",
        auditId = -1L,
        idOffset = 7000,
      )
    return posted != null
  }

  private suspend fun notifyDetectedThreatsForAudits(
    audits: List<ScanAuditEntity>,
    whitelisted: Set<String>,
  ) {
    val alertCutoff = System.currentTimeMillis() - 6 * 60 * 60 * 1000L
    val candidates =
      audits.filter { audit ->
        !audit.isSystemApp &&
          audit.packageName !in whitelisted &&
          (audit.verdict == SecurityVerdict.BLOQUEADO.name ||
            (audit.verdict == SecurityVerdict.SUSPEITO.name &&
              (audit.hasAccessibilityAbuse ||
                audit.hasPermissionAbuse ||
                audit.hasHiddenCommunication ||
                audit.matchedThreatName.isNotBlank())))
      }

    for (audit in candidates) {
      val recent = dao.findRecentEvent(audit.packageName, "THREAT_PUSH_ALERTED", alertCutoff)
      if (recent != null) continue

      val alertType =
        resolveThreatAlertType(audit, defaultForBlocked = ThreatAlertType.MALWARE_DETECTED)
      val firstFinding =
        audit.findingsSummary.lineSequence().firstOrNull()?.removePrefix("• ")?.trim().orEmpty()
      val title =
        when (alertType) {
          ThreatAlertType.ACCESSIBILITY_ABUSE -> "Alerta de Acessibilidade: ${audit.appName}"
          ThreatAlertType.PERMISSION_ABUSE -> "Abuso de Permissões: ${audit.appName}"
          ThreatAlertType.HIDDEN_COMMUNICATION -> "Comunicação Oculta: ${audit.appName}"
          ThreatAlertType.INVALID_SIGNATURE -> "Assinatura Inválida: ${audit.appName}"
          ThreatAlertType.MALWARE_DETECTED ->
            if (audit.matchedThreatName.isNotBlank()) {
              "Ameaça Detectada: ${audit.appName}"
            } else {
              "App de Alto Risco: ${audit.appName}"
            }
          else -> "Alerta de Segurança: ${audit.appName}"
        }
      val originTag = if (audit.isPlayStoreApp) "Play Store" else "Fonte externa"
      val detailText =
        buildString {
          append("$originTag • Risco ${audit.riskScore}/100. ")
          if (audit.matchedThreatName.isNotBlank()) {
            append("Correspondência: ${audit.matchedThreatName}. ")
          }
          if (firstFinding.isNotBlank()) {
            append(firstFinding)
          }
        }

      val postedId =
        SecurityNotifier.postSecurityThreatPushAlert(
          context = context,
          alertType = alertType,
          title = title,
          message = detailText.trim(),
          appName = audit.appName,
          packageName = audit.packageName,
          sha256Fingerprint = audit.sha256Fingerprint,
          auditId = audit.id,
          idOffset = 8000,
        )

      if (postedId != null) {
        dao.insertBehaviorEvent(
          BehaviorEventEntity(
            packageName = audit.packageName,
            appName = audit.appName,
            eventType = "THREAT_PUSH_ALERTED",
            severity =
              if (audit.verdict == SecurityVerdict.BLOQUEADO.name) EventSeverity.CRITICAL.name
              else EventSeverity.WARNING.name,
            details = "Notificação imediata emitida: ${detailText.trim()}",
            txBytes = audit.txBytes,
            rxBytes = audit.rxBytes,
          )
        )
      }
    }
  }

  private fun resolveThreatAlertType(
    audit: ScanAuditEntity,
    defaultForBlocked: ThreatAlertType,
  ): ThreatAlertType {
    val hasInvalidSig =
      audit.signatureMismatch ||
        audit.isExpiredCert ||
        audit.isDebugCert ||
        audit.sha256Fingerprint == "SEM ASSINATURA"
    return when {
      hasInvalidSig -> ThreatAlertType.INVALID_SIGNATURE
      audit.hasAccessibilityAbuse -> ThreatAlertType.ACCESSIBILITY_ABUSE
      audit.hasHiddenCommunication -> ThreatAlertType.HIDDEN_COMMUNICATION
      audit.hasPermissionAbuse -> ThreatAlertType.PERMISSION_ABUSE
      audit.matchedThreatName.isNotBlank() -> ThreatAlertType.MALWARE_DETECTED
      audit.verdict == SecurityVerdict.BLOQUEADO.name -> defaultForBlocked
      else -> ThreatAlertType.SUSPICIOUS_BEHAVIOR
    }
  }

  private suspend fun getTrustStatus(sha256: String): TrustStatus {
    val rule = dao.getCertificateRule(sha256) ?: return TrustStatus.NEUTRAL
    return runCatching { TrustStatus.valueOf(rule.trustStatus) }.getOrDefault(TrustStatus.NEUTRAL)
  }

  private fun ScanAuditEntity.toScanHistory(
    auditId: Long,
    scanSource: String,
  ): ScanHistoryEntity {
    return ScanHistoryEntity(
      auditId = auditId,
      packageName = packageName,
      appName = appName,
      versionName = versionName,
      scanSource = scanSource,
      verdict = verdict,
      riskScore = riskScore,
      sha256Fingerprint = sha256Fingerprint,
      findingsSummary = findingsSummary,
      scannedAt = scannedAt,
    )
  }
}
