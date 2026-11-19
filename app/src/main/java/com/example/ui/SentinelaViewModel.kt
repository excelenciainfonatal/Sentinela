package com.example.ui

import android.Manifest
import android.app.Application
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.compose.runtime.Immutable
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.SentinelaApplication
import com.example.data.ThreatStatsSummary
import com.example.data.local.BehaviorEventEntity
import com.example.data.local.CertificateRuleEntity
import com.example.data.local.ScanAuditEntity
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.data.local.WhitelistedAppEntity
import com.example.data.preferences.SecuritySettings
import com.example.security.ApkInspectionReport
import com.example.service.MonitorServiceState
import com.example.service.SecurityMonitorService
import com.example.service.ServiceMonitorTelemetry
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class BehaviorFilter(val labelPt: String) {
  TODOS("Todos"),
  ALTO_RISCO("Risco Alto"),
  SUSPEITOS("Atenção"),
  SEGUROS("Seguros"),
  SIDELOAD("Fora da Loja"),
  LISTA_BRANCA("Confiáveis"),
}

enum class SignatureFilter(val labelPt: String) {
  TODOS("Todas"),
  CONFIAVEIS("Confiáveis"),
  BLOQUEADOS("Bloqueadas"),
  ALERTAS("Com Alerta"),
}

enum class HistoryFilter(val labelPt: String) {
  TODOS("Todos"),
  BLOQUEADOS("Risco Alto"),
  SUSPEITOS("Atenção"),
  SEGUROS("Seguros"),
}

@Immutable
data class CertificateSummary(
  val sha256: String,
  val sha1: String,
  val subject: String,
  val issuer: String,
  val keyAlgorithmInfo: String,
  val validUntilMillis: Long,
  val isDebugCert: Boolean,
  val isExpiredCert: Boolean,
  val isSelfSigned: Boolean,
  val trustStatus: TrustStatus,
  val appNames: List<String>,
  val primaryPackageHint: String,
)

sealed interface AuditDetailUiState {
  data object Loading : AuditDetailUiState

  @Immutable data class Ready(val audit: ScanAuditEntity) : AuditDetailUiState

  data object NotFound : AuditDetailUiState
}

@Immutable
data class SentinelaUiState(
  val isScanningDevice: Boolean = false,
  val isInspectingApk: Boolean = false,
  val latestApkReport: ApkInspectionReport? = null,
  val apkErrorMessage: String? = null,
  val usageAccessGranted: Boolean = false,
  val notificationPermissionGranted: Boolean = true,
  val installedApps: List<ScanAuditEntity> = emptyList(),
  val apkAudits: List<ScanAuditEntity> = emptyList(),
  val behaviorEvents: List<BehaviorEventEntity> = emptyList(),
  val scanHistory: List<ScanHistoryEntity> = emptyList(),
  val whitelistedApps: List<WhitelistedAppEntity> = emptyList(),
  val whitelistedPackageNames: Set<String> = emptySet(),
  val threatStats: ThreatStatsSummary = ThreatStatsSummary(),
  val certificateSummaries: List<CertificateSummary> = emptyList(),
  val settings: SecuritySettings = SecuritySettings(),
  val behaviorFilter: BehaviorFilter = BehaviorFilter.TODOS,
  val behaviorSearchQuery: String = "",
  val signatureFilter: SignatureFilter = SignatureFilter.TODOS,
  val historyFilter: HistoryFilter = HistoryFilter.TODOS,
  val historySearchQuery: String = "",
  val serviceTelemetry: ServiceMonitorTelemetry = ServiceMonitorTelemetry(),
)

class SentinelaViewModel(application: Application) : AndroidViewModel(application) {

  private val repository = (application as SentinelaApplication).repository

  private val _isScanningDevice = MutableStateFlow(false)
  private val _isInspectingApk = MutableStateFlow(false)
  private val _latestApkReport = MutableStateFlow<ApkInspectionReport?>(null)
  private val _apkErrorMessage = MutableStateFlow<String?>(null)
  private val _usageAccessGranted = MutableStateFlow(false)
  private val _notificationPermissionGranted = MutableStateFlow(true)
  private val _behaviorFilter = MutableStateFlow(BehaviorFilter.TODOS)
  private val _behaviorSearchQuery = MutableStateFlow("")
  private val _signatureFilter = MutableStateFlow(SignatureFilter.TODOS)
  private val _historyFilter = MutableStateFlow(HistoryFilter.TODOS)
  private val _historySearchQuery = MutableStateFlow("")
  private val auditDetailFlows = ConcurrentHashMap<String, StateFlow<AuditDetailUiState>>()

  private val baseDataFlow =
    combine(
      repository.installedAppAudits,
      repository.apkGatekeeperAudits,
      repository.behaviorEvents,
      repository.certificateRules,
      repository.settings,
    ) { installed, apks, events, rules, settings ->
      BaseDataBundle(installed, apks, events, rules, settings)
    }

  private val filterStateFlow =
    combine(
      _behaviorFilter,
      _behaviorSearchQuery,
      _signatureFilter,
      _historyFilter,
      _historySearchQuery,
    ) { bFilter, query, sFilter, hFilter, hQuery ->
      FilterBundle(bFilter, query, sFilter, hFilter, hQuery)
    }

  private val statusStateFlow =
    combine(
      _isScanningDevice,
      _isInspectingApk,
      _latestApkReport,
      _apkErrorMessage,
      _usageAccessGranted,
    ) { scanning, inspecting, report, error, usageGranted ->
      StatusBundle(scanning, inspecting, report, error, usageGranted)
    }

  private val systemStateFlow =
    combine(
      _notificationPermissionGranted,
      MonitorServiceState.state,
      repository.threatStatsSummary,
      repository.whitelistedApps,
    ) { notifGranted, telemetry, stats, whitelist ->
      SystemBundle(notifGranted, telemetry, stats, whitelist)
    }

  val uiState: StateFlow<SentinelaUiState> =
    combine(
        baseDataFlow,
        repository.scanHistory,
        filterStateFlow,
        statusStateFlow,
        systemStateFlow,
      ) { base, history, filters, status, sysState ->
        val summaries = buildCertificateSummaries(base.installed + base.apks, base.rules)
        SentinelaUiState(
          isScanningDevice = status.isScanningDevice,
          isInspectingApk = status.isInspectingApk,
          latestApkReport = status.latestApkReport,
          apkErrorMessage = status.apkErrorMessage,
          usageAccessGranted = status.usageAccessGranted,
          notificationPermissionGranted = sysState.notificationPermissionGranted,
          installedApps = base.installed,
          apkAudits = base.apks,
          behaviorEvents = base.events,
          scanHistory = history,
          whitelistedApps = sysState.whitelistedApps,
          whitelistedPackageNames = sysState.whitelistedApps.map { it.packageName }.toSet(),
          threatStats = sysState.threatStats,
          certificateSummaries = summaries,
          settings = base.settings,
          behaviorFilter = filters.behaviorFilter,
          behaviorSearchQuery = filters.behaviorSearchQuery,
          signatureFilter = filters.signatureFilter,
          historyFilter = filters.historyFilter,
          historySearchQuery = filters.historySearchQuery,
          serviceTelemetry = sysState.serviceTelemetry,
        )
      }
      .distinctUntilChanged()
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = SentinelaUiState(),
      )

  init {
    refreshSystemPermissionsStatus()
    viewModelScope.launch {
      val currentSettings = repository.settings.first()
      if (currentSettings.realTimeMonitorEnabled) {
        runCatching { SecurityMonitorService.start(getApplication()) }
      }
      scanDeviceApps()
    }
  }

  fun refreshSystemPermissionsStatus() {
    _usageAccessGranted.value = repository.behaviorEngine.hasUsageStatsPermission()
    _notificationPermissionGranted.value =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ContextCompat.checkSelfPermission(
          getApplication(),
          Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
      } else {
        true
      }
  }

  fun scanDeviceApps(onCompleted: ((Int) -> Unit)? = null) {
    if (_isScanningDevice.value) return
    viewModelScope.launch {
      _isScanningDevice.value = true
      try {
        val count = repository.scanAllInstalledApps()
        refreshSystemPermissionsStatus()
        onCompleted?.invoke(count)
      } finally {
        _isScanningDevice.value = false
      }
    }
  }

  fun inspectApkUri(uri: Uri) {
    viewModelScope.launch {
      _isInspectingApk.value = true
      _apkErrorMessage.value = null
      val result = repository.inspectApkForInstallation(uri)
      result
        .onSuccess { report -> _latestApkReport.value = report }
        .onFailure { err ->
          _apkErrorMessage.value = err.localizedMessage ?: "Falha ao analisar o arquivo APK."
        }
      _isInspectingApk.value = false
    }
  }

  fun clearLatestApkReport() {
    _latestApkReport.value = null
  }

  fun dismissApkError() {
    _apkErrorMessage.value = null
  }

  fun toggleRealTimeMonitor(enabled: Boolean) {
    viewModelScope.launch {
      repository.setRealTimeMonitor(enabled)
      if (enabled) {
        runCatching { SecurityMonitorService.start(getApplication()) }
      } else {
        runCatching { SecurityMonitorService.stop(getApplication()) }
      }
    }
  }

  fun updatePushAlertsEnabled(enabled: Boolean) {
    viewModelScope.launch { repository.setPushAlertsEnabled(enabled) }
  }

  fun sendTestPushAlert(): Boolean = repository.sendTestPushAlert()

  fun updatePolicyDebugCerts(enabled: Boolean) {
    viewModelScope.launch {
      repository.setBlockDebugCerts(enabled)
      repository.scanAllInstalledApps()
    }
  }

  fun updatePolicySigMismatch(enabled: Boolean) {
    viewModelScope.launch {
      repository.setBlockSignatureMismatch(enabled)
      repository.scanAllInstalledApps()
    }
  }

  fun updatePolicyHighRiskPerms(enabled: Boolean) {
    viewModelScope.launch {
      repository.setBlockHighRiskPermissions(enabled)
      repository.scanAllInstalledApps()
    }
  }

  fun updatePolicyStrictSideload(enabled: Boolean) {
    viewModelScope.launch {
      repository.setStrictSideloadBlocking(enabled)
      repository.scanAllInstalledApps()
    }
  }

  fun setBehaviorFilter(filter: BehaviorFilter) {
    _behaviorFilter.value = filter
  }

  fun setBehaviorSearchQuery(query: String) {
    _behaviorSearchQuery.value = query
  }

  fun setSignatureFilter(filter: SignatureFilter) {
    _signatureFilter.value = filter
  }

  fun setHistoryFilter(filter: HistoryFilter) {
    _historyFilter.value = filter
  }

  fun setHistorySearchQuery(query: String) {
    _historySearchQuery.value = query
  }

  fun deleteScanHistoryEntry(id: Long) {
    viewModelScope.launch { repository.deleteScanHistoryEntry(id) }
  }

  fun clearScanHistory() {
    viewModelScope.launch { repository.clearScanHistory() }
  }

  fun trustCertificate(sha256: String, label: String, packageHint: String) {
    viewModelScope.launch {
      repository.setCertificateTrust(
        sha256 = sha256,
        label = label,
        packageNameHint = packageHint,
        status = TrustStatus.TRUSTED,
        notes = "Aprovado manualmente pelo usuário",
      )
    }
  }

  fun blockCertificate(sha256: String, label: String, packageHint: String) {
    viewModelScope.launch {
      repository.setCertificateTrust(
        sha256 = sha256,
        label = label,
        packageNameHint = packageHint,
        status = TrustStatus.BLOCKED,
        notes = "Bloqueado manualmente — instalações com esta assinatura serão impedidas",
      )
    }
  }

  fun resetCertificateRule(sha256: String) {
    viewModelScope.launch {
      repository.setCertificateTrust(
        sha256 = sha256,
        label = "",
        packageNameHint = "",
        status = TrustStatus.NEUTRAL,
      )
    }
  }

  fun deleteAudit(id: Long) {
    viewModelScope.launch { repository.deleteAudit(id) }
  }

  fun clearBehaviorEvents() {
    viewModelScope.launch { repository.clearBehaviorEvents() }
  }

  fun addToWhitelist(
    packageName: String,
    appName: String,
    sha256Fingerprint: String,
    reason: String = "Marcado pelo usuário como aplicativo confiável",
  ) {
    viewModelScope.launch {
      repository.addToWhitelist(
        packageName = packageName,
        appName = appName,
        sha256Fingerprint = sha256Fingerprint,
        reason = reason,
      )
    }
  }

  fun removeFromWhitelist(packageName: String) {
    viewModelScope.launch { repository.removeFromWhitelist(packageName) }
  }

  fun clearWhitelist() {
    viewModelScope.launch { repository.clearWhitelist() }
  }

  fun observeAudit(id: Long): StateFlow<ScanAuditEntity?> {
    return repository
      .observeAuditById(id)
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = null,
      )
  }

  fun observeAuditDetail(id: Long, packageNameHint: String = ""): StateFlow<AuditDetailUiState> {
    val key = "$id|$packageNameHint"
    return auditDetailFlows.getOrPut(key) {
      repository
        .observeAuditWithFallback(id, packageNameHint)
        .map { entity ->
          if (entity != null) AuditDetailUiState.Ready(entity)
          else AuditDetailUiState.NotFound
        }
        .distinctUntilChanged()
        .stateIn(
          scope = viewModelScope,
          started = SharingStarted.WhileSubscribed(5000),
          initialValue = AuditDetailUiState.Loading,
        )
    }
  }

  private fun buildCertificateSummaries(
    audits: List<ScanAuditEntity>,
    rules: List<CertificateRuleEntity>,
  ): List<CertificateSummary> {
    val ruleBySha = rules.associateBy { it.sha256Fingerprint }
    val grouped =
      audits
        .filter { it.sha256Fingerprint.isNotBlank() && it.sha256Fingerprint != "SEM ASSINATURA" }
        .groupBy { it.sha256Fingerprint }

    val summaries =
      grouped.map { (sha, items) ->
        val sample = items.first()
        val rule = ruleBySha[sha]
        val trust =
          rule?.let { runCatching { TrustStatus.valueOf(it.trustStatus) }.getOrNull() }
            ?: TrustStatus.NEUTRAL
        CertificateSummary(
          sha256 = sha,
          sha1 = sample.sha1Fingerprint,
          subject = sample.signerSubject,
          issuer = sample.signerIssuer,
          keyAlgorithmInfo = sample.keyAlgorithmInfo,
          validUntilMillis = sample.validUntilMillis,
          isDebugCert = sample.isDebugCert,
          isExpiredCert = sample.isExpiredCert,
          isSelfSigned = sample.isSelfSigned,
          trustStatus = trust,
          appNames = items.map { it.appName }.distinct(),
          primaryPackageHint = sample.packageName,
        )
      }

    // Also include blocked/trusted rules whose apps are no longer installed
    val existingShas = summaries.map { it.sha256 }.toSet()
    val orphanRules =
      rules
        .filter { it.sha256Fingerprint !in existingShas }
        .map { rule ->
          CertificateSummary(
            sha256 = rule.sha256Fingerprint,
            sha1 = "N/A",
            subject = rule.label,
            issuer = rule.notes.ifBlank { "Regra manual do Sentinela" },
            keyAlgorithmInfo = "Registro armazenado",
            validUntilMillis = 0L,
            isDebugCert = false,
            isExpiredCert = false,
            isSelfSigned = false,
            trustStatus = runCatching { TrustStatus.valueOf(rule.trustStatus) }.getOrDefault(TrustStatus.NEUTRAL),
            appNames = listOf(rule.label),
            primaryPackageHint = rule.packageNameHint,
          )
        }

    return (summaries + orphanRules).sortedWith(
      compareBy<CertificateSummary> {
        when (it.trustStatus) {
          TrustStatus.BLOCKED -> 0
          TrustStatus.NEUTRAL -> if (it.isDebugCert || it.isExpiredCert) 1 else 2
          TrustStatus.TRUSTED -> 3
        }
      }.thenByDescending { it.appNames.size }
    )
  }

  private data class BaseDataBundle(
    val installed: List<ScanAuditEntity>,
    val apks: List<ScanAuditEntity>,
    val events: List<BehaviorEventEntity>,
    val rules: List<CertificateRuleEntity>,
    val settings: SecuritySettings,
  )

  private data class StatusBundle(
    val isScanningDevice: Boolean,
    val isInspectingApk: Boolean,
    val latestApkReport: ApkInspectionReport?,
    val apkErrorMessage: String?,
    val usageAccessGranted: Boolean,
  )

  private data class FilterBundle(
    val behaviorFilter: BehaviorFilter,
    val behaviorSearchQuery: String,
    val signatureFilter: SignatureFilter,
    val historyFilter: HistoryFilter,
    val historySearchQuery: String,
  )

  private data class SystemBundle(
    val notificationPermissionGranted: Boolean,
    val serviceTelemetry: ServiceMonitorTelemetry,
    val threatStats: ThreatStatsSummary,
    val whitelistedApps: List<WhitelistedAppEntity>,
  )
}
