package com.example.ui

import android.util.Log
import androidx.compose.runtime.Immutable
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.SecurityRepository
import com.example.data.local.CertificateRuleEntity
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.data.local.WhitelistedAppEntity
import com.example.data.remote.CloudCertificateRule
import com.example.data.remote.CloudScanRecord
import com.example.data.remote.CloudSecurityRepository
import com.example.data.remote.CloudWhitelistedApp
import com.example.data.remote.UserSecurityProfile
import com.google.firebase.firestore.FirebaseFirestoreException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

sealed interface CloudStreamState<out T> {
  data object Loading : CloudStreamState<Nothing>

  @Immutable data class Success<T>(val data: T) : CloudStreamState<T>

  @Immutable data class Error(val message: String) : CloudStreamState<Nothing>
}

@Immutable
data class CloudSyncUiState(
  val userId: String = "",
  val displayName: String = "",
  val email: String = "",
  val autoSyncEnabled: Boolean = true,
  val isSyncing: Boolean = false,
  val cloudWhitelistCount: Int = 0,
  val cloudCertRulesCount: Int = 0,
  val cloudHistoryCount: Int = 0,
  val totalSyncedScans: Long = 0L,
  val statusMessage: String? = null,
  val errorMessage: String? = null,
)

private data class CloudSnapshotBundle(
  val profile: CloudStreamState<UserSecurityProfile?>,
  val whitelist: CloudStreamState<List<CloudWhitelistedApp>>,
  val certRules: CloudStreamState<List<CloudCertificateRule>>,
  val history: CloudStreamState<List<CloudScanRecord>>,
)

private data class SyncControlBundle(
  val isSyncing: Boolean,
  val statusMessage: String?,
  val errorMessage: String?,
)

class CloudSyncViewModel(
  private val cloudRepo: CloudSecurityRepository,
  private val localRepo: SecurityRepository,
  private val currentUserId: String,
  private val userDisplayName: String,
  private val userEmail: String,
) : ViewModel() {

  private val _isSyncing = MutableStateFlow(false)
  private val _statusMessage = MutableStateFlow<String?>(null)
  private val _errorMessage = MutableStateFlow<String?>(null)

  private val profileFlow: StateFlow<CloudStreamState<UserSecurityProfile?>> =
    cloudRepo
      .observeUserProfile(currentUserId)
      .map<UserSecurityProfile?, CloudStreamState<UserSecurityProfile?>> { CloudStreamState.Success(it) }
      .catch { error ->
        val firestoreError = unwrapFirestoreErrorOrThrowCancellation(error)
        Log.w(TAG, "Error observing cloud profile", firestoreError ?: error)
        emit(
          CloudStreamState.Error(
            (firestoreError ?: error).localizedMessage ?: "Falha ao carregar perfil na nuvem."
          )
        )
      }
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS),
        initialValue = CloudStreamState.Loading,
      )

  private val whitelistFlow: StateFlow<CloudStreamState<List<CloudWhitelistedApp>>> =
    cloudRepo
      .observeCloudWhitelist(currentUserId)
      .map<List<CloudWhitelistedApp>, CloudStreamState<List<CloudWhitelistedApp>>> {
        CloudStreamState.Success(it)
      }
      .catch { error ->
        val firestoreError = unwrapFirestoreErrorOrThrowCancellation(error)
        Log.w(TAG, "Error observing cloud whitelist", firestoreError ?: error)
        emit(
          CloudStreamState.Error(
            (firestoreError ?: error).localizedMessage ?: "Falha ao observar Lista Branca na nuvem."
          )
        )
      }
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS),
        initialValue = CloudStreamState.Loading,
      )

  private val certRulesFlow: StateFlow<CloudStreamState<List<CloudCertificateRule>>> =
    cloudRepo
      .observeCloudCertificateRules(currentUserId)
      .map<List<CloudCertificateRule>, CloudStreamState<List<CloudCertificateRule>>> {
        CloudStreamState.Success(it)
      }
      .catch { error ->
        val firestoreError = unwrapFirestoreErrorOrThrowCancellation(error)
        Log.w(TAG, "Error observing cloud certificate rules", firestoreError ?: error)
        emit(
          CloudStreamState.Error(
            (firestoreError ?: error).localizedMessage ?: "Falha ao observar regras X.509 na nuvem."
          )
        )
      }
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS),
        initialValue = CloudStreamState.Loading,
      )

  private val historyFlow: StateFlow<CloudStreamState<List<CloudScanRecord>>> =
    cloudRepo
      .observeCloudScanHistory(currentUserId)
      .map<List<CloudScanRecord>, CloudStreamState<List<CloudScanRecord>>> {
        CloudStreamState.Success(it)
      }
      .catch { error ->
        val firestoreError = unwrapFirestoreErrorOrThrowCancellation(error)
        Log.w(TAG, "Error observing cloud scan history", firestoreError ?: error)
        emit(
          CloudStreamState.Error(
            (firestoreError ?: error).localizedMessage ?: "Falha ao observar histórico na nuvem."
          )
        )
      }
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS),
        initialValue = CloudStreamState.Loading,
      )

  private val cloudSnapshotFlow =
    combine(profileFlow, whitelistFlow, certRulesFlow, historyFlow) { p, w, c, h ->
      CloudSnapshotBundle(p, w, c, h)
    }

  private val controlFlow =
    combine(_isSyncing, _statusMessage, _errorMessage) { syncing, status, err ->
      SyncControlBundle(syncing, status, err)
    }

  val uiState: StateFlow<CloudSyncUiState> =
    combine(cloudSnapshotFlow, controlFlow) { cloud, ctrl ->
        val profile = (cloud.profile as? CloudStreamState.Success)?.data
        val wl = (cloud.whitelist as? CloudStreamState.Success)?.data.orEmpty()
        val rules = (cloud.certRules as? CloudStreamState.Success)?.data.orEmpty()
        val history = (cloud.history as? CloudStreamState.Success)?.data.orEmpty()

        val streamError =
          (cloud.profile as? CloudStreamState.Error)?.message
            ?: (cloud.whitelist as? CloudStreamState.Error)?.message
            ?: (cloud.certRules as? CloudStreamState.Error)?.message
            ?: (cloud.history as? CloudStreamState.Error)?.message

        CloudSyncUiState(
          userId = currentUserId,
          displayName = profile?.displayName?.ifBlank { userDisplayName } ?: userDisplayName,
          email = profile?.email?.ifBlank { userEmail } ?: userEmail,
          autoSyncEnabled = profile?.autoSyncEnabled ?: true,
          isSyncing = ctrl.isSyncing,
          cloudWhitelistCount = wl.size,
          cloudCertRulesCount = rules.size,
          cloudHistoryCount = history.size,
          totalSyncedScans = profile?.totalSyncedScans ?: history.size.toLong(),
          statusMessage = ctrl.statusMessage,
          errorMessage = ctrl.errorMessage ?: streamError,
        )
      }
      .distinctUntilChanged()
      .stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(STOP_TIMEOUT_MILLIS),
        initialValue =
          CloudSyncUiState(
            userId = currentUserId,
            displayName = userDisplayName.ifBlank { "Usuário Sentinela" },
            email = userEmail,
          ),
      )

  init {
    viewModelScope.launch {
      cloudRepo
        .ensureUserProfile(
          userId = currentUserId,
          displayName = userDisplayName,
          email = userEmail,
        )
        .onFailure { err ->
          _errorMessage.value =
            err.localizedMessage ?: "Não foi possível inicializar seu perfil na nuvem."
        }
    }
  }

  fun syncLocalToCloud(onResult: ((String) -> Unit)? = null) {
    if (_isSyncing.value) return
    viewModelScope.launch {
      _isSyncing.value = true
      _errorMessage.value = null
      try {
        val wl = localRepo.whitelistedApps.first()
        val rules = localRepo.certificateRules.first()
        val history = localRepo.scanHistory.first()
        val result = cloudRepo.syncAllLocalToCloud(currentUserId, wl, rules, history)
        result
          .onSuccess { summary ->
            val msg =
              "Nuvem atualizada: ${summary.whitelistSynced} lista branca, ${summary.certificateRulesSynced} chaves X.509, ${summary.scanHistorySynced} scans."
            _statusMessage.value = msg
            onResult?.invoke(msg)
          }
          .onFailure { err ->
            val msg = err.localizedMessage ?: "Erro ao sincronizar backup com o Firestore."
            _errorMessage.value = msg
            onResult?.invoke(msg)
          }
      } finally {
        _isSyncing.value = false
      }
    }
  }

  fun restoreFromCloudToRoom(onResult: ((String) -> Unit)? = null) {
    if (_isSyncing.value) return
    viewModelScope.launch {
      _isSyncing.value = true
      _errorMessage.value = null
      try {
        val snapResult = cloudRepo.fetchCloudSnapshotForRestore(currentUserId)
        snapResult
          .onSuccess { backup ->
            val wlEntities =
              backup.whitelist.map { item ->
                WhitelistedAppEntity(
                  packageName = item.packageName,
                  appName = item.appName,
                  sha256Fingerprint = item.sha256Fingerprint,
                  reason = item.reason.ifBlank { "Restaurado do backup na nuvem" },
                  addedAt = item.addedAtMillis.takeIf { it > 0L } ?: System.currentTimeMillis(),
                )
              }
            val ruleEntities =
              backup.certificateRules.map { rule ->
                val status =
                  enumValues<TrustStatus>().firstOrNull { it.name == rule.trustStatus }
                    ?: TrustStatus.TRUSTED
                CertificateRuleEntity(
                  sha256Fingerprint = rule.sha256Fingerprint,
                  label = rule.label,
                  trustStatus = status.name,
                  packageNameHint = rule.packageNameHint,
                  notes = rule.notes,
                )
              }
            val historyEntities =
              backup.scanHistory.map { rec ->
                val verdict =
                  enumValues<SecurityVerdict>().firstOrNull { it.name == rec.verdict }
                    ?: SecurityVerdict.SUSPEITO
                ScanHistoryEntity(
                  auditId = null,
                  packageName = rec.packageName,
                  appName = rec.appName,
                  versionName = rec.versionName,
                  scanSource = rec.scanSource,
                  verdict = verdict.name,
                  riskScore = rec.riskScore.toInt().coerceIn(0, 100),
                  sha256Fingerprint = rec.sha256Fingerprint,
                  findingsSummary = rec.findingsSummary,
                  scannedAt = rec.scannedAtMillis.takeIf { it > 0L } ?: System.currentTimeMillis(),
                )
              }
            val restored = localRepo.restoreFromCloudBackup(wlEntities, ruleEntities, historyEntities)
            val msg =
              if (restored > 0) "Restaurados $restored registro(s) da nuvem para o Room."
              else "Backup em nuvem já está em dia com o dispositivo."
            _statusMessage.value = msg
            onResult?.invoke(msg)
          }
          .onFailure { err ->
            val msg = err.localizedMessage ?: "Falha ao restaurar backup da nuvem."
            _errorMessage.value = msg
            onResult?.invoke(msg)
          }
      } finally {
        _isSyncing.value = false
      }
    }
  }

  fun toggleAutoSync(enabled: Boolean) {
    viewModelScope.launch {
      _errorMessage.value = null
      cloudRepo.setAutoSyncEnabled(currentUserId, enabled).onFailure { err ->
        _errorMessage.value = err.localizedMessage ?: "Falha ao atualizar preferência na nuvem."
      }
    }
  }

  fun mirrorWhitelistAdd(packageName: String, appName: String, sha256: String) {
    if (!uiState.value.autoSyncEnabled) return
    viewModelScope.launch {
      cloudRepo
        .upsertWhitelistedApp(
          userId = currentUserId,
          entity =
            WhitelistedAppEntity(
              packageName = packageName,
              appName = appName,
              sha256Fingerprint = sha256,
            ),
        )
        .onFailure { err -> _errorMessage.value = err.localizedMessage }
    }
  }

  fun mirrorWhitelistRemove(packageName: String) {
    if (!uiState.value.autoSyncEnabled) return
    viewModelScope.launch {
      cloudRepo.removeWhitelistedApp(currentUserId, packageName).onFailure { err ->
        _errorMessage.value = err.localizedMessage
      }
    }
  }

  fun mirrorCertificateRule(sha256: String, label: String, packageHint: String, status: TrustStatus) {
    if (!uiState.value.autoSyncEnabled) return
    if (sha256.isBlank() || sha256 == "SEM ASSINATURA") return
    viewModelScope.launch {
      if (status == TrustStatus.NEUTRAL) {
        cloudRepo.removeCertificateRule(currentUserId, sha256)
      } else {
        cloudRepo.upsertCertificateRule(
          userId = currentUserId,
          rule =
            CertificateRuleEntity(
              sha256Fingerprint = sha256,
              label = label,
              trustStatus = status.name,
              packageNameHint = packageHint,
              notes =
                if (status == TrustStatus.TRUSTED) "Aprovado manualmente pelo usuário"
                else "Bloqueado manualmente — instalações impedidas",
            ),
        )
      }
    }
  }

  fun clearMessages() {
    _statusMessage.value = null
    _errorMessage.value = null
  }

  private fun unwrapFirestoreErrorOrThrowCancellation(error: Throwable): FirebaseFirestoreException? {
    val firestoreError =
      generateSequence(error) { it.cause }
        .filterIsInstance<FirebaseFirestoreException>()
        .firstOrNull()
    if (firestoreError == null && error is CancellationException) throw error
    return firestoreError
  }

  private companion object {
    const val TAG = "CloudSyncVM"
    const val STOP_TIMEOUT_MILLIS = 5000L
  }
}
