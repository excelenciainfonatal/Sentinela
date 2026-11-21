package com.example.data.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.securityDataStore: DataStore<Preferences> by preferencesDataStore(name = "sentinela_prefs")

data class SecuritySettings(
  val realTimeMonitorEnabled: Boolean = true,
  val pushAlertsEnabled: Boolean = true,
  val blockDebugCerts: Boolean = true,
  val blockSignatureMismatch: Boolean = true,
  val blockHighRiskPermissions: Boolean = true,
  val strictSideloadBlocking: Boolean = false,
  val autoAntivirusUpdatesEnabled: Boolean = true,
  val lastAntivirusUpdateAt: Long = 0L,
  val lastAntivirusUpdateVersion: String = "v1.0 • Base Sentinela",
  val lastAntivirusUpdateStatus: String = "Aguardando primeira sincronização",
  val lastAntivirusUpdateSource: String = "Servidor Google OSV (api.osv.dev)",
  val lastAntivirusNewDefinitionsCount: Int = 0,
  val lastAntivirusProviderVerified: Boolean = false,
  val lastAntivirusUpdateHadError: Boolean = false,
)

class SecurityPreferences(private val context: Context) {

  private object Keys {
    val REAL_TIME_MONITOR = booleanPreferencesKey("real_time_monitor")
    val PUSH_ALERTS_ENABLED = booleanPreferencesKey("push_alerts_enabled")
    val BLOCK_DEBUG_CERTS = booleanPreferencesKey("block_debug_certs")
    val BLOCK_SIG_MISMATCH = booleanPreferencesKey("block_sig_mismatch")
    val BLOCK_HIGH_RISK_PERMS = booleanPreferencesKey("block_high_risk_perms")
    val STRICT_SIDELOAD = booleanPreferencesKey("strict_sideload")
    val AUTO_AV_UPDATES = booleanPreferencesKey("auto_av_updates")
    val LAST_AV_UPDATE_AT = longPreferencesKey("last_av_update_at")
    val LAST_AV_UPDATE_VERSION = stringPreferencesKey("last_av_update_version")
    val LAST_AV_UPDATE_STATUS = stringPreferencesKey("last_av_update_status")
    val LAST_AV_UPDATE_SOURCE = stringPreferencesKey("last_av_update_source")
    val LAST_AV_NEW_DEFS = intPreferencesKey("last_av_new_defs")
    val LAST_AV_PROVIDER_VERIFIED = booleanPreferencesKey("last_av_provider_verified")
    val LAST_AV_HAD_ERROR = booleanPreferencesKey("last_av_had_error")
  }

  val settingsFlow: Flow<SecuritySettings> =
    context.securityDataStore.data.map { prefs ->
      SecuritySettings(
        realTimeMonitorEnabled = prefs[Keys.REAL_TIME_MONITOR] ?: true,
        pushAlertsEnabled = prefs[Keys.PUSH_ALERTS_ENABLED] ?: true,
        blockDebugCerts = prefs[Keys.BLOCK_DEBUG_CERTS] ?: true,
        blockSignatureMismatch = prefs[Keys.BLOCK_SIG_MISMATCH] ?: true,
        blockHighRiskPermissions = prefs[Keys.BLOCK_HIGH_RISK_PERMS] ?: true,
        strictSideloadBlocking = prefs[Keys.STRICT_SIDELOAD] ?: false,
        autoAntivirusUpdatesEnabled = prefs[Keys.AUTO_AV_UPDATES] ?: true,
        lastAntivirusUpdateAt = prefs[Keys.LAST_AV_UPDATE_AT] ?: 0L,
        lastAntivirusUpdateVersion =
          prefs[Keys.LAST_AV_UPDATE_VERSION] ?: "v1.0 • Base Sentinela",
        lastAntivirusUpdateStatus =
          prefs[Keys.LAST_AV_UPDATE_STATUS] ?: "Aguardando primeira sincronização",
        lastAntivirusUpdateSource =
          prefs[Keys.LAST_AV_UPDATE_SOURCE] ?: "Servidor Google OSV (api.osv.dev)",
        lastAntivirusNewDefinitionsCount = prefs[Keys.LAST_AV_NEW_DEFS] ?: 0,
        lastAntivirusProviderVerified = prefs[Keys.LAST_AV_PROVIDER_VERIFIED] ?: false,
        lastAntivirusUpdateHadError = prefs[Keys.LAST_AV_HAD_ERROR] ?: false,
      )
    }

  suspend fun setRealTimeMonitor(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.REAL_TIME_MONITOR] = enabled }
  }

  suspend fun setPushAlertsEnabled(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.PUSH_ALERTS_ENABLED] = enabled }
  }

  suspend fun setBlockDebugCerts(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.BLOCK_DEBUG_CERTS] = enabled }
  }

  suspend fun setBlockSignatureMismatch(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.BLOCK_SIG_MISMATCH] = enabled }
  }

  suspend fun setBlockHighRiskPermissions(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.BLOCK_HIGH_RISK_PERMS] = enabled }
  }

  suspend fun setStrictSideloadBlocking(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.STRICT_SIDELOAD] = enabled }
  }

  suspend fun setAutoAntivirusUpdatesEnabled(enabled: Boolean) {
    context.securityDataStore.edit { it[Keys.AUTO_AV_UPDATES] = enabled }
  }

  suspend fun recordAntivirusUpdateSuccess(
    updatedAt: Long,
    versionLabel: String,
    statusMessage: String,
    sourceName: String,
    newDefinitionsCount: Int,
    providerVerified: Boolean,
  ) {
    context.securityDataStore.edit {
      it[Keys.LAST_AV_UPDATE_AT] = updatedAt
      it[Keys.LAST_AV_UPDATE_VERSION] = versionLabel
      it[Keys.LAST_AV_UPDATE_STATUS] = statusMessage
      it[Keys.LAST_AV_UPDATE_SOURCE] = sourceName
      it[Keys.LAST_AV_NEW_DEFS] = newDefinitionsCount
      it[Keys.LAST_AV_PROVIDER_VERIFIED] = providerVerified
      it[Keys.LAST_AV_HAD_ERROR] = false
    }
  }

  suspend fun recordAntivirusUpdateFailure(
    statusMessage: String,
    providerVerified: Boolean,
  ) {
    context.securityDataStore.edit {
      it[Keys.LAST_AV_UPDATE_STATUS] = statusMessage
      it[Keys.LAST_AV_PROVIDER_VERIFIED] = providerVerified
      it[Keys.LAST_AV_HAD_ERROR] = true
    }
  }
}
