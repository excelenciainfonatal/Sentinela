package com.example.data.remote

import androidx.annotation.Keep
import androidx.compose.runtime.Immutable
import com.google.firebase.Timestamp
import com.google.firebase.firestore.DocumentId
import com.google.firebase.firestore.IgnoreExtraProperties
import com.google.firebase.firestore.ServerTimestamp
import java.security.MessageDigest

@Immutable
@Keep
@IgnoreExtraProperties
data class UserSecurityProfile(
  @DocumentId val id: String = "",
  val userId: String = "",
  val displayName: String = "",
  val email: String = "",
  val autoSyncEnabled: Boolean = true,
  val totalSyncedScans: Long = 0L,
  @ServerTimestamp val createdAt: Timestamp? = null,
  @ServerTimestamp val updatedAt: Timestamp? = null,
)

@Immutable
@Keep
@IgnoreExtraProperties
data class CloudWhitelistedApp(
  @DocumentId val id: String = "",
  val packageName: String = "",
  val appName: String = "",
  val sha256Fingerprint: String = "",
  val reason: String = "",
  val addedAtMillis: Long = 0L,
  @ServerTimestamp val createdAt: Timestamp? = null,
  @ServerTimestamp val updatedAt: Timestamp? = null,
)

@Immutable
@Keep
@IgnoreExtraProperties
data class CloudCertificateRule(
  @DocumentId val id: String = "",
  val sha256Fingerprint: String = "",
  val label: String = "",
  val trustStatus: String = "TRUSTED",
  val packageNameHint: String = "",
  val notes: String = "",
  @ServerTimestamp val createdAt: Timestamp? = null,
  @ServerTimestamp val updatedAt: Timestamp? = null,
)

@Immutable
@Keep
@IgnoreExtraProperties
data class CloudScanRecord(
  @DocumentId val id: String = "",
  val packageName: String = "",
  val appName: String = "",
  val versionName: String = "",
  val scanSource: String = "VARREDURA_DISPOSITIVO",
  val verdict: String = "SEGURO",
  val riskScore: Long = 0L,
  val sha256Fingerprint: String = "",
  val findingsSummary: String = "",
  val scannedAtMillis: Long = 0L,
  @ServerTimestamp val createdAt: Timestamp? = null,
  @ServerTimestamp val updatedAt: Timestamp? = null,
)

data class CloudSyncSummary(
  val whitelistSynced: Int = 0,
  val certificateRulesSynced: Int = 0,
  val scanHistorySynced: Int = 0,
)

data class CloudBackupSnapshot(
  val whitelist: List<CloudWhitelistedApp> = emptyList(),
  val certificateRules: List<CloudCertificateRule> = emptyList(),
  val scanHistory: List<CloudScanRecord> = emptyList(),
)

object CloudDocIds {
  private fun shortHash(raw: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
    return digest.take(5).joinToString("") { "%02x".format(it) }
  }

  private fun sanitizeSegment(raw: String, maxLen: Int): String {
    return raw.replace(Regex("[^a-zA-Z0-9_-]"), "_").take(maxLen).ifBlank { "item" }
  }

  fun whitelistDocId(packageName: String): String {
    val base = sanitizeSegment(packageName, 110)
    return "${base}_${shortHash(packageName)}".take(128)
  }

  fun certRuleDocId(sha256: String): String {
    val hexOnly = sha256.filter { it.isLetterOrDigit() }.take(115)
    return if (hexOnly.isNotEmpty()) hexOnly else "cert_${shortHash(sha256)}"
  }

  fun scanHistoryDocId(packageName: String, scannedAtMillis: Long): String {
    val base = sanitizeSegment(packageName, 80)
    val hash = shortHash("$packageName|$scannedAtMillis")
    return "${base}_${scannedAtMillis}_$hash".take(128)
  }
}
