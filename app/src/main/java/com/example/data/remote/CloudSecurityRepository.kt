package com.example.data.remote

import android.content.Context
import com.example.R
import com.example.data.local.CertificateRuleEntity
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.data.local.WhitelistedAppEntity
import com.google.firebase.Firebase
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.auth
import com.google.firebase.firestore.DocumentSnapshot
import com.google.firebase.firestore.FieldValue
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Query
import com.google.firebase.firestore.snapshots
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.tasks.await

class CloudSecurityRepository(
  private val db: FirebaseFirestore,
  private val auth: FirebaseAuth = Firebase.auth,
) {

  constructor(context: Context) : this(
    db =
      FirebaseFirestore.getInstance(
        context.applicationContext.getString(R.string.firestore_database_id)
      )
  )

  private fun requireUserId(expectedUserId: String): String {
    val uid =
      auth.currentUser?.uid?.takeIf { it.isNotBlank() }
        ?: error("Sessão expirada. Entre com sua conta Google para acessar a nuvem.")
    check(uid == expectedUserId) { "Usuário autenticado alterado; escrita recusada." }
    return uid
  }

  private fun userDoc(userId: String) = db.collection("users").document(userId)

  private fun whitelistCol(userId: String) = userDoc(userId).collection("whitelist")

  private fun certRulesCol(userId: String) = userDoc(userId).collection("certificateRules")

  private fun scanHistoryCol(userId: String) = userDoc(userId).collection("scanHistory")

  fun observeUserProfile(userId: String): Flow<UserSecurityProfile?> =
    userDoc(userId)
      .snapshots()
      .map { snapshot ->
        snapshot.toObject(
          UserSecurityProfile::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      }

  fun observeCloudWhitelist(userId: String): Flow<List<CloudWhitelistedApp>> =
    whitelistCol(userId)
      .orderBy("addedAtMillis", Query.Direction.DESCENDING)
      .snapshots()
      .map { snapshot ->
        snapshot.toObjects(
          CloudWhitelistedApp::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      }

  fun observeCloudCertificateRules(userId: String): Flow<List<CloudCertificateRule>> =
    certRulesCol(userId)
      .snapshots()
      .map { snapshot ->
        snapshot.toObjects(
          CloudCertificateRule::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      }

  fun observeCloudScanHistory(userId: String, limitCount: Long = 50L): Flow<List<CloudScanRecord>> =
    scanHistoryCol(userId)
      .orderBy("scannedAtMillis", Query.Direction.DESCENDING)
      .limit(limitCount)
      .snapshots()
      .map { snapshot ->
        snapshot.toObjects(
          CloudScanRecord::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      }

  suspend fun ensureUserProfile(
    userId: String,
    displayName: String,
    email: String,
  ): Result<Unit> {
    val path = "users/$userId"
    return try {
      requireUserId(userId)
      val safeName = displayName.trim().ifBlank { "Usuário Sentinela" }.take(120)
      val safeEmail = email.trim().take(254)
      val docRef = userDoc(userId)
      val existing = docRef.get().await()
      if (!existing.exists()) {
        val createPayload =
          buildMap<String, Any> {
            put("userId", userId)
            put("displayName", safeName)
            if (safeEmail.isNotBlank()) put("email", safeEmail)
            put("autoSyncEnabled", true)
            put("totalSyncedScans", 0L)
            put("createdAt", FieldValue.serverTimestamp())
            put("updatedAt", FieldValue.serverTimestamp())
          }
        docRef.set(createPayload).await()
      } else {
        val updatePayload =
          buildMap<String, Any> {
            put("displayName", safeName)
            if (safeEmail.isNotBlank()) put("email", safeEmail)
            put("updatedAt", FieldValue.serverTimestamp())
          }
        docRef.update(updatePayload).await()
      }
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.WRITE, path)
      Result.failure(e)
    }
  }

  suspend fun setAutoSyncEnabled(userId: String, enabled: Boolean): Result<Unit> {
    val path = "users/$userId"
    return try {
      requireUserId(userId)
      userDoc(userId)
        .update(
          mapOf(
            "autoSyncEnabled" to enabled,
            "updatedAt" to FieldValue.serverTimestamp(),
          )
        )
        .await()
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.UPDATE, path)
      Result.failure(e)
    }
  }

  suspend fun upsertWhitelistedApp(userId: String, entity: WhitelistedAppEntity): Result<Unit> {
    val docId = CloudDocIds.whitelistDocId(entity.packageName)
    val path = "users/$userId/whitelist/$docId"
    return try {
      requireUserId(userId)
      val pkg = entity.packageName.trim().take(200)
      require(pkg.isNotEmpty()) { "Nome do pacote inválido." }
      val appName = entity.appName.trim().ifBlank { pkg }.take(120)
      val sha = entity.sha256Fingerprint.trim().take(128)
      val reason = entity.reason.trim().take(240)
      val addedAt = entity.addedAt.coerceAtLeast(0L)

      val docRef = whitelistCol(userId).document(docId)
      val snapshot = docRef.get().await()
      if (!snapshot.exists()) {
        docRef
          .set(
            mapOf(
              "packageName" to pkg,
              "appName" to appName,
              "sha256Fingerprint" to sha,
              "reason" to reason,
              "addedAtMillis" to addedAt,
              "createdAt" to FieldValue.serverTimestamp(),
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      } else {
        docRef
          .update(
            mapOf(
              "appName" to appName,
              "sha256Fingerprint" to sha,
              "reason" to reason,
              "addedAtMillis" to addedAt,
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      }
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.WRITE, path)
      Result.failure(e)
    }
  }

  suspend fun removeWhitelistedApp(userId: String, packageName: String): Result<Unit> {
    val docId = CloudDocIds.whitelistDocId(packageName)
    val path = "users/$userId/whitelist/$docId"
    return try {
      requireUserId(userId)
      whitelistCol(userId).document(docId).delete().await()
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.DELETE, path)
      Result.failure(e)
    }
  }

  suspend fun upsertCertificateRule(userId: String, rule: CertificateRuleEntity): Result<Unit> {
    val docId = CloudDocIds.certRuleDocId(rule.sha256Fingerprint)
    val path = "users/$userId/certificateRules/$docId"
    return try {
      requireUserId(userId)
      val sha = rule.sha256Fingerprint.trim().take(128)
      require(sha.isNotEmpty() && sha != "SEM ASSINATURA") { "Assinatura SHA-256 inválida." }
      val normalizedStatus =
        when (rule.trustStatus) {
          TrustStatus.TRUSTED.name,
          TrustStatus.BLOCKED.name -> rule.trustStatus
          else -> error("Apenas regras TRUSTED ou BLOCKED podem ser salvas na nuvem.")
        }
      val label = rule.label.trim().ifBlank { rule.packageNameHint.ifBlank { "Certificado" } }.take(120)
      val pkgHint = rule.packageNameHint.trim().take(200)
      val notes = rule.notes.trim().take(240)

      val docRef = certRulesCol(userId).document(docId)
      val snapshot = docRef.get().await()
      if (!snapshot.exists()) {
        docRef
          .set(
            mapOf(
              "sha256Fingerprint" to sha,
              "label" to label,
              "trustStatus" to normalizedStatus,
              "packageNameHint" to pkgHint,
              "notes" to notes,
              "createdAt" to FieldValue.serverTimestamp(),
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      } else {
        docRef
          .update(
            mapOf(
              "label" to label,
              "trustStatus" to normalizedStatus,
              "packageNameHint" to pkgHint,
              "notes" to notes,
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      }
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.WRITE, path)
      Result.failure(e)
    }
  }

  suspend fun removeCertificateRule(userId: String, sha256: String): Result<Unit> {
    val docId = CloudDocIds.certRuleDocId(sha256)
    val path = "users/$userId/certificateRules/$docId"
    return try {
      requireUserId(userId)
      certRulesCol(userId).document(docId).delete().await()
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.DELETE, path)
      Result.failure(e)
    }
  }

  suspend fun syncAllLocalToCloud(
    userId: String,
    whitelist: List<WhitelistedAppEntity>,
    rules: List<CertificateRuleEntity>,
    history: List<ScanHistoryEntity>,
  ): Result<CloudSyncSummary> {
    val basePath = "users/$userId"
    return try {
      requireUserId(userId)
      var wlCount = 0
      whitelist.forEach { item ->
        upsertWhitelistedApp(userId, item).getOrThrow()
        wlCount++
      }

      var rulesCount = 0
      rules
        .filter { it.trustStatus == TrustStatus.TRUSTED.name || it.trustStatus == TrustStatus.BLOCKED.name }
        .forEach { rule ->
          upsertCertificateRule(userId, rule).getOrThrow()
          rulesCount++
        }

      val historySlice = history.take(30)
      var historyCount = 0
      historySlice.forEach { record ->
        upsertScanHistoryRecord(userId, record).getOrThrow()
        historyCount++
      }

      val totalSynced = historyCount.toLong().coerceIn(0L, 1_000_000L)
      val profileRef = userDoc(userId)
      val profileSnap = profileRef.get().await()
      if (profileSnap.exists()) {
        val currentTotal = (profileSnap.getLong("totalSyncedScans") ?: 0L).coerceAtLeast(totalSynced)
        profileRef
          .update(
            mapOf(
              "totalSyncedScans" to currentTotal.coerceAtMost(1_000_000L),
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      }

      Result.success(
        CloudSyncSummary(
          whitelistSynced = wlCount,
          certificateRulesSynced = rulesCount,
          scanHistorySynced = historyCount,
        )
      )
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.WRITE, basePath)
      Result.failure(e)
    }
  }

  private suspend fun upsertScanHistoryRecord(
    userId: String,
    record: ScanHistoryEntity,
  ): Result<Unit> {
    val docId = CloudDocIds.scanHistoryDocId(record.packageName, record.scannedAt)
    val path = "users/$userId/scanHistory/$docId"
    return try {
      requireUserId(userId)
      val pkg = record.packageName.trim().take(200)
      require(pkg.isNotEmpty()) { "Pacote inválido no histórico." }
      val appName = record.appName.trim().ifBlank { pkg }.take(120)
      val version = record.versionName.trim().take(64)
      val source =
        when (record.scanSource) {
          "GATEKEEPER_APK",
          "VARREDURA_DISPOSITIVO",
          "TEMPO_REAL" -> record.scanSource
          else -> "VARREDURA_DISPOSITIVO"
        }
      val verdict =
        enumValues<SecurityVerdict>().firstOrNull { it.name == record.verdict }?.name
          ?: SecurityVerdict.SUSPEITO.name
      val risk = record.riskScore.coerceIn(0, 100).toLong()
      val sha = record.sha256Fingerprint.trim().take(128)
      val summary = record.findingsSummary.trim().take(1000)
      val scannedAt = record.scannedAt.coerceAtLeast(0L)

      val docRef = scanHistoryCol(userId).document(docId)
      val existing = docRef.get().await()
      if (!existing.exists()) {
        docRef
          .set(
            mapOf(
              "packageName" to pkg,
              "appName" to appName,
              "versionName" to version,
              "scanSource" to source,
              "verdict" to verdict,
              "riskScore" to risk,
              "sha256Fingerprint" to sha,
              "findingsSummary" to summary,
              "scannedAtMillis" to scannedAt,
              "createdAt" to FieldValue.serverTimestamp(),
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      } else {
        docRef
          .update(
            mapOf(
              "appName" to appName,
              "versionName" to version,
              "scanSource" to source,
              "verdict" to verdict,
              "riskScore" to risk,
              "sha256Fingerprint" to sha,
              "findingsSummary" to summary,
              "scannedAtMillis" to scannedAt,
              "updatedAt" to FieldValue.serverTimestamp(),
            )
          )
          .await()
      }
      Result.success(Unit)
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.WRITE, path)
      Result.failure(e)
    }
  }

  suspend fun fetchCloudSnapshotForRestore(userId: String): Result<CloudBackupSnapshot> {
    val path = "users/$userId"
    return try {
      requireUserId(userId)
      val wlSnap =
        whitelistCol(userId)
          .orderBy("addedAtMillis", Query.Direction.DESCENDING)
          .get()
          .await()
      val rulesSnap = certRulesCol(userId).get().await()
      val historySnap =
        scanHistoryCol(userId)
          .orderBy("scannedAtMillis", Query.Direction.DESCENDING)
          .limit(50L)
          .get()
          .await()

      val wl =
        wlSnap.toObjects(
          CloudWhitelistedApp::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      val rules =
        rulesSnap.toObjects(
          CloudCertificateRule::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      val history =
        historySnap.toObjects(
          CloudScanRecord::class.java,
          DocumentSnapshot.ServerTimestampBehavior.ESTIMATE,
        )
      Result.success(CloudBackupSnapshot(wl, rules, history))
    } catch (e: CancellationException) {
      throw e
    } catch (e: Exception) {
      handleFirestoreError(e, OperationType.LIST, path)
      Result.failure(e)
    }
  }
}
