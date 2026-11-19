package com.example.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface SentinelaDao {

  // --- Scan Audits ---
  @Query("SELECT * FROM scan_audits ORDER BY scannedAt DESC")
  fun observeAllAudits(): Flow<List<ScanAuditEntity>>

  @Query("SELECT * FROM scan_audits WHERE sourceType = 'APK_PRE_INSTALL' ORDER BY scannedAt DESC")
  fun observeApkGatekeeperAudits(): Flow<List<ScanAuditEntity>>

  @Query("SELECT * FROM scan_audits WHERE sourceType != 'APK_PRE_INSTALL' ORDER BY riskScore DESC, appName ASC")
  fun observeInstalledAppAudits(): Flow<List<ScanAuditEntity>>

  @Query("SELECT * FROM scan_audits WHERE id = :id LIMIT 1")
  fun observeAuditById(id: Long): Flow<ScanAuditEntity?>

  @Query(
    """
    SELECT * FROM scan_audits
    WHERE id = :id OR (:packageName != '' AND packageName = :packageName)
    ORDER BY CASE WHEN id = :id THEN 0 ELSE 1 END, scannedAt DESC
    LIMIT 1
    """
  )
  fun observeAuditWithFallback(id: Long, packageName: String): Flow<ScanAuditEntity?>

  @Query("SELECT * FROM scan_audits WHERE packageName = :packageName AND sourceType != 'APK_PRE_INSTALL' ORDER BY scannedAt DESC LIMIT 1")
  suspend fun getLatestInstalledAuditForPackage(packageName: String): ScanAuditEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertAudit(audit: ScanAuditEntity): Long

  @Query("DELETE FROM scan_audits WHERE sourceType != 'APK_PRE_INSTALL' AND packageName = :packageName")
  suspend fun deleteInstalledAuditsForPackage(packageName: String)

  @Query("DELETE FROM scan_audits WHERE id = :id")
  suspend fun deleteAuditById(id: Long)

  // --- Certificate Rules ---
  @Query("SELECT * FROM certificate_rules ORDER BY updatedAt DESC")
  fun observeAllCertificateRules(): Flow<List<CertificateRuleEntity>>

  @Query("SELECT * FROM certificate_rules WHERE sha256Fingerprint = :sha256 LIMIT 1")
  suspend fun getCertificateRule(sha256: String): CertificateRuleEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun upsertCertificateRule(rule: CertificateRuleEntity)

  @Query("DELETE FROM certificate_rules WHERE sha256Fingerprint = :sha256")
  suspend fun deleteCertificateRule(sha256: String)

  // --- Behavior Events ---
  @Query("SELECT * FROM behavior_events ORDER BY timestamp DESC LIMIT 150")
  fun observeBehaviorEvents(): Flow<List<BehaviorEventEntity>>

  @Query("SELECT * FROM behavior_events WHERE packageName = :packageName AND eventType = :eventType AND timestamp > :sinceTimestamp LIMIT 1")
  suspend fun findRecentEvent(packageName: String, eventType: String, sinceTimestamp: Long): BehaviorEventEntity?

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertBehaviorEvent(event: BehaviorEventEntity): Long

  @Query("DELETE FROM behavior_events")
  suspend fun clearBehaviorEvents()

  // --- Scan History ---
  @Query("SELECT * FROM scan_history ORDER BY scannedAt DESC, id DESC LIMIT 500")
  fun observeScanHistory(): Flow<List<ScanHistoryEntity>>

  @Query("SELECT * FROM scan_history WHERE packageName = :packageName ORDER BY scannedAt DESC, id DESC")
  fun observeHistoryForPackage(packageName: String): Flow<List<ScanHistoryEntity>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertScanHistory(entry: ScanHistoryEntity): Long

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insertScanHistoryBatch(entries: List<ScanHistoryEntity>)

  @Query("DELETE FROM scan_history WHERE id = :id")
  suspend fun deleteScanHistoryById(id: Long)

  @Query("DELETE FROM scan_history")
  suspend fun clearScanHistory()

  @Transaction
  suspend fun replaceInstalledAuditsAndRecordHistory(
    audits: List<ScanAuditEntity>,
    scanSource: String,
  ) {
    val historyBatch = ArrayList<ScanHistoryEntity>(audits.size)
    for (audit in audits) {
      deleteInstalledAuditsForPackage(audit.packageName)
      val insertedId = insertAudit(audit)
      historyBatch +=
        ScanHistoryEntity(
          auditId = insertedId,
          packageName = audit.packageName,
          appName = audit.appName,
          versionName = audit.versionName,
          scanSource = scanSource,
          verdict = audit.verdict,
          riskScore = audit.riskScore,
          sha256Fingerprint = audit.sha256Fingerprint,
          findingsSummary = audit.findingsSummary,
          scannedAt = audit.scannedAt,
        )
    }
    if (historyBatch.isNotEmpty()) {
      insertScanHistoryBatch(historyBatch)
    }
  }

  // --- Room Statistical Aggregations for Dashboard ---
  @Query(
    """
    SELECT
      COALESCE(SUM(CASE WHEN sourceType != 'APK_PRE_INSTALL' THEN 1 ELSE 0 END), 0) AS totalAppsAudited,
      COALESCE(SUM(CASE WHEN sourceType = 'APK_PRE_INSTALL' THEN 1 ELSE 0 END), 0) AS totalApkInspected,
      COALESCE(SUM(CASE WHEN verdict = 'BLOQUEADO' THEN 1 ELSE 0 END), 0) AS blockedCount,
      COALESCE(SUM(CASE WHEN verdict = 'SUSPEITO' THEN 1 ELSE 0 END), 0) AS suspiciousCount,
      COALESCE(SUM(CASE WHEN verdict = 'SEGURO' THEN 1 ELSE 0 END), 0) AS safeCount,
      COALESCE(SUM(CASE WHEN isDebugCert = 1 OR isExpiredCert = 1 OR signatureMismatch = 1 OR sha256Fingerprint = 'SEM ASSINATURA' THEN 1 ELSE 0 END), 0) AS invalidSignatureCount
    FROM scan_audits
    """
  )
  fun observeAuditStats(): Flow<AuditStatsProjection>

  @Query(
    """
    SELECT
      COUNT(*) AS totalScans,
      COALESCE(SUM(CASE WHEN verdict IN ('BLOQUEADO', 'SUSPEITO') THEN 1 ELSE 0 END), 0) AS historicalThreatsFound,
      COALESCE(MAX(scannedAt), 0) AS lastScanTimestamp
    FROM scan_history
    """
  )
  fun observeHistoryStats(): Flow<HistoryStatsProjection>

  @Query(
    """
    SELECT
      COALESCE(SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS criticalCount,
      COALESCE(SUM(CASE WHEN severity = 'WARNING' THEN 1 ELSE 0 END), 0) AS warningCount
    FROM behavior_events
    """
  )
  fun observeBehaviorStats(): Flow<BehaviorStatsProjection>

  // --- Whitelisted Apps (Lista Branca) ---
  @Query("SELECT * FROM whitelisted_apps ORDER BY addedAt DESC")
  fun observeWhitelistedApps(): Flow<List<WhitelistedAppEntity>>

  @Query("SELECT packageName FROM whitelisted_apps")
  fun observeWhitelistedPackageNames(): Flow<List<String>>

  @Query("SELECT EXISTS(SELECT 1 FROM whitelisted_apps WHERE packageName = :packageName)")
  suspend fun isAppWhitelisted(packageName: String): Boolean

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun upsertWhitelistedApp(app: WhitelistedAppEntity)

  @Query("DELETE FROM whitelisted_apps WHERE packageName = :packageName")
  suspend fun removeWhitelistedApp(packageName: String)

  @Query("DELETE FROM whitelisted_apps")
  suspend fun clearWhitelist()

  @Query(
    "UPDATE scan_audits SET verdict = 'SEGURO', riskScore = 0, findingsSummary = :summary WHERE packageName = :packageName AND sourceType != 'APK_PRE_INSTALL'"
  )
  suspend fun markAuditSafeForWhitelist(packageName: String, summary: String)
}

data class AuditStatsProjection(
  val totalAppsAudited: Int = 0,
  val totalApkInspected: Int = 0,
  val blockedCount: Int = 0,
  val suspiciousCount: Int = 0,
  val safeCount: Int = 0,
  val invalidSignatureCount: Int = 0,
)

data class HistoryStatsProjection(
  val totalScans: Int = 0,
  val historicalThreatsFound: Int = 0,
  val lastScanTimestamp: Long = 0L,
)

data class BehaviorStatsProjection(
  val criticalCount: Int = 0,
  val warningCount: Int = 0,
)
