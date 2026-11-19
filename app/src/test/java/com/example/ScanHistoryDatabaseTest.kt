package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.SentinelaDao
import com.example.data.local.SentinelaDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ScanHistoryDatabaseTest {

  private lateinit var db: SentinelaDatabase
  private lateinit var dao: SentinelaDao

  @Before
  fun setUp() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    db = Room.inMemoryDatabaseBuilder(context, SentinelaDatabase::class.java).allowMainThreadQueries().build()
    dao = db.sentinelaDao()
  }

  @After
  fun tearDown() {
    db.close()
  }

  @Test
  fun insertAndObserveScanHistoryOrderedByScanDateDescending() = runTest {
    val olderScan =
      ScanHistoryEntity(
        packageName = "com.example.safe",
        appName = "Safe Utility",
        versionName = "1.2.0",
        scanSource = "VARREDURA_DISPOSITIVO",
        verdict = SecurityVerdict.SEGURO.name,
        riskScore = 5,
        sha256Fingerprint = "AA:BB:CC",
        findingsSummary = "• Assinatura digital íntegra",
        scannedAt = 1_700_000_000_000L,
      )
    val newerBlockedScan =
      ScanHistoryEntity(
        packageName = "com.fake.trojan",
        appName = "Trojan Installer",
        versionName = "2.0.1",
        scanSource = "GATEKEEPER_APK",
        verdict = SecurityVerdict.BLOQUEADO.name,
        riskScore = 95,
        sha256Fingerprint = "FF:EE:DD",
        findingsSummary = "• Divergência de assinatura digital",
        scannedAt = 1_700_000_500_000L,
      )

    dao.insertScanHistory(olderScan)
    dao.insertScanHistory(newerBlockedScan)

    val history = dao.observeScanHistory().first()
    assertEquals(2, history.size)
    assertEquals("com.fake.trojan", history[0].packageName)
    assertEquals(SecurityVerdict.BLOQUEADO.name, history[0].verdict)
    assertEquals(1_700_000_500_000L, history[0].scannedAt)

    assertEquals("com.example.safe", history[1].packageName)
    assertEquals(SecurityVerdict.SEGURO.name, history[1].verdict)
    assertEquals(1_700_000_000_000L, history[1].scannedAt)
  }

  @Test
  fun deleteSingleAndClearHistoryWorks() = runTest {
    val id1 =
      dao.insertScanHistory(
        ScanHistoryEntity(
          packageName = "com.app.one",
          appName = "App One",
          versionName = "1.0",
          scanSource = "TEMPO_REAL",
          verdict = SecurityVerdict.SUSPEITO.name,
          riskScore = 45,
          sha256Fingerprint = "11:22",
          findingsSummary = "• Permissões sensíveis",
          scannedAt = 1000L,
        )
      )
    dao.insertScanHistory(
      ScanHistoryEntity(
        packageName = "com.app.two",
        appName = "App Two",
        versionName = "1.0",
        scanSource = "VARREDURA_DISPOSITIVO",
        verdict = SecurityVerdict.SEGURO.name,
        riskScore = 0,
        sha256Fingerprint = "33:44",
        findingsSummary = "• Seguro",
        scannedAt = 2000L,
      )
    )

    dao.deleteScanHistoryById(id1)
    val afterSingleDelete = dao.observeScanHistory().first()
    assertEquals(1, afterSingleDelete.size)
    assertEquals("com.app.two", afterSingleDelete[0].packageName)

    dao.clearScanHistory()
    val afterClear = dao.observeScanHistory().first()
    assertTrue(afterClear.isEmpty())
  }

  @Test
  fun statisticalSummaryQueriesAggregateThreatsCorrectlyFromRoom() = runTest {
    dao.insertAudit(
      com.example.data.local.ScanAuditEntity(
        packageName = "com.bad.app",
        appName = "Bad App",
        versionName = "1.0",
        sourceType = "INSTALLED_APP",
        verdict = SecurityVerdict.BLOQUEADO.name,
        riskScore = 90,
        sha256Fingerprint = "AA:BB",
        sha1Fingerprint = "11",
        signerSubject = "CN=Android Debug",
        signerIssuer = "CN=Android Debug",
        keyAlgorithmInfo = "RSA 2048",
        validUntilMillis = 0L,
        isDebugCert = true,
        isExpiredCert = false,
        isSelfSigned = true,
        signatureMismatch = false,
        installerSource = "Sideload",
        targetSdk = 33,
        isDebuggableApp = false,
        isSystemApp = false,
        txBytes = 0L,
        rxBytes = 0L,
        findingsSummary = "• Certificado debug",
        dangerousPermissions = "",
        scannedAt = 5000L,
      )
    )
    dao.insertAudit(
      com.example.data.local.ScanAuditEntity(
        packageName = "com.good.app",
        appName = "Good App",
        versionName = "1.0",
        sourceType = "INSTALLED_APP",
        verdict = SecurityVerdict.SEGURO.name,
        riskScore = 0,
        sha256Fingerprint = "CC:DD",
        sha1Fingerprint = "22",
        signerSubject = "CN=Good",
        signerIssuer = "CN=Good",
        keyAlgorithmInfo = "RSA 2048",
        validUntilMillis = 9999999999999L,
        isDebugCert = false,
        isExpiredCert = false,
        isSelfSigned = true,
        signatureMismatch = false,
        installerSource = "com.android.vending",
        targetSdk = 35,
        isDebuggableApp = false,
        isSystemApp = false,
        txBytes = 0L,
        rxBytes = 0L,
        findingsSummary = "• Seguro",
        dangerousPermissions = "",
        scannedAt = 6000L,
      )
    )

    val auditStats = dao.observeAuditStats().first()
    assertEquals(2, auditStats.totalAppsAudited)
    assertEquals(1, auditStats.blockedCount)
    assertEquals(1, auditStats.safeCount)
    assertEquals(1, auditStats.invalidSignatureCount)
  }

  @Test
  fun transactionalReplaceInstalledAuditsRecordsHistoryAtomically() = runTest {
    val batch =
      listOf(
        com.example.data.local.ScanAuditEntity(
          packageName = "com.app.alpha",
          appName = "Alpha",
          versionName = "1.0",
          sourceType = "INSTALLED_APP",
          verdict = SecurityVerdict.SEGURO.name,
          riskScore = 0,
          sha256Fingerprint = "11:11",
          sha1Fingerprint = "11",
          signerSubject = "CN=Alpha",
          signerIssuer = "CN=Alpha",
          keyAlgorithmInfo = "RSA 2048",
          validUntilMillis = 9999999999999L,
          isDebugCert = false,
          isExpiredCert = false,
          isSelfSigned = true,
          signatureMismatch = false,
          installerSource = "com.android.vending",
          targetSdk = 35,
          isDebuggableApp = false,
          isSystemApp = false,
          txBytes = 0L,
          rxBytes = 0L,
          findingsSummary = "• Seguro",
          dangerousPermissions = "",
          scannedAt = 9000L,
        )
      )

    dao.replaceInstalledAuditsAndRecordHistory(batch, scanSource = "VARREDURA_DISPOSITIVO")

    val audits = dao.observeInstalledAppAudits().first()
    val history = dao.observeScanHistory().first()
    assertEquals(1, audits.size)
    assertEquals(1, history.size)
    assertEquals(audits[0].id, history[0].auditId)
    assertEquals("VARREDURA_DISPOSITIVO", history[0].scanSource)
  }

  @Test
  fun observeAuditWithFallbackResolvesLatestAuditWhenOldIdWasReplaced() = runTest {
    val newerId =
      dao.insertAudit(
        com.example.data.local.ScanAuditEntity(
          packageName = "com.example.target",
          appName = "Target App",
          versionName = "2.0",
          sourceType = "INSTALLED_APP",
          verdict = SecurityVerdict.SEGURO.name,
          riskScore = 0,
          sha256Fingerprint = "AA:BB",
          sha1Fingerprint = "11",
          signerSubject = "CN=Target",
          signerIssuer = "CN=Target",
          keyAlgorithmInfo = "RSA 2048",
          validUntilMillis = 9999999999999L,
          isDebugCert = false,
          isExpiredCert = false,
          isSelfSigned = true,
          signatureMismatch = false,
          installerSource = "com.android.vending",
          targetSdk = 35,
          isDebuggableApp = false,
          isSystemApp = false,
          txBytes = 0L,
          rxBytes = 0L,
          findingsSummary = "• Seguro",
          dangerousPermissions = "",
          scannedAt = 12000L,
        )
      )

    // Query with an obsolete auditId (9999L) but valid packageName fallback
    val resolved = dao.observeAuditWithFallback(9999L, "com.example.target").first()
    assertEquals(newerId, resolved?.id)
    assertEquals("2.0", resolved?.versionName)
  }
}
