package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.ScanAuditEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.SentinelaDao
import com.example.data.local.SentinelaDatabase
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.ThreatCatalogSeeder
import com.example.data.local.ThreatClassification
import com.example.data.local.ThreatType
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
class ThreatCatalogDatabaseTest {

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
  fun catalogSeederPopulatesAllFourMalwareCategories() = runTest {
    val defaults = ThreatCatalogSeeder.defaultCatalogEntries()
    dao.upsertThreatCatalog(defaults)

    val stored = dao.observeThreatCatalog().first()
    assertEquals(defaults.size, stored.size)
    assertTrue(stored.any { it.threatType == ThreatType.VIRUS.name })
    assertTrue(stored.any { it.threatType == ThreatType.SPYWARE.name })
    assertTrue(stored.any { it.threatType == ThreatType.ADWARE.name })
    assertTrue(stored.any { it.threatType == ThreatType.ARQUIVO_MALICIOSO.name })
  }

  @Test
  fun auditStatsDifferentiatePlayStoreVsExternalAndDeepSignals() = runTest {
    dao.insertAudit(
      ScanAuditEntity(
        packageName = "com.playstore.flashlight.spy",
        appName = "Lanterna Spy",
        versionName = "1.0",
        sourceType = "INSTALLED_APP",
        verdict = SecurityVerdict.BLOQUEADO.name,
        riskScore = 85,
        sha256Fingerprint = "AA:BB",
        sha1Fingerprint = "11",
        signerSubject = "CN=Dev",
        signerIssuer = "CN=Dev",
        keyAlgorithmInfo = "RSA 2048",
        validUntilMillis = 9999999999999L,
        isDebugCert = false,
        isExpiredCert = false,
        isSelfSigned = true,
        signatureMismatch = false,
        installerSource = "com.android.vending",
        targetSdk = 34,
        isDebuggableApp = false,
        isSystemApp = false,
        txBytes = 3_000_000L,
        rxBytes = 100_000L,
        findingsSummary = "• Abuso de permissão: Lanterna lendo SMS",
        dangerousPermissions = "android.permission.READ_SMS",
        threatCategory = ThreatClassification.SPYWARE.name,
        isPlayStoreApp = true,
        hasAccessibilityAbuse = false,
        hasPermissionAbuse = true,
        hasHiddenCommunication = true,
      )
    )

    dao.insertAudit(
      ScanAuditEntity(
        packageName = "com.external.bank.trojan",
        appName = "Pix Atualizado",
        versionName = "2.0",
        sourceType = "INSTALLED_APP",
        verdict = SecurityVerdict.BLOQUEADO.name,
        riskScore = 95,
        sha256Fingerprint = "CC:DD",
        sha1Fingerprint = "22",
        signerSubject = "CN=Unknown",
        signerIssuer = "CN=Unknown",
        keyAlgorithmInfo = "RSA 2048",
        validUntilMillis = 9999999999999L,
        isDebugCert = false,
        isExpiredCert = false,
        isSelfSigned = true,
        signatureMismatch = false,
        installerSource = "Sideload / Instalador Manual",
        targetSdk = 33,
        isDebuggableApp = false,
        isSystemApp = false,
        txBytes = 0L,
        rxBytes = 0L,
        findingsSummary = "• Acessibilidade ATIVA",
        dangerousPermissions = "android.permission.BIND_ACCESSIBILITY_SERVICE",
        threatCategory = ThreatClassification.VIRUS_TROJAN.name,
        isPlayStoreApp = false,
        hasAccessibilityAbuse = true,
        hasPermissionAbuse = false,
        hasHiddenCommunication = false,
        matchedThreatName = "PixPirate / Brasileirão Trojan",
      )
    )

    val stats = dao.observeAuditStats().first()
    assertEquals(2, stats.totalAppsAudited)
    assertEquals(1, stats.playStoreFlaggedCount)
    assertEquals(1, stats.externalFlaggedCount)
    assertEquals(1, stats.accessibilityRiskCount)
    assertEquals(1, stats.permissionAbuseCount)
    assertEquals(1, stats.hiddenCommCount)
  }

  @Test
  fun customCatalogEntriesCanBeInsertedAndDeleted() = runTest {
    val custom =
      ThreatCatalogEntity(
        threatKey = "CUSTOM_TEST_1",
        name = "Custom Malware Test",
        threatType = ThreatType.ADWARE.name,
        severityScore = 70,
        packagePatterns = "com.custom.adware",
        sha256Signatures = "",
        permissionSignature = "",
        indicatorTokens = "",
        descriptionPt = "Teste",
        recommendationPt = "Remover",
      )
    dao.upsertThreatCatalogEntry(custom)
    assertEquals(1, dao.countThreatCatalog())

    dao.deleteThreatCatalogEntry("CUSTOM_TEST_1")
    assertEquals(0, dao.countThreatCatalog())
  }
}
