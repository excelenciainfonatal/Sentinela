package com.example

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.work.Configuration
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.testing.WorkManagerTestInitHelper
import com.example.data.SecurityRepository
import com.example.data.local.SentinelaDao
import com.example.data.local.SentinelaDatabase
import com.example.data.local.ThreatCatalogSeeder
import com.example.data.local.ThreatType
import com.example.data.preferences.SecurityPreferences
import com.example.security.ApkGatekeeperAnalyzer
import com.example.security.BehaviorMonitorEngine
import com.example.security.GoogleHttpResponse
import com.example.security.GoogleThreatFeedUpdater
import com.example.service.AntivirusUpdateScheduler
import java.io.IOException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AntivirusUpdateTest {

  private lateinit var context: Context
  private lateinit var db: SentinelaDatabase
  private lateinit var dao: SentinelaDao
  private lateinit var prefs: SecurityPreferences

  @Before
  fun setUp() {
    context = ApplicationProvider.getApplicationContext()
    db = Room.inMemoryDatabaseBuilder(context, SentinelaDatabase::class.java).allowMainThreadQueries().build()
    dao = db.sentinelaDao()
    prefs = SecurityPreferences(context)
    val config = Configuration.Builder().build()
    WorkManagerTestInitHelper.initializeTestWorkManager(context, config)
  }

  @After
  fun tearDown() {
    db.close()
  }

  @Test
  fun googleOsvJsonUpdatesCatalogAndPersistsSyncTelemetry() = runTest {
    val sampleGoogleOsvJson =
      """
      {
        "vulns": [
          {
            "id": "ASB-A-321456789",
            "summary": "Remote code execution via crafted APK dex accessibility overlay",
            "details": "Privilege escalation and remote code execution in Android framework accessibility handling.",
            "modified": "2026-10-15T12:00:00Z",
            "database_specific": { "severity": "CRITICAL" }
          },
          {
            "id": "ASB-A-987654321",
            "summary": "Silent SMS and microphone spy leak in background service",
            "details": "Allows reading SMS and recording audio silently.",
            "modified": "2026-10-10T08:30:00Z",
            "database_specific": { "severity": "HIGH" }
          }
        ]
      }
      """.trimIndent()

    val updater =
      GoogleThreatFeedUpdater(context) { _, _ ->
        GoogleHttpResponse(
          statusCode = 200,
          body = sampleGoogleOsvJson,
          serverTimestampMillis = System.currentTimeMillis(),
        )
      }

    val repository =
      SecurityRepository(
        context = context,
        dao = dao,
        preferences = prefs,
        apkAnalyzer = ApkGatekeeperAnalyzer(context),
        behaviorEngine = BehaviorMonitorEngine(context),
        googleUpdater = updater,
      )

    val result = repository.updateAntivirusDefinitionsFromGoogle(isAutomatic = false)
    assertTrue(result.isSuccess)

    val update = result.getOrThrow()
    assertEquals(2, update.googleAdvisoriesCount)
    assertEquals(
      ThreatCatalogSeeder.defaultCatalogEntries().size + 2,
      update.totalCatalogCount,
    )

    val storedCatalog = dao.observeThreatCatalog().first()
    val rceRule = storedCatalog.firstOrNull { it.threatKey == "GOOGLE_OSV_ASB-A-321456789" }
    val spyRule = storedCatalog.firstOrNull { it.threatKey == "GOOGLE_OSV_ASB-A-987654321" }
    assertTrue(rceRule != null)
    assertTrue(spyRule != null)
    assertEquals(ThreatType.VIRUS.name, rceRule!!.threatType)
    assertEquals(92, rceRule.severityScore)
    assertEquals(ThreatType.SPYWARE.name, spyRule!!.threatType)
    assertEquals(GoogleThreatFeedUpdater.GOOGLE_SERVER_LABEL, spyRule.sourceReference)

    val updatedSettings = prefs.settingsFlow.first()
    assertTrue(updatedSettings.lastAntivirusUpdateAt > 0L)
    assertFalse(updatedSettings.lastAntivirusUpdateHadError)
    assertEquals(2, updatedSettings.lastAntivirusNewDefinitionsCount)

    val events = dao.observeBehaviorEvents().first()
    assertTrue(events.any { it.eventType == "ANTIVIRUS_DEFINITIONS_UPDATED" })
  }

  @Test
  fun googleUpdateFailurePreservesCatalogAndFlagsErrorState() = runTest {
    dao.upsertThreatCatalog(ThreatCatalogSeeder.defaultCatalogEntries())
    val initialCount = dao.countThreatCatalog()

    val failingUpdater =
      GoogleThreatFeedUpdater(context) { _, _ -> throw IOException("Sem conexão com a internet") }

    val repository =
      SecurityRepository(
        context = context,
        dao = dao,
        preferences = prefs,
        apkAnalyzer = ApkGatekeeperAnalyzer(context),
        behaviorEngine = BehaviorMonitorEngine(context),
        googleUpdater = failingUpdater,
      )

    val result = repository.updateAntivirusDefinitionsFromGoogle(isAutomatic = true)
    assertTrue(result.isFailure)
    assertEquals(initialCount, dao.countThreatCatalog())

    val settings = prefs.settingsFlow.first()
    assertTrue(settings.lastAntivirusUpdateHadError)
    assertTrue(settings.lastAntivirusStatusContainsNetworkError())
  }

  private fun com.example.data.preferences.SecuritySettings.lastAntivirusStatusContainsNetworkError(): Boolean =
    lastAntivirusUpdateStatus.contains("Não foi possível conectar", ignoreCase = true)

  @Test
  fun recurringSchedulerEnqueuesAndCancelsPeriodicGoogleUpdateWork() {
    AntivirusUpdateScheduler.syncSchedule(context, enabled = true)

    val workManager = WorkManager.getInstance(context)
    val enqueuedInfos =
      workManager.getWorkInfosForUniqueWork(AntivirusUpdateScheduler.PERIODIC_WORK_NAME).get()
    assertEquals(1, enqueuedInfos.size)
    assertEquals(WorkInfo.State.ENQUEUED, enqueuedInfos.first().state)

    AntivirusUpdateScheduler.syncSchedule(context, enabled = false)
    val cancelledInfos =
      workManager.getWorkInfosForUniqueWork(AntivirusUpdateScheduler.PERIODIC_WORK_NAME).get()
    assertTrue(cancelledInfos.isEmpty() || cancelledInfos.first().state == WorkInfo.State.CANCELLED)
  }
}
