package com.example

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.ScanAuditEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.SentinelaDao
import com.example.data.local.SentinelaDatabase
import com.example.data.local.WhitelistedAppEntity
import com.example.service.MonitorServiceState
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
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class WhitelistDatabaseTest {

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
  fun whitelistDaoInsertsQueriesAndRemovesApps() = runTest {
    val trusted =
      WhitelistedAppEntity(
        packageName = "com.trusted.bank",
        appName = "Trusted Bank",
        sha256Fingerprint = "AA:BB:CC:DD",
      )
    dao.upsertWhitelistedApp(trusted)

    assertTrue(dao.isAppWhitelisted("com.trusted.bank"))
    assertFalse(dao.isAppWhitelisted("com.unknown.app"))

    val list = dao.observeWhitelistedApps().first()
    assertEquals(1, list.size)
    assertEquals("Trusted Bank", list[0].appName)

    dao.removeWhitelistedApp("com.trusted.bank")
    assertFalse(dao.isAppWhitelisted("com.trusted.bank"))
    assertTrue(dao.observeWhitelistedApps().first().isEmpty())
  }

  @Test
  fun whitelistedAppIsIgnoredByRealTimePackageScannerAndSweep() = runTest {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication
    Shadows.shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    manager.cancelAll()

    val shadowPm = Shadows.shadowOf(context.packageManager)
    val whitelistedPkg = "com.whitelisted.unsigned"
    val appInfo =
      ApplicationInfo().apply {
        packageName = whitelistedPkg
        name = "Whitelisted Local Tool"
        targetSdkVersion = 34
        uid = 10912
      }
    val pkgInfo =
      PackageInfo().apply {
        packageName = whitelistedPkg
        versionName = "1.0.0"
        applicationInfo = appInfo
        requestedPermissions = arrayOf("android.permission.INTERNET")
        @Suppress("DEPRECATION")
        signatures = emptyArray<Signature>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          signingInfo = SigningInfo()
        }
      }
    shadowPm.installPackage(pkgInfo)

    // Seed an existing risky audit to confirm addToWhitelist clears it to SEGURO
    val appDao = SentinelaDatabase.getInstance(context).sentinelaDao()
    appDao.insertAudit(
      ScanAuditEntity(
        packageName = whitelistedPkg,
        appName = "Whitelisted Local Tool",
        versionName = "1.0.0",
        sourceType = "INSTALLED_APP",
        verdict = SecurityVerdict.BLOQUEADO.name,
        riskScore = 85,
        sha256Fingerprint = "SEM ASSINATURA",
        sha1Fingerprint = "N/A",
        signerSubject = "Desconhecido",
        signerIssuer = "Desconhecido",
        keyAlgorithmInfo = "N/A",
        validUntilMillis = 0L,
        isDebugCert = false,
        isExpiredCert = false,
        isSelfSigned = false,
        signatureMismatch = false,
        installerSource = "Sideload",
        targetSdk = 34,
        isDebuggableApp = false,
        isSystemApp = false,
        txBytes = 0L,
        rxBytes = 0L,
        findingsSummary = "• Sem assinatura",
        dangerousPermissions = "",
      )
    )

    // Add to whitelist
    app.repository.addToWhitelist(
      packageName = whitelistedPkg,
      appName = "Whitelisted Local Tool",
      sha256Fingerprint = "SEM ASSINATURA",
    )

    // Verify existing audit marked safe
    val updatedAudit = appDao.getLatestInstalledAuditForPackage(whitelistedPkg)
    assertEquals(SecurityVerdict.SEGURO.name, updatedAudit?.verdict)
    assertEquals(0, updatedAudit?.riskScore)

    // Real-time package install event should ignore whitelisted package completely
    app.repository.handlePackageInstalledEvent(whitelistedPkg, isUpdate = false)
    assertEquals("Lista Branca (Ignorado)", MonitorServiceState.state.value.lastVerifiedVerdict)

    // Background sweep should also ignore it
    app.repository.runBehavioralSweep()

    val historyForPkg =
      app.repository.scanHistory.first().filter { it.packageName == whitelistedPkg }
    assertTrue(historyForPkg.isEmpty())

    val eventsForPkg =
      app.repository.behaviorEvents.first().filter { it.packageName == whitelistedPkg }
    assertTrue(eventsForPkg.isEmpty())

    val notifications = Shadows.shadowOf(manager).allNotifications
    assertFalse(
      notifications.any { notif ->
        val title = notif.extras.getString("android.title").orEmpty()
        title.contains("Whitelisted Local Tool")
      }
    )

    // Remove from whitelist and verify DB reflects removal
    app.repository.removeFromWhitelist(whitelistedPkg)
    assertFalse(appDao.isAppWhitelisted(whitelistedPkg))
  }
}
