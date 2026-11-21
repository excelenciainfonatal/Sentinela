package com.example

import android.Manifest
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.service.SecurityNotifier
import com.example.service.ThreatAlertType
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SecurityNotificationTest {

  @Test
  fun postsHighPriorityAlertNotificationWithUninstallBlockAndInspectActions() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication
    Shadows.shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    val shadowManager = Shadows.shadowOf(manager)

    val notifId =
      SecurityNotifier.postSecurityThreatPushAlert(
        context = context,
        alertType = ThreatAlertType.INVALID_SIGNATURE,
        title = "Assinatura Inválida: MaliciousApp",
        message = "Certificado expirado detectado em segundo plano.",
        appName = "MaliciousApp",
        packageName = "com.malicious.app",
        sha256Fingerprint = "AA:BB:CC:DD",
        auditId = 42L,
      )

    assertNotNull(notifId)
    val channel = manager.getNotificationChannel(SecurityNotifier.ALERTS_CHANNEL_ID)
    assertNotNull(channel)
    assertEquals(NotificationManager.IMPORTANCE_HIGH, channel.importance)

    val posted = shadowManager.allNotifications
    assertTrue(posted.isNotEmpty())
    val last = posted.last()
    assertEquals("Assinatura Inválida: MaliciousApp", last.extras.getString("android.title"))
    // Actions: "Desinstalar", "Bloquear", "Inspecionar"
    assertEquals(3, last.actions.size)
    val actionTitles = last.actions.map { it.title.toString() }
    assertEquals(listOf("Desinstalar", "Bloquear", "Inspecionar"), actionTitles)

    val uninstallIntent = Shadows.shadowOf(last.actions[0].actionIntent).savedIntent
    assertEquals(Intent.ACTION_DELETE, uninstallIntent.action)
    assertEquals("package:com.malicious.app", uninstallIntent.dataString)
  }

  @Test
  fun quickBlockActionFromNotificationBlocksPackageAndSignatureInRoom() = runTest {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication

    app.repository.blockThreatFromNotification(
      packageName = "com.spy.flashlight",
      appName = "Lanterna Spy",
      sha256Fingerprint = "DE:AD:BE:EF",
    )

    val rules = app.repository.certificateRules.first()
    assertTrue(
      rules.any {
        it.sha256Fingerprint == "DE:AD:BE:EF" && it.trustStatus == TrustStatus.BLOCKED.name
      }
    )

    val catalog = app.repository.threatCatalog.first()
    assertTrue(
      catalog.any { it.packagePatterns.contains("com.spy.flashlight") && it.severityScore >= 90 }
    )

    val events = app.repository.behaviorEvents.first()
    assertTrue(events.any { it.eventType == "THREAT_BLOCKED_NOTIFICATION" })
  }

  @Test
  fun backgroundSweepPostsPushAlertForInstalledAppWithMissingSignature() = runTest {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication
    Shadows.shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

    val shadowPm = Shadows.shadowOf(context.packageManager)
    val unsignedPkg = "com.unsigned.suspect"
    val appInfo =
      ApplicationInfo().apply {
        packageName = unsignedPkg
        name = "Unsigned Suspect"
        targetSdkVersion = 33
        uid = 10888
      }
    val pkgInfo =
      PackageInfo().apply {
        packageName = unsignedPkg
        versionName = "1.0"
        applicationInfo = appInfo
        requestedPermissions = arrayOf("android.permission.INTERNET")
        @Suppress("DEPRECATION")
        signatures = emptyArray<Signature>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          signingInfo = SigningInfo()
        }
      }
    shadowPm.installPackage(pkgInfo)

    app.repository.handlePackageInstalledEvent(unsignedPkg, isUpdate = false)

    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    val notifications = Shadows.shadowOf(manager).allNotifications
    assertTrue(
      notifications.any { notif ->
        val title = notif.extras.getString("android.title").orEmpty()
        title.contains("Assinatura Inválida")
      }
    )
  }

  @Test
  fun deviceScanAlertsImmediatelyWhenCatalogedOrAccessibilityThreatDetected() = runTest {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication
    Shadows.shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)

    val shadowPm = Shadows.shadowOf(context.packageManager)
    val trojanPkg = "com.pixpirate.bank.alert"
    val appInfo =
      ApplicationInfo().apply {
        packageName = trojanPkg
        name = "Pix Update"
        targetSdkVersion = 34
        uid = 10999
        flags = ApplicationInfo.FLAG_INSTALLED
      }
    val mainActivityInfo =
      ActivityInfo().apply {
        packageName = trojanPkg
        name = "com.pixpirate.MainActivity"
        applicationInfo = appInfo
        exported = true
      }
    val pkgInfo =
      PackageInfo().apply {
        packageName = trojanPkg
        versionName = "2.1"
        applicationInfo = appInfo
        activities = arrayOf(mainActivityInfo)
        requestedPermissions =
          arrayOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
          )
        @Suppress("DEPRECATION")
        signatures = arrayOf(Signature(byteArrayOf(1, 2, 3, 4, 5)))
      }
    shadowPm.installPackage(pkgInfo)
    @Suppress("DEPRECATION")
    shadowPm.addResolveInfoForIntent(
      Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
      android.content.pm.ResolveInfo().apply { activityInfo = mainActivityInfo },
    )

    app.repository.scanAllInstalledApps()

    val audits = app.repository.installedAppAudits.first()
    val flagged = audits.firstOrNull { it.packageName == trojanPkg }
    assertNotNull(flagged)
    assertEquals(SecurityVerdict.BLOQUEADO.name, flagged!!.verdict)

    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    val notifications = Shadows.shadowOf(manager).allNotifications
    assertTrue(
      notifications.any { notif ->
        val text = notif.extras.getCharSequence("android.text")?.toString().orEmpty()
        val title = notif.extras.getString("android.title").orEmpty()
        (title.contains("Pix Update") || text.contains("Pix Update") || title.contains(trojanPkg)) &&
          notif.actions.any { it.title == "Desinstalar" } &&
          notif.actions.any { it.title == "Bloquear" }
      }
    )
  }
}
