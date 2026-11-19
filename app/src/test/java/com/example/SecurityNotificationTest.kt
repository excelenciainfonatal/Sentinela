package com.example

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import com.example.service.SecurityNotifier
import com.example.service.ThreatAlertType
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
  fun postsHighPriorityAlertNotificationWithDeepLinkAndActions() {
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
    // Actions: "Inspecionar", "Bloquear Assinatura", "Gerenciar App"
    assertEquals(3, last.actions.size)
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

    // Audit the unsigned package and then execute background sweep
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
}
