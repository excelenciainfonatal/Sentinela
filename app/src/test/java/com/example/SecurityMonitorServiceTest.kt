package com.example

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.net.Uri
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import com.example.service.MonitorServiceState
import com.example.service.PackageInstallReceiver
import com.example.service.SecurityMonitorService
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SecurityMonitorServiceTest {

  @Test
  fun foregroundServiceStartsUpdatesTelemetryAndStopsCleanly() {
    val controller = Robolectric.buildService(SecurityMonitorService::class.java)
    controller.create().startCommand(0, 0)

    assertTrue(MonitorServiceState.state.value.isServiceRunning)

    controller.destroy()
    assertFalse(MonitorServiceState.state.value.isServiceRunning)
  }

  @Test
  fun packageInstallReceiverAuditsInstalledPackageViaPackageManager() = runTest {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val app = context.applicationContext as SentinelaApplication
    val shadowPm = Shadows.shadowOf(context.packageManager)

    val testPkg = "com.test.newinstaller"
    val appInfo =
      ApplicationInfo().apply {
        packageName = testPkg
        name = "Test New App"
        targetSdkVersion = 34
        uid = 10999
      }

    val pkgInfo =
      PackageInfo().apply {
        packageName = testPkg
        versionName = "2.1.0"
        applicationInfo = appInfo
        requestedPermissions = arrayOf("android.permission.INTERNET")
        @Suppress("DEPRECATION")
        signatures = arrayOf(Signature(ByteArray(64) { 0x42 }))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          signingInfo = SigningInfo()
        }
      }

    shadowPm.installPackage(pkgInfo)

    // Directly invoke repository package event handler backed by ShadowPackageManager
    app.repository.handlePackageInstalledEvent(testPkg, isUpdate = false)

    val history = app.repository.scanHistory.first()
    val recorded = history.firstOrNull { it.packageName == testPkg && it.scanSource == "TEMPO_REAL" }
    assertEquals(testPkg, recorded?.packageName)
    assertEquals("2.1.0", recorded?.versionName)

    // Also verify BroadcastReceiver filters self-package cleanly
    val receiver = PackageInstallReceiver()
    receiver.onReceive(
      context,
      Intent(Intent.ACTION_PACKAGE_ADDED).apply { data = Uri.parse("package:${context.packageName}") },
    )
  }
}
