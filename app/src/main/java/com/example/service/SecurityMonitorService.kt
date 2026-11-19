package com.example.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.content.ContextCompat
import com.example.SentinelaApplication
import com.example.security.SignatureVerifier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class SecurityMonitorService : Service() {

  private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var monitorJob: Job? = null
  private var dynamicReceiver: PackageInstallReceiver? = null
  private var lastPackageSequenceNumber: Int = 0

  override fun onCreate() {
    super.onCreate()
    initializePackageBaseline()
    registerDynamicPackageReceiver()
    MonitorServiceState.markStarted(lastPackageSequenceNumber)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent?.action == ACTION_STOP) {
      stopSelf()
      return START_NOT_STICKY
    }

    val notification = SecurityNotifier.buildMonitorNotification(this)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      startForeground(
        SecurityNotifier.MONITOR_NOTIFICATION_ID,
        notification,
        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
      )
    } else {
      startForeground(SecurityNotifier.MONITOR_NOTIFICATION_ID, notification)
    }

    startPeriodicPackageAndBehaviorMonitor()
    return START_STICKY
  }

  private fun initializePackageBaseline() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val changed = runCatching { packageManager.getChangedPackages(0) }.getOrNull()
      lastPackageSequenceNumber = changed?.sequenceNumber ?: 0
    }
  }

  private fun startPeriodicPackageAndBehaviorMonitor() {
    if (monitorJob?.isActive == true) return
    val app = applicationContext as? SentinelaApplication ?: return
    monitorJob =
      serviceScope.launch {
        while (isActive) {
          runCatching {
            checkNewlyChangedPackagesViaPackageManager(app)
            app.repository.runBehavioralSweep()
          }
          delay(20_000L)
        }
      }
  }

  private suspend fun checkNewlyChangedPackagesViaPackageManager(app: SentinelaApplication) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val changed = runCatching { packageManager.getChangedPackages(lastPackageSequenceNumber) }.getOrNull()
      if (changed != null) {
        lastPackageSequenceNumber = changed.sequenceNumber
        MonitorServiceState.updateSequenceAndSweep(lastPackageSequenceNumber)
        for (pkgName in changed.packageNames) {
          if (pkgName == packageName) continue
          if (verifyPackageExistsAndSignatureReadable(pkgName)) {
            app.repository.handlePackageInstalledEvent(pkgName, isUpdate = false)
          }
        }
      } else {
        MonitorServiceState.updateSequenceAndSweep(lastPackageSequenceNumber)
      }
    } else {
      MonitorServiceState.updateSequenceAndSweep(lastPackageSequenceNumber)
    }
  }

  private fun verifyPackageExistsAndSignatureReadable(targetPackage: String): Boolean {
    return try {
      val flags =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          PackageManager.GET_SIGNING_CERTIFICATES
        } else {
          @Suppress("DEPRECATION")
          PackageManager.GET_SIGNATURES
        }
      val info =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
          packageManager.getPackageInfo(targetPackage, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
          @Suppress("DEPRECATION")
          packageManager.getPackageInfo(targetPackage, flags)
        }
      SignatureVerifier.analyze(info).hasSignature
    } catch (_: Exception) {
      false
    }
  }

  private fun registerDynamicPackageReceiver() {
    if (dynamicReceiver != null) return
    val receiver = PackageInstallReceiver()
    val filter =
      IntentFilter().apply {
        addAction(Intent.ACTION_PACKAGE_ADDED)
        addAction(Intent.ACTION_PACKAGE_REPLACED)
        addAction(Intent.ACTION_PACKAGE_REMOVED)
        addDataScheme("package")
      }
    // RECEIVER_EXPORTED is required so system-protected package broadcasts are delivered on API 33+
    ContextCompat.registerReceiver(this, receiver, filter, ContextCompat.RECEIVER_EXPORTED)
    dynamicReceiver = receiver
  }

  override fun onDestroy() {
    monitorJob?.cancel()
    dynamicReceiver?.let { runCatching { unregisterReceiver(it) } }
    dynamicReceiver = null
    MonitorServiceState.markStopped()
    serviceScope.cancel()
    super.onDestroy()
  }

  override fun onBind(intent: Intent?): IBinder? = null

  companion object {
    const val ACTION_START = "com.example.action.START_MONITOR"
    const val ACTION_STOP = "com.example.action.STOP_MONITOR"

    fun start(context: Context) {
      val intent = Intent(context, SecurityMonitorService::class.java).setAction(ACTION_START)
      ContextCompat.startForegroundService(context, intent)
    }

    fun stop(context: Context) {
      val intent = Intent(context, SecurityMonitorService::class.java)
      context.stopService(intent)
    }
  }
}
