package com.example.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.example.SentinelaApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class NotificationActionReceiver : BroadcastReceiver() {

  override fun onReceive(context: Context, intent: Intent) {
    if (intent.action != ACTION_BLOCK_THREAT && intent.action != ACTION_BLOCK_SIGNATURE) return

    val sha256 = intent.getStringExtra(EXTRA_SHA256).orEmpty()
    val appName = intent.getStringExtra(EXTRA_APP_NAME).orEmpty()
    val pkgName = intent.getStringExtra(EXTRA_PACKAGE_NAME).orEmpty()
    val notificationId = intent.getIntExtra(EXTRA_NOTIFICATION_ID, -1)

    if (sha256.isBlank() && pkgName.isBlank()) return

    val app = context.applicationContext as? SentinelaApplication ?: return
    val pendingResult = goAsync()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    scope.launch {
      try {
        app.repository.blockThreatFromNotification(
          packageName = pkgName,
          appName = appName.ifBlank { pkgName },
          sha256Fingerprint = sha256,
        )
        SecurityNotifier.cancelNotification(context, notificationId)
      } finally {
        pendingResult.finish()
      }
    }
  }

  companion object {
    const val ACTION_BLOCK_THREAT = "com.example.action.BLOCK_THREAT_FROM_NOTIFICATION"
    const val ACTION_BLOCK_SIGNATURE = "com.example.action.BLOCK_SIGNATURE_FROM_NOTIFICATION"
    const val EXTRA_SHA256 = "extra_sha256"
    const val EXTRA_APP_NAME = "extra_app_name"
    const val EXTRA_PACKAGE_NAME = "extra_package_name"
    const val EXTRA_NOTIFICATION_ID = "extra_notification_id"
  }
}
