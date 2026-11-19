package com.example.service

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.example.SentinelaApplication
import com.example.data.local.TrustStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class NotificationActionReceiver : BroadcastReceiver() {

  override fun onReceive(context: Context, intent: Intent) {
    if (intent.action != ACTION_BLOCK_SIGNATURE) return

    val sha256 = intent.getStringExtra(EXTRA_SHA256) ?: return
    val appName = intent.getStringExtra(EXTRA_APP_NAME).orEmpty()
    val pkgName = intent.getStringExtra(EXTRA_PACKAGE_NAME).orEmpty()
    val notificationId = intent.getIntExtra(EXTRA_NOTIFICATION_ID, -1)

    val app = context.applicationContext as? SentinelaApplication ?: return
    val pendingResult = goAsync()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    scope.launch {
      try {
        app.repository.setCertificateTrust(
          sha256 = sha256,
          label = appName.ifBlank { pkgName },
          packageNameHint = pkgName,
          status = TrustStatus.BLOCKED,
          notes = "Bloqueado diretamente a partir do alerta push do Sentinela",
        )
        if (notificationId != -1) {
          val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
          manager.cancel(notificationId)
        }
      } finally {
        pendingResult.finish()
      }
    }
  }

  companion object {
    const val ACTION_BLOCK_SIGNATURE = "com.example.action.BLOCK_SIGNATURE_FROM_NOTIFICATION"
    const val EXTRA_SHA256 = "extra_sha256"
    const val EXTRA_APP_NAME = "extra_app_name"
    const val EXTRA_PACKAGE_NAME = "extra_package_name"
    const val EXTRA_NOTIFICATION_ID = "extra_notification_id"
  }
}
