package com.example.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.example.SentinelaApplication
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class PackageInstallReceiver : BroadcastReceiver() {

  override fun onReceive(context: Context, intent: Intent) {
    val action = intent.action ?: return
    val packageName = intent.data?.schemeSpecificPart ?: return
    if (packageName == context.packageName) return

    val app = context.applicationContext as? SentinelaApplication ?: return
    val pendingResult = goAsync()
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    scope.launch {
      try {
        when (action) {
          Intent.ACTION_PACKAGE_ADDED -> {
            val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            app.repository.handlePackageInstalledEvent(packageName, isUpdate = isReplacing)
          }
          Intent.ACTION_PACKAGE_REPLACED -> {
            app.repository.handlePackageInstalledEvent(packageName, isUpdate = true)
          }
          Intent.ACTION_PACKAGE_REMOVED -> {
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            if (!replacing) {
              app.repository.handlePackageRemovedEvent(packageName)
            }
          }
        }
      } finally {
        pendingResult.finish()
      }
    }
  }
}
