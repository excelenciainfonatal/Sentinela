package com.example.service

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object AntivirusUpdateScheduler {

  const val PERIODIC_WORK_NAME = "sentinela_google_antivirus_update"
  const val ONE_TIME_WORK_NAME = "sentinela_google_antivirus_manual_sync"
  const val REPEAT_INTERVAL_HOURS = 12L

  fun syncSchedule(context: Context, enabled: Boolean) {
    val workManager = WorkManager.getInstance(context)
    if (enabled) {
      val constraints =
        Constraints.Builder()
          .setRequiredNetworkType(NetworkType.CONNECTED)
          .setRequiresBatteryNotLow(true)
          .build()

      val request =
        PeriodicWorkRequestBuilder<AntivirusUpdateWorker>(
            REPEAT_INTERVAL_HOURS,
            TimeUnit.HOURS,
          )
          .setConstraints(constraints)
          .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
          .addTag(PERIODIC_WORK_NAME)
          .build()

      workManager.enqueueUniquePeriodicWork(
        PERIODIC_WORK_NAME,
        ExistingPeriodicWorkPolicy.KEEP,
        request,
      )
    } else {
      workManager.cancelUniqueWork(PERIODIC_WORK_NAME)
    }
  }

  fun enqueueImmediateSync(context: Context) {
    val constraints =
      Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
    val request =
      OneTimeWorkRequestBuilder<AntivirusUpdateWorker>()
        .setConstraints(constraints)
        .addTag(ONE_TIME_WORK_NAME)
        .build()
    WorkManager.getInstance(context)
      .enqueueUniqueWork(ONE_TIME_WORK_NAME, ExistingWorkPolicy.REPLACE, request)
  }
}
