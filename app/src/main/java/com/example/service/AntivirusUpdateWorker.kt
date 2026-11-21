package com.example.service

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.example.SentinelaApplication

class AntivirusUpdateWorker(
  appContext: Context,
  params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

  override suspend fun doWork(): Result {
    val app = applicationContext as? SentinelaApplication ?: return Result.failure()
    val result = app.repository.updateAntivirusDefinitionsFromGoogle(isAutomatic = true)
    return if (result.isSuccess) {
      Result.success()
    } else if (runAttemptCount < 3) {
      Result.retry()
    } else {
      Result.failure()
    }
  }
}
