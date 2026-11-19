package com.example

import android.app.Application
import com.example.data.SecurityRepository
import com.example.data.local.SentinelaDatabase
import com.example.data.preferences.SecurityPreferences
import com.example.security.ApkGatekeeperAnalyzer
import com.example.security.BehaviorMonitorEngine
import com.example.service.SecurityNotifier

class SentinelaApplication : Application() {

  lateinit var repository: SecurityRepository
    private set

  override fun onCreate() {
    super.onCreate()
    SecurityNotifier.ensureChannels(this)
    val db = SentinelaDatabase.getInstance(this)
    val prefs = SecurityPreferences(this)
    repository =
      SecurityRepository(
        context = this,
        dao = db.sentinelaDao(),
        preferences = prefs,
        apkAnalyzer = ApkGatekeeperAnalyzer(this),
        behaviorEngine = BehaviorMonitorEngine(this),
      )
  }
}
