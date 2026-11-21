package com.example.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
  entities = [
    ScanAuditEntity::class,
    CertificateRuleEntity::class,
    BehaviorEventEntity::class,
    ScanHistoryEntity::class,
    WhitelistedAppEntity::class,
    ThreatCatalogEntity::class,
  ],
  version = 4,
  exportSchema = false,
)
abstract class SentinelaDatabase : RoomDatabase() {
  abstract fun sentinelaDao(): SentinelaDao

  companion object {
    @Volatile private var INSTANCE: SentinelaDatabase? = null

    val MIGRATION_1_2 =
      object : Migration(1, 2) {
        override fun migrate(db: SupportSQLiteDatabase) {
          db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `scan_history` (
              `id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
              `auditId` INTEGER,
              `packageName` TEXT NOT NULL,
              `appName` TEXT NOT NULL,
              `versionName` TEXT NOT NULL,
              `scanSource` TEXT NOT NULL,
              `verdict` TEXT NOT NULL,
              `riskScore` INTEGER NOT NULL,
              `sha256Fingerprint` TEXT NOT NULL,
              `findingsSummary` TEXT NOT NULL,
              `scannedAt` INTEGER NOT NULL
            )
            """.trimIndent()
          )
        }
      }

    val MIGRATION_2_3 =
      object : Migration(2, 3) {
        override fun migrate(db: SupportSQLiteDatabase) {
          db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `whitelisted_apps` (
              `packageName` TEXT NOT NULL PRIMARY KEY,
              `appName` TEXT NOT NULL,
              `sha256Fingerprint` TEXT NOT NULL,
              `reason` TEXT NOT NULL,
              `addedAt` INTEGER NOT NULL
            )
            """.trimIndent()
          )
        }
      }

    val MIGRATION_3_4 =
      object : Migration(3, 4) {
        override fun migrate(db: SupportSQLiteDatabase) {
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `threatCategory` TEXT NOT NULL DEFAULT 'SEGURO'")
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `isPlayStoreApp` INTEGER NOT NULL DEFAULT 0")
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `hasAccessibilityAbuse` INTEGER NOT NULL DEFAULT 0")
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `hasPermissionAbuse` INTEGER NOT NULL DEFAULT 0")
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `hasHiddenCommunication` INTEGER NOT NULL DEFAULT 0")
          db.execSQL("ALTER TABLE `scan_audits` ADD COLUMN `matchedThreatName` TEXT NOT NULL DEFAULT ''")
          db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS `threat_catalog` (
              `threatKey` TEXT NOT NULL PRIMARY KEY,
              `name` TEXT NOT NULL,
              `threatType` TEXT NOT NULL,
              `severityScore` INTEGER NOT NULL,
              `packagePatterns` TEXT NOT NULL,
              `sha256Signatures` TEXT NOT NULL,
              `permissionSignature` TEXT NOT NULL,
              `indicatorTokens` TEXT NOT NULL,
              `descriptionPt` TEXT NOT NULL,
              `recommendationPt` TEXT NOT NULL,
              `sourceReference` TEXT NOT NULL,
              `isActive` INTEGER NOT NULL,
              `updatedAt` INTEGER NOT NULL
            )
            """.trimIndent()
          )
        }
      }

    fun getInstance(context: Context): SentinelaDatabase {
      return INSTANCE
        ?: synchronized(this) {
          INSTANCE
            ?: Room.databaseBuilder(
                context.applicationContext,
                SentinelaDatabase::class.java,
                "sentinela_security.db",
              )
              .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4)
              .build()
              .also { INSTANCE = it }
        }
    }
  }
}
