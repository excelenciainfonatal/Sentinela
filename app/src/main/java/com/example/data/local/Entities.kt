package com.example.data.local

import androidx.compose.runtime.Immutable
import androidx.room.Entity
import androidx.room.PrimaryKey

enum class SecurityVerdict(val labelPt: String) {
  SEGURO("Seguro"),
  SUSPEITO("Suspeito"),
  BLOQUEADO("Bloqueado"),
}

enum class TrustStatus(val labelPt: String) {
  NEUTRAL("Não Classificado"),
  TRUSTED("Confiável"),
  BLOCKED("Bloqueado"),
}

enum class EventSeverity(val labelPt: String) {
  INFO("Info"),
  WARNING("Alerta"),
  CRITICAL("Crítico"),
}

enum class ThreatType(val labelPt: String) {
  VIRUS("Vírus / Trojan"),
  SPYWARE("Spyware"),
  ADWARE("Adware"),
  ARQUIVO_MALICIOSO("Arquivo Malicioso"),
}

enum class ThreatClassification(val labelPt: String) {
  SEGURO("Seguro"),
  VIRUS_TROJAN("Vírus / Trojan Bancário"),
  SPYWARE("Spyware / Espião"),
  ADWARE("Adware / Propagandas"),
  ABUSO_PERMISSAO("Abuso de Permissão"),
  ACESSIBILIDADE("Abuso de Acessibilidade"),
  COMUNICACAO_OCULTA("Comunicação Oculta"),
  ARQUIVO_MALICIOSO("Arquivo Malicioso"),
}

@Immutable
@Entity(tableName = "scan_audits")
data class ScanAuditEntity(
  @PrimaryKey(autoGenerate = true) val id: Long = 0,
  val packageName: String,
  val appName: String,
  val versionName: String,
  val sourceType: String, // "APK_PRE_INSTALL", "INSTALLED_APP", "PACKAGE_ADDED"
  val verdict: String, // SecurityVerdict name
  val riskScore: Int,
  val sha256Fingerprint: String,
  val sha1Fingerprint: String,
  val signerSubject: String,
  val signerIssuer: String,
  val keyAlgorithmInfo: String,
  val validUntilMillis: Long,
  val isDebugCert: Boolean,
  val isExpiredCert: Boolean,
  val isSelfSigned: Boolean,
  val signatureMismatch: Boolean,
  val installerSource: String,
  val targetSdk: Int,
  val isDebuggableApp: Boolean,
  val isSystemApp: Boolean,
  val txBytes: Long,
  val rxBytes: Long,
  val findingsSummary: String,
  val dangerousPermissions: String,
  val scannedAt: Long = System.currentTimeMillis(),
  val threatCategory: String = ThreatClassification.SEGURO.name,
  val isPlayStoreApp: Boolean = false,
  val hasAccessibilityAbuse: Boolean = false,
  val hasPermissionAbuse: Boolean = false,
  val hasHiddenCommunication: Boolean = false,
  val matchedThreatName: String = "",
)

@Immutable
@Entity(tableName = "certificate_rules")
data class CertificateRuleEntity(
  @PrimaryKey val sha256Fingerprint: String,
  val label: String,
  val trustStatus: String, // TrustStatus name: "TRUSTED" or "BLOCKED"
  val packageNameHint: String,
  val notes: String,
  val updatedAt: Long = System.currentTimeMillis(),
)

@Immutable
@Entity(tableName = "behavior_events")
data class BehaviorEventEntity(
  @PrimaryKey(autoGenerate = true) val id: Long = 0,
  val packageName: String,
  val appName: String,
  val eventType: String,
  val severity: String, // EventSeverity name
  val details: String,
  val txBytes: Long,
  val rxBytes: Long,
  val timestamp: Long = System.currentTimeMillis(),
)

@Immutable
@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
  @PrimaryKey(autoGenerate = true) val id: Long = 0,
  val auditId: Long? = null,
  val packageName: String,
  val appName: String,
  val versionName: String,
  val scanSource: String, // "GATEKEEPER_APK", "VARREDURA_DISPOSITIVO", "TEMPO_REAL"
  val verdict: String, // SecurityVerdict name: SEGURO, SUSPEITO, BLOQUEADO
  val riskScore: Int,
  val sha256Fingerprint: String,
  val findingsSummary: String,
  val scannedAt: Long = System.currentTimeMillis(),
)

@Immutable
@Entity(tableName = "whitelisted_apps")
data class WhitelistedAppEntity(
  @PrimaryKey val packageName: String,
  val appName: String,
  val sha256Fingerprint: String,
  val reason: String = "Marcado pelo usuário como confiável",
  val addedAt: Long = System.currentTimeMillis(),
)

@Immutable
@Entity(tableName = "threat_catalog")
data class ThreatCatalogEntity(
  @PrimaryKey val threatKey: String,
  val name: String,
  val threatType: String, // ThreatType name: VIRUS, SPYWARE, ADWARE, ARQUIVO_MALICIOSO
  val severityScore: Int,
  val packagePatterns: String,
  val sha256Signatures: String,
  val permissionSignature: String,
  val indicatorTokens: String,
  val descriptionPt: String,
  val recommendationPt: String,
  val sourceReference: String = "Catálogo Sentinela",
  val isActive: Boolean = true,
  val updatedAt: Long = System.currentTimeMillis(),
)
