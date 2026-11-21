package com.example

import com.example.data.local.SecurityVerdict
import com.example.data.local.ThreatCatalogSeeder
import com.example.data.local.ThreatClassification
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings
import com.example.security.RiskAssessmentInput
import com.example.security.RiskHeuristicEngine
import com.example.security.SignatureAnalysis
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskHeuristicEngineTest {

  private fun sampleSignature(
    hasSignature: Boolean = true,
    sha256: String = "AA:BB:CC:DD:EE:FF",
    isDebug: Boolean = false,
    isExpired: Boolean = false,
    isWeak: Boolean = false,
  ) =
    SignatureAnalysis(
      hasSignature = hasSignature,
      sha256Fingerprint = sha256,
      sha1Fingerprint = "11:22:33",
      subject = "CN=Trusted Dev",
      issuer = "CN=Trusted Dev",
      keyAlgorithmInfo = "RSA 2048-bit (SHA256withRSA)",
      keyBitLength = 2048,
      sigAlgName = "SHA256withRSA",
      validFromMillis = 1_000_000L,
      validUntilMillis = 9_999_999_999_999L,
      isDebugCert = isDebug,
      isExpired = isExpired,
      isSelfSigned = true,
      isWeakKey = isWeak,
      hasMultipleSigners = false,
    )

  @Test
  fun signatureMismatchForcesBlockVerdict() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.bank.app",
          signature = sampleSignature(sha256 = "FF:EE:DD:CC"),
          requestedPermissions = emptyList(),
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "Inspeção Pré-Instalação",
          installedSignatureSha256 = "11:22:33:44",
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(blockSignatureMismatch = true),
        )
      )

    assertTrue(result.signatureMismatch)
    assertEquals(SecurityVerdict.BLOQUEADO, result.verdict)
    assertTrue(result.riskScore >= 90)
  }

  @Test
  fun trojanPermissionCombinationBlocksInstallation() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.malicious.dropper",
          signature = sampleSignature(isDebug = true),
          requestedPermissions =
            listOf(
              "android.permission.BIND_ACCESSIBILITY_SERVICE",
              "android.permission.RECEIVE_SMS",
              "android.permission.SYSTEM_ALERT_WINDOW",
            ),
          targetSdk = 33,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "Inspeção Pré-Instalação",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(),
        )
      )

    assertEquals(SecurityVerdict.BLOQUEADO, result.verdict)
    assertTrue(result.hasAccessibilityAbuse)
    assertEquals(ThreatClassification.VIRUS_TROJAN, result.threatCategory)
    assertTrue(result.dangerousPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE"))
  }

  @Test
  fun validTrustedCertificateWithSafePermissionsIsSafe() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.clean.utility",
          signature = sampleSignature(),
          requestedPermissions = listOf("android.permission.INTERNET"),
          targetSdk = 35,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "com.android.vending",
          installedSignatureSha256 = "AA:BB:CC:DD:EE:FF",
          certificateTrustStatus = TrustStatus.TRUSTED,
          settings = SecuritySettings(),
        )
      )

    assertEquals(SecurityVerdict.SEGURO, result.verdict)
    assertTrue(result.isPlayStoreApp)
    assertEquals(0, result.riskScore)
  }

  @Test
  fun utilityFlashlightRequestingSmsContactsAndMicFlagsPermissionAbuseEvenFromPlayStore() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.bright.flashlight.free",
          appName = "Super Lanterna LED",
          signature = sampleSignature(),
          requestedPermissions =
            listOf(
              "android.permission.READ_SMS",
              "android.permission.READ_CONTACTS",
              "android.permission.RECORD_AUDIO",
              "android.permission.INTERNET",
            ),
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "com.android.vending",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(),
        )
      )

    assertTrue(result.isPlayStoreApp)
    assertTrue(result.hasPermissionAbuse)
    assertEquals(SecurityVerdict.BLOQUEADO, result.verdict)
    assertTrue(result.findings.any { it.contains("Abuso de permissão", ignoreCase = true) })
    assertTrue(result.findings.any { it.contains("Google Play Store", ignoreCase = true) })
  }

  @Test
  fun activeAccessibilityServiceDetectedAsBankingTrojanRisk() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.helper.pdf.viewer",
          appName = "Leitor PDF Rápido",
          signature = sampleSignature(),
          requestedPermissions = listOf("android.permission.INTERNET"),
          declaresAccessibilityService = true,
          isAccessibilityServiceEnabled = true,
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "Sideload / Instalador Manual",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(blockHighRiskPermissions = true),
        )
      )

    assertFalse(result.isPlayStoreApp)
    assertTrue(result.hasAccessibilityAbuse)
    assertEquals(ThreatClassification.VIRUS_TROJAN, result.threatCategory)
    assertEquals(SecurityVerdict.BLOQUEADO, result.verdict)
    assertTrue(result.findings.any { it.contains("Acessibilidade ATIVA", ignoreCase = true) })
  }

  @Test
  fun silentBackgroundUploadWithoutUserLaunchesFlagsHiddenCommunication() {
    val result =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.simple.calculator.tools",
          appName = "Calculadora Simples",
          signature = sampleSignature(),
          requestedPermissions = listOf("android.permission.INTERNET"),
          txBytes = 4L * 1024L * 1024L,
          rxBytes = 128L * 1024L,
          foregroundLaunchCount = 0,
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "com.android.vending",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(),
        )
      )

    assertTrue(result.hasHiddenCommunication)
    assertEquals(ThreatClassification.COMUNICACAO_OCULTA, result.threatCategory)
    assertTrue(result.verdict != SecurityVerdict.SEGURO)
    assertTrue(result.findings.any { it.contains("Comunicação oculta", ignoreCase = true) })
  }

  @Test
  fun catalogedSpywareAndNestedDropperAreMatchedFromCatalog() {
    val catalog = ThreatCatalogSeeder.defaultCatalogEntries()
    val spywareResult =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.joker.bread.emoji",
          appName = "Color Emoji",
          signature = sampleSignature(),
          requestedPermissions = listOf("android.permission.READ_SMS", "android.permission.INTERNET"),
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "com.android.vending",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(),
          catalogThreats = catalog,
        )
      )

    assertEquals(SecurityVerdict.BLOQUEADO, spywareResult.verdict)
    assertEquals(ThreatClassification.SPYWARE, spywareResult.threatCategory)
    assertTrue(spywareResult.matchedThreatName.contains("Joker"))

    val dropperResult =
      RiskHeuristicEngine.evaluate(
        RiskAssessmentInput(
          packageName = "com.unknown.installer",
          appName = "Atualização Sistema",
          signature = sampleSignature(),
          requestedPermissions = listOf("android.permission.REQUEST_INSTALL_PACKAGES"),
          staticIndicators = listOf("nested_apk_in_assets", "raw_ip_http_endpoint"),
          targetSdk = 34,
          isDebuggableApp = false,
          isSystemApp = false,
          installerSource = "Inspeção Pré-Instalação",
          installedSignatureSha256 = null,
          certificateTrustStatus = TrustStatus.NEUTRAL,
          settings = SecuritySettings(),
          catalogThreats = catalog,
        )
      )

    assertEquals(SecurityVerdict.BLOQUEADO, dropperResult.verdict)
    assertTrue(dropperResult.hasHiddenCommunication)
    assertEquals(ThreatClassification.ARQUIVO_MALICIOSO, dropperResult.threatCategory)
  }
}
