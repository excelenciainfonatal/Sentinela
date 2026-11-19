package com.example

import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings
import com.example.security.RiskAssessmentInput
import com.example.security.RiskHeuristicEngine
import com.example.security.SignatureAnalysis
import org.junit.Assert.assertEquals
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
    assertEquals(0, result.riskScore)
  }
}
