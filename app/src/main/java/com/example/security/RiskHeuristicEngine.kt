package com.example.security

import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings

data class RiskAssessmentInput(
  val packageName: String,
  val signature: SignatureAnalysis,
  val requestedPermissions: List<String>,
  val targetSdk: Int,
  val isDebuggableApp: Boolean,
  val isSystemApp: Boolean,
  val installerSource: String,
  val installedSignatureSha256: String?,
  val certificateTrustStatus: TrustStatus,
  val settings: SecuritySettings,
  val behavioralAnomalyScore: Int = 0,
  val behavioralFindings: List<String> = emptyList(),
)

data class RiskAssessmentResult(
  val verdict: SecurityVerdict,
  val riskScore: Int,
  val signatureMismatch: Boolean,
  val dangerousPermissions: List<String>,
  val findings: List<String>,
)

object RiskHeuristicEngine {

  private val HIGH_RISK_PERMISSIONS =
    setOf(
      "android.permission.BIND_ACCESSIBILITY_SERVICE",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.REQUEST_INSTALL_PACKAGES",
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.SEND_SMS",
      "android.permission.READ_CALL_LOG",
      "android.permission.PROCESS_OUTGOING_CALLS",
      "android.permission.READ_CONTACTS",
      "android.permission.RECORD_AUDIO",
      "android.permission.CAMERA",
      "android.permission.ACCESS_FINE_LOCATION",
      "android.permission.ACCESS_BACKGROUND_LOCATION",
      "android.permission.BIND_DEVICE_ADMIN",
      "android.permission.QUERY_ALL_PACKAGES",
      "android.permission.RECEIVE_BOOT_COMPLETED",
    )

  private val TRUSTED_INSTALLERS =
    setOf("com.android.vending", "com.google.android.feedback", "Sistema Android")

  fun evaluate(input: RiskAssessmentInput): RiskAssessmentResult {
    var score = 0
    val findings = mutableListOf<String>()
    var forceBlock = false

    val perms = input.requestedPermissions.toSet()
    val dangerousMatched = perms.filter { it in HIGH_RISK_PERMISSIONS }.sorted()

    // 1. Certificate trust rules & cryptographic checks
    if (!input.signature.hasSignature) {
      score += 100
      forceBlock = true
      findings += "APK sem assinatura digital válida (violação crítica de integridade)"
    }

    if (input.certificateTrustStatus == TrustStatus.BLOCKED) {
      score += 100
      forceBlock = true
      findings += "Assinatura digital consta na lista de bloqueio do usuário"
    }

    val signatureMismatch =
      !input.installedSignatureSha256.isNullOrBlank() &&
        input.signature.hasSignature &&
        input.installedSignatureSha256 != input.signature.sha256Fingerprint

    if (signatureMismatch) {
      score += 95
      if (input.settings.blockSignatureMismatch) {
        forceBlock = true
      }
      findings +=
        "Divergência de assinatura digital: o APK usa um certificado diferente do app já instalado (risco de adulteração/trojan)"
    }

    if (input.signature.isDebugCert) {
      score += 55
      if (input.settings.blockDebugCerts && dangerousMatched.isNotEmpty()) {
        forceBlock = true
      }
      findings += "Assinado com certificado de depuração/teste (Android Debug / testkey)"
    }

    if (input.signature.isExpired) {
      score += 40
      findings += "Certificado X.509 expirado ou fora da janela de validade"
    }

    if (input.signature.isWeakKey) {
      score += 35
      findings += "Algoritmo ou tamanho de chave fraco (${input.signature.keyAlgorithmInfo})"
    }

    if (input.signature.hasMultipleSigners) {
      score += 15
      findings += "Pacote assinado por múltiplos certificados simultâneos"
    }

    // 2. Dangerous permission combinations (Trojan / Dropper / Stalkerware heuristics)
    val hasAccessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
    val hasSms =
      "android.permission.READ_SMS" in perms ||
        "android.permission.RECEIVE_SMS" in perms ||
        "android.permission.SEND_SMS" in perms
    val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms
    val hasInstaller = "android.permission.REQUEST_INSTALL_PACKAGES" in perms
    val hasDeviceAdmin = "android.permission.BIND_DEVICE_ADMIN" in perms
    val hasBoot = "android.permission.RECEIVE_BOOT_COMPLETED" in perms
    val hasMicOrLoc =
      "android.permission.RECORD_AUDIO" in perms &&
        "android.permission.ACCESS_FINE_LOCATION" in perms &&
        "android.permission.READ_CALL_LOG" in perms

    if (hasAccessibility && (hasSms || hasOverlay)) {
      score += 60
      if (input.settings.blockHighRiskPermissions) forceBlock = true
      findings += "Combinação típica de trojan bancário: Acessibilidade + SMS/Sobreposição de tela"
    }

    if (hasInstaller && (hasOverlay || hasBoot)) {
      score += 45
      if (input.settings.blockHighRiskPermissions && input.installerSource !in TRUSTED_INSTALLERS) {
        forceBlock = true
      }
      findings += "Perfil de dropper: permissão para instalar outros APKs com persistência/sobreposição"
    }

    if (hasDeviceAdmin && hasSms) {
      score += 55
      if (input.settings.blockHighRiskPermissions) forceBlock = true
      findings += "Solicita privilégio de Administrador do Dispositivo combinado com acesso a SMS"
    }

    if (hasMicOrLoc) {
      score += 45
      findings += "Coleta simultânea de áudio, localização precisa e histórico de chamadas"
    }

    if (dangerousMatched.size >= 6) {
      score += 20
      findings += "Superfície ampla de permissões sensíveis (${dangerousMatched.size} detectadas)"
    } else if (dangerousMatched.isNotEmpty()) {
      score += (dangerousMatched.size * 3).coerceAtMost(15)
    }

    // 3. Manifest & provenance checks
    if (input.isDebuggableApp && !input.isSystemApp) {
      score += 25
      findings += "Flag android:debuggable ativa no manifesto"
    }

    if (input.targetSdk in 1..22 && !input.isSystemApp) {
      score += 35
      findings += "Target SDK legado (${input.targetSdk}) contorna permissões em tempo de execução"
    }

    val isSideload = !input.isSystemApp && input.installerSource !in TRUSTED_INSTALLERS
    if (isSideload && input.installerSource != "Inspeção Pré-Instalação") {
      score += 12
      findings += "Origem externa fora da loja oficial (${input.installerSource})"
    }

    if (input.settings.strictSideloadBlocking && isSideload && input.certificateTrustStatus != TrustStatus.TRUSTED) {
      score += 45
      forceBlock = true
      findings += "Bloqueio estrito de sideload ativo para fontes externas não confiáveis"
    }

    // 4. Behavioral anomalies
    if (input.behavioralAnomalyScore > 0) {
      score += input.behavioralAnomalyScore
      findings.addAll(input.behavioralFindings)
    }

    // 5. Explicit user allowlist mitigates non-critical risk (unless mismatch or blocked)
    if (input.certificateTrustStatus == TrustStatus.TRUSTED && !signatureMismatch && input.signature.hasSignature) {
      score = (score - 35).coerceAtLeast(0)
      if (findings.isEmpty()) {
        findings += "Certificado digital verificado na lista de confiança do Sentinela"
      }
    }

    val clampedScore = score.coerceIn(0, 100)
    val verdict =
      when {
        forceBlock || clampedScore >= 65 -> SecurityVerdict.BLOQUEADO
        clampedScore >= 30 -> SecurityVerdict.SUSPEITO
        else -> SecurityVerdict.SEGURO
      }

    if (findings.isEmpty()) {
      findings += "Assinatura digital íntegra e perfil de permissões dentro do padrão esperado"
    }

    return RiskAssessmentResult(
      verdict = verdict,
      riskScore = clampedScore,
      signatureMismatch = signatureMismatch,
      dangerousPermissions = dangerousMatched,
      findings = findings.distinct(),
    )
  }
}
