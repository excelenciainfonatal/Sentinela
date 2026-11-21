package com.example.security

import com.example.data.local.SecurityVerdict
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.ThreatClassification
import com.example.data.local.ThreatType
import com.example.data.local.TrustStatus
import com.example.data.preferences.SecuritySettings
import java.util.Locale

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
  val appName: String = "",
  val declaresAccessibilityService: Boolean = false,
  val isAccessibilityServiceEnabled: Boolean = false,
  val txBytes: Long = 0L,
  val rxBytes: Long = 0L,
  val foregroundLaunchCount: Int = -1,
  val staticIndicators: List<String> = emptyList(),
  val fileSha256: String? = null,
  val catalogThreats: List<ThreatCatalogEntity> = emptyList(),
)

data class RiskAssessmentResult(
  val verdict: SecurityVerdict,
  val riskScore: Int,
  val signatureMismatch: Boolean,
  val dangerousPermissions: List<String>,
  val findings: List<String>,
  val threatCategory: ThreatClassification = ThreatClassification.SEGURO,
  val isPlayStoreApp: Boolean = false,
  val hasAccessibilityAbuse: Boolean = false,
  val hasPermissionAbuse: Boolean = false,
  val hasHiddenCommunication: Boolean = false,
  val matchedThreatName: String = "",
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

  private data class UtilityProfile(val label: String, val keywords: List<String>)

  private val UTILITY_PROFILES =
    listOf(
      UtilityProfile("Lanterna", listOf("lanterna", "flashlight", "torch", "ledlight")),
      UtilityProfile("Calculadora", listOf("calculadora", "calculator", ".calc")),
      UtilityProfile("Bússola", listOf("bussola", "bússola", "compass")),
      UtilityProfile("Relógio/Alarme", listOf("relogio", "relógio", "stopwatch", "cronometro", "timer")),
      UtilityProfile("Papel de Parede", listOf("wallpaper", "papel de parede", "ringtone")),
      UtilityProfile("Bloco de Notas", listOf("notepad", "bloco de notas", "sticky note")),
      UtilityProfile("Limpador/Booster", listOf("cleaner", "limpador", "booster", "ramboost", "battery saver")),
      UtilityProfile("Clima/Conversor", listOf("conversor", "unit converter", "horoscope", "horóscopo")),
    )

  fun evaluate(input: RiskAssessmentInput): RiskAssessmentResult {
    var score = 0
    val findings = mutableListOf<String>()
    var forceBlock = false

    var hasAccessibilityAbuse = false
    var hasPermissionAbuse = false
    var hasHiddenCommunication = false
    var matchedCatalogEntry: ThreatCatalogEntity? = null

    val isPlayStoreApp = input.installerSource == "com.android.vending"
    val isSideload = !input.isSystemApp && input.installerSource !in TRUSTED_INSTALLERS

    val perms = input.requestedPermissions.toSet()
    val shortPerms = perms.map { it.removePrefix("android.permission.") }.toSet()
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

    // 2. Cataloged Threat Database Matching (Vírus, Spywares, Adwares, Arquivos Maliciosos)
    if (!input.isSystemApp && input.catalogThreats.isNotEmpty()) {
      val pkgLower = input.packageName.lowercase(Locale.ROOT)
      val certShaUpper = input.signature.sha256Fingerprint.uppercase(Locale.ROOT)
      val fileShaUpper = input.fileSha256?.uppercase(Locale.ROOT).orEmpty()
      val indicatorSet = input.staticIndicators.map { it.lowercase(Locale.ROOT) }.toSet()

      var bestCatalogScore = 0
      for (entry in input.catalogThreats) {
        if (!entry.isActive) continue
        val shaHits =
          entry.sha256Signatures
            .split(",")
            .map { it.trim().uppercase(Locale.ROOT) }
            .filter { it.isNotBlank() }
            .any { it == certShaUpper || (fileShaUpper.isNotBlank() && it == fileShaUpper) }

        val pkgHits =
          entry.packagePatterns
            .split(",")
            .map { it.trim().lowercase(Locale.ROOT) }
            .filter { it.isNotBlank() }
            .any { pattern -> pkgLower == pattern || pkgLower.startsWith("$pattern.") || pkgLower.contains(pattern) }

        val requiredPerms =
          entry.permissionSignature
            .split(",")
            .map { it.trim() }
            .filter { it.isNotBlank() }
        val permMatchCount = requiredPerms.count { it in shortPerms }

        val indicatorTokens =
          entry.indicatorTokens
            .split(",")
            .map { it.trim().lowercase(Locale.ROOT) }
            .filter { it.isNotBlank() }
        val indicatorHits = indicatorTokens.count { token -> token in indicatorSet }

        val matched =
          shaHits ||
            pkgHits ||
            (indicatorHits >= 2) ||
            (indicatorHits >= 1 && permMatchCount >= 2)

        if (matched && entry.severityScore > bestCatalogScore) {
          bestCatalogScore = entry.severityScore
          matchedCatalogEntry = entry
        }
      }

      matchedCatalogEntry?.let { threat ->
        val typeLabel =
          runCatching { ThreatType.valueOf(threat.threatType).labelPt }.getOrDefault(threat.threatType)
        score = maxOf(score + 35, threat.severityScore)
        if (threat.severityScore >= 75) {
          forceBlock = true
        }
        findings += "Catálogo [$typeLabel]: ${threat.name} — ${threat.descriptionPt}"
        if (threat.threatType == ThreatType.SPYWARE.name) {
          hasPermissionAbuse = true
        }
      }
    }

    // 3. Accessibility Service Abuse Detection (Screen Reading & Auto-Click Banking Trojans)
    val hasAccessibility =
      input.declaresAccessibilityService ||
        "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
    val hasSms =
      "android.permission.READ_SMS" in perms ||
        "android.permission.RECEIVE_SMS" in perms ||
        "android.permission.SEND_SMS" in perms
    val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms
    val hasInstaller = "android.permission.REQUEST_INSTALL_PACKAGES" in perms
    val hasDeviceAdmin = "android.permission.BIND_DEVICE_ADMIN" in perms
    val hasBoot = "android.permission.RECEIVE_BOOT_COMPLETED" in perms
    val hasQueryAll = "android.permission.QUERY_ALL_PACKAGES" in perms
    val hasContactsOrCalls =
      "android.permission.READ_CONTACTS" in perms ||
        "android.permission.READ_CALL_LOG" in perms ||
        "android.permission.PROCESS_OUTGOING_CALLS" in perms
    val hasMic = "android.permission.RECORD_AUDIO" in perms
    val hasBgLocation = "android.permission.ACCESS_BACKGROUND_LOCATION" in perms

    if (!input.isSystemApp) {
      if (input.isAccessibilityServiceEnabled) {
        hasAccessibilityAbuse = true
        score += 50
        if (input.settings.blockHighRiskPermissions) forceBlock = true
        findings +=
          "Acessibilidade ATIVA: este app pode ler o que aparece na sua tela e clicar em botões sozinho (comportamento comum em vírus bancários)."
      } else if (hasAccessibility) {
        hasAccessibilityAbuse = true
        score += 35
        findings +=
          "Serviço de Acessibilidade declarado: permite ler sua tela e automatizar toques sem você perceber."
      }

      if (hasAccessibility && (hasSms || hasOverlay || hasInstaller || hasQueryAll || hasDeviceAdmin)) {
        hasAccessibilityAbuse = true
        score += 45
        if (input.settings.blockHighRiskPermissions) forceBlock = true
        findings +=
          "Combinação típica de trojan bancário: Acessibilidade + SMS/Sobreposição de tela ou instalação oculta"
      }
    }

    // 4. Context-Mismatch Permission Abuse (e.g., Flashlight or Calculator asking for SMS/Contacts/Mic)
    if (!input.isSystemApp) {
      val searchText = "${input.appName} ${input.packageName}".lowercase(Locale.ROOT)
      val matchedUtility =
        UTILITY_PROFILES.firstOrNull { profile ->
          profile.keywords.any { keyword -> searchText.contains(keyword) }
        }

      if (matchedUtility != null) {
        if (hasSms) {
          hasPermissionAbuse = true
          score += 55
          if (input.settings.blockHighRiskPermissions) forceBlock = true
          findings +=
            "Abuso de permissão: app simples (${matchedUtility.label}) tentando ler ou enviar mensagens SMS."
        }
        if (hasContactsOrCalls) {
          hasPermissionAbuse = true
          score += 40
          findings +=
            "Abuso de permissão: aplicativo de ${matchedUtility.label} pedindo acesso à lista de contatos ou histórico de chamadas."
        }
        if (hasMic) {
          hasPermissionAbuse = true
          score += 42
          findings +=
            "Abuso de permissão: aplicativo de ${matchedUtility.label} solicitando microfone para gravar áudio sem justificativa."
        }
        if (hasBgLocation) {
          hasPermissionAbuse = true
          score += 35
          findings +=
            "Abuso de permissão: aplicativo de ${matchedUtility.label} rastreando localização em segundo plano."
        }
      }

      // General spyware / background recording combinations for any app
      val hasBgAudioSpy = hasMic && (hasBoot || hasBgLocation || "android.permission.READ_CALL_LOG" in perms)
      val hasMicLocCalls =
        hasMic &&
          "android.permission.ACCESS_FINE_LOCATION" in perms &&
          "android.permission.READ_CALL_LOG" in perms

      if (hasMicLocCalls) {
        hasPermissionAbuse = true
        score += 45
        findings += "Abuso de permissão: coleta simultânea de áudio, localização precisa e histórico de chamadas"
      } else if (hasBgAudioSpy && matchedUtility == null) {
        hasPermissionAbuse = true
        score += 32
        findings += "Abuso de permissão: acesso ao microfone combinado com inicialização em segundo plano"
      }

      if (hasSms && "android.permission.READ_CONTACTS" in perms && "android.permission.INTERNET" in perms && matchedUtility == null) {
        hasPermissionAbuse = true
        score += 35
        findings += "Abuso de permissão: combinação de leitura de SMS, contatos e acesso à internet"
      }
    }

    if (hasInstaller && (hasOverlay || hasBoot)) {
      score += 45
      if (input.settings.blockHighRiskPermissions && input.installerSource !in TRUSTED_INSTALLERS) {
        forceBlock = true
      }
      findings += "Perfil de dropper: permissão para instalar outros APKs com persistência/sobreposição"
    }

    if (hasDeviceAdmin && hasSms) {
      hasPermissionAbuse = true
      score += 55
      if (input.settings.blockHighRiskPermissions) forceBlock = true
      findings += "Solicita privilégio de Administrador do Dispositivo combinado com acesso a SMS"
    }

    if (dangerousMatched.size >= 6) {
      score += 20
      findings += "Superfície ampla de permissões sensíveis (${dangerousMatched.size} detectadas)"
    } else if (dangerousMatched.isNotEmpty()) {
      score += (dangerousMatched.size * 3).coerceAtMost(15)
    }

    // 5. Hidden Communication Detection (Runtime silent upload + Static C2 endpoints)
    if (!input.isSystemApp) {
      val twoMb = 2L * 1024L * 1024L
      val fiveMb = 5L * 1024L * 1024L
      if (input.txBytes >= twoMb && input.foregroundLaunchCount == 0) {
        hasHiddenCommunication = true
        score += 48
        findings +=
          "Comunicação oculta: enviou ${formatBytesCompact(input.txBytes)} silenciosamente sem você abrir o aplicativo."
      } else if (input.txBytes >= fiveMb && input.txBytes > (input.rxBytes * 2L + 1_048_576L)) {
        hasHiddenCommunication = true
        score += 36
        findings +=
          "Comunicação oculta suspeita: tráfego de saída desproporcional (${formatBytesCompact(input.txBytes)} enviados vs ${formatBytesCompact(input.rxBytes)} recebidos)."
      }

      val indicators = input.staticIndicators.toSet()
      if ("raw_ip_http_endpoint" in indicators) {
        hasHiddenCommunication = true
        score += 42
        findings +=
          "Comunicação oculta: endereço de servidor externo por IP direto encontrado no código do aplicativo."
      }
      if ("onion_tor_c2" in indicators) {
        hasHiddenCommunication = true
        score += 50
        forceBlock = true
        findings +=
          "Comunicação oculta crítica: endereço de rede oculta (.onion) detectado para envio silencioso."
      }
      if ("api.telegram.org/bot" in indicators || "discord.com/api/webhooks" in indicators) {
        hasHiddenCommunication = true
        score += 45
        findings +=
          "Comunicação oculta: canal de bot/webhook externo embutido para envio automático de dados."
      }
      if ("nested_apk_in_assets" in indicators || "nested_jar_payload" in indicators) {
        score += 55
        forceBlock = true
        findings +=
          "Arquivo malicioso: pacote executável oculto (.APK/.JAR) escondido dentro das pastas internas."
      }
      if ("DexClassLoader" in indicators && "android.permission.INTERNET" in perms) {
        score += 25
        findings += "Carregamento dinâmico oculto de código (DexClassLoader) com conexão à internet."
      }
    }

    // 6. Manifest & Play Store vs Sideload Provenance Differentiation
    if (input.isDebuggableApp && !input.isSystemApp) {
      score += 25
      findings += "Flag android:debuggable ativa no manifesto"
    }

    if (input.targetSdk in 1..22 && !input.isSystemApp) {
      score += 35
      findings += "Target SDK legado (${input.targetSdk}) contorna permissões em tempo de execução"
    }

    if (isSideload && input.installerSource != "Inspeção Pré-Instalação") {
      score += 12
      findings += "Origem externa fora da Play Store (${input.installerSource}) — verificação reforçada"
    }

    if (input.settings.strictSideloadBlocking && isSideload && input.certificateTrustStatus != TrustStatus.TRUSTED) {
      score += 45
      forceBlock = true
      findings += "Bloqueio estrito ativo para apps instalados fora da Google Play Store"
    }

    // 7. Behavioral anomalies passed in
    if (input.behavioralAnomalyScore > 0) {
      score += input.behavioralAnomalyScore
      findings.addAll(input.behavioralFindings)
    }

    // 8. Explicit user allowlist mitigates non-critical risk (unless mismatch, blocked, or catalog/accessibility critical)
    if (
      input.certificateTrustStatus == TrustStatus.TRUSTED &&
        !signatureMismatch &&
        input.signature.hasSignature &&
        matchedCatalogEntry == null
    ) {
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

    // Add clear provenance differentiation when a Play Store app still raises alerts
    if (isPlayStoreApp && verdict != SecurityVerdict.SEGURO) {
      findings +=
        "Origem oficial (Google Play Store): alerta gerado por comportamento ou abuso de permissão detectado após a análise."
    }

    val threatCategory =
      when {
        matchedCatalogEntry?.threatType == ThreatType.VIRUS.name ||
          (hasAccessibilityAbuse && (hasSms || hasOverlay || input.isAccessibilityServiceEnabled)) ->
          ThreatClassification.VIRUS_TROJAN
        matchedCatalogEntry?.threatType == ThreatType.ARQUIVO_MALICIOSO.name ||
          "nested_apk_in_assets" in input.staticIndicators ||
          "nested_jar_payload" in input.staticIndicators ||
          !input.signature.hasSignature ||
          signatureMismatch ->
          ThreatClassification.ARQUIVO_MALICIOSO
        matchedCatalogEntry?.threatType == ThreatType.SPYWARE.name ||
          (hasPermissionAbuse && (hasMic || hasSms)) ->
          ThreatClassification.SPYWARE
        matchedCatalogEntry?.threatType == ThreatType.ADWARE.name ->
          ThreatClassification.ADWARE
        hasHiddenCommunication ->
          ThreatClassification.COMUNICACAO_OCULTA
        hasAccessibilityAbuse ->
          ThreatClassification.ACESSIBILIDADE
        hasPermissionAbuse ->
          ThreatClassification.ABUSO_PERMISSAO
        verdict != SecurityVerdict.SEGURO ->
          ThreatClassification.ARQUIVO_MALICIOSO
        else ->
          ThreatClassification.SEGURO
      }

    if (findings.isEmpty()) {
      findings +=
        if (isPlayStoreApp) {
          "App oficial da Google Play Store com assinatura íntegra e sem abusos detectados"
        } else {
          "Assinatura digital íntegra e perfil de permissões dentro do padrão esperado"
        }
    }

    return RiskAssessmentResult(
      verdict = verdict,
      riskScore = clampedScore,
      signatureMismatch = signatureMismatch,
      dangerousPermissions = dangerousMatched,
      findings = findings.distinct(),
      threatCategory = threatCategory,
      isPlayStoreApp = isPlayStoreApp,
      hasAccessibilityAbuse = hasAccessibilityAbuse,
      hasPermissionAbuse = hasPermissionAbuse,
      hasHiddenCommunication = hasHiddenCommunication,
      matchedThreatName = matchedCatalogEntry?.name.orEmpty(),
    )
  }

  private fun formatBytesCompact(bytes: Long): String {
    val mb = bytes / (1024.0 * 1024.0)
    return if (mb >= 1.0) String.format(Locale.US, "%.1f MB", mb) else "${bytes / 1024L} KB"
  }
}
