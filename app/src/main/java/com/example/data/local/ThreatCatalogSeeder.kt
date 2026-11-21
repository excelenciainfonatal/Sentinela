package com.example.data.local

object ThreatCatalogSeeder {

  fun defaultCatalogEntries(): List<ThreatCatalogEntity> =
    listOf(
      // --- VÍRUS / TROJANS BANCÁRIOS ---
      ThreatCatalogEntity(
        threatKey = "VIRUS_ANATSA_BANKER",
        name = "Anatsa / TeaBot (Trojan Bancário)",
        threatType = ThreatType.VIRUS.name,
        severityScore = 95,
        packagePatterns = "com.anatsa,com.teabot,com.pdf.reader.update.pro,com.cleaner.boost.anatsa",
        sha256Signatures = "6A:1F:9E:4B:3C:8D:22:10:AA:55:F1:98:21:44:7B:C0:DE:AD:BE:EF:01:23:45:67:89:AB:CD:EF:11:22:33:44",
        permissionSignature = "BIND_ACCESSIBILITY_SERVICE,SYSTEM_ALERT_WINDOW,RECEIVE_SMS,INTERNET",
        indicatorTokens = "DexClassLoader,accessibility_auto_click,overlay_bank_login",
        descriptionPt =
          "Trojan bancário que usa o menu de Acessibilidade para ler sua senha na tela e clicar em botões para transferir dinheiro sozinho.",
        recommendationPt =
          "Desative a Acessibilidade deste app nas configurações do celular e desinstale imediatamente.",
        sourceReference = "Catálogo Sentinela • Trojan Bancário",
      ),
      ThreatCatalogEntity(
        threatKey = "VIRUS_FLUBOT_SMS",
        name = "FluBot / FakeDelivery",
        threatType = ThreatType.VIRUS.name,
        severityScore = 92,
        packagePatterns = "com.flubot,com.correios.rastreio.apk,com.dhl.tracking.fake,com.fedex.delivery.update",
        sha256Signatures = "7B:2E:8C:11:90:FA:32:45:66:77:88:99:00:AA:BB:CC:DD:EE:FF:10:20:30:40:50:60:70:80:90:A1:B2:C3:D4",
        permissionSignature = "BIND_ACCESSIBILITY_SERVICE,READ_SMS,SEND_SMS,READ_CONTACTS,INTERNET",
        indicatorTokens = "sendMultipartTextMessage,dga_domain_c2,upload_contacts_sms",
        descriptionPt =
          "Vírus espalhado por links falsos de entrega. Rouba sua lista de contatos, lê códigos de SMS bancários e envia mensagens falsas para seus amigos.",
        recommendationPt =
          "Não instale apps recebidos por SMS. Remova o aplicativo e troque suas senhas de banco.",
        sourceReference = "Catálogo Sentinela • Trojan SMS",
      ),
      ThreatCatalogEntity(
        threatKey = "VIRUS_SHARKBOT_ATS",
        name = "SharkBot / Cerberus ATS",
        threatType = ThreatType.VIRUS.name,
        severityScore = 94,
        packagePatterns = "com.sharkbot,com.cerberus.rat,com.antivirus.super.clean.apk,com.bank.security.update",
        sha256Signatures = "8C:3D:7A:54:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:12:34:56:78",
        permissionSignature = "BIND_ACCESSIBILITY_SERVICE,REQUEST_INSTALL_PACKAGES,SYSTEM_ALERT_WINDOW,INTERNET",
        indicatorTokens = "performGlobalAction,AccessibilityNodeInfo,ats_transfer_bot",
        descriptionPt =
          "Vírus que se disfarça de antivírus ou atualização de segurança para assumir o controle dos cliques na tela e realizar transferências automáticas.",
        recommendationPt =
          "Remova o acesso em Acessibilidade e Administrador do Dispositivo e desinstale o pacote.",
        sourceReference = "Catálogo Sentinela • Trojan ATS",
      ),
      ThreatCatalogEntity(
        threatKey = "VIRUS_HOOK_BRAT",
        name = "Hook / Ermac Remote Control",
        threatType = ThreatType.VIRUS.name,
        severityScore = 96,
        packagePatterns = "com.ermac.bot,com.hook.rat,com.system.update.service.fake",
        sha256Signatures = "9D:4E:6F:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD",
        permissionSignature = "BIND_ACCESSIBILITY_SERVICE,BIND_DEVICE_ADMIN,READ_SMS,INTERNET",
        indicatorTokens = "vnc_screen_stream,keylogger_accessibility,websocket_c2",
        descriptionPt =
          "Vírus de controle remoto que captura tudo o que você digita na tela e impede a desinstalação usando permissão de Administrador.",
        recommendationPt =
          "Revogue Administrador do Dispositivo em Segurança > Apps administradores e desinstale.",
        sourceReference = "Catálogo Sentinela • Controle Remoto",
      ),
      ThreatCatalogEntity(
        threatKey = "VIRUS_BRASILEIRO_PIX",
        name = "PixPirate / Brasileirão Trojan",
        threatType = ThreatType.VIRUS.name,
        severityScore = 97,
        packagePatterns = "com.pixpirate,com.brasileiro.pix.fake,com.receita.federal.app.apk,com.auxilio.update.apk",
        sha256Signatures = "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:12:34:56:78:9A:BC:DE:F0:11:22:33:44:55:66:77:88",
        permissionSignature = "BIND_ACCESSIBILITY_SERVICE,SYSTEM_ALERT_WINDOW,QUERY_ALL_PACKAGES,INTERNET",
        indicatorTokens = "br.com.banco,pix_chave_replace,hide_launcher_icon",
        descriptionPt =
          "Vírus bancário focado em interceptar transferências Pix substituindo a chave ou valor usando Acessibilidade.",
        recommendationPt =
          "Bloqueie imediatamente e confira seu extrato bancário em outro aparelho confiável.",
        sourceReference = "Catálogo Sentinela • Fraude Pix",
      ),
      ThreatCatalogEntity(
        threatKey = "VIRUS_XHELPER_PERSIST",
        name = "xHelper Trojan Persistente",
        threatType = ThreatType.VIRUS.name,
        severityScore = 88,
        packagePatterns = "com.mufc.fire,com.xhelper.service,com.system.helper.daemon",
        sha256Signatures = "",
        permissionSignature = "REQUEST_INSTALL_PACKAGES,RECEIVE_BOOT_COMPLETED,INTERNET",
        indicatorTokens = "su_binary_exec,reinstall_self_daemon,DexClassLoader",
        descriptionPt =
          "Trojan persistente que se reinicia junto com o aparelho e baixa outros programas indesejados escondido.",
        recommendationPt =
          "Desinstale o app e remova arquivos APK estranhos da pasta Downloads.",
        sourceReference = "Catálogo Sentinela • Trojan Persistente",
      ),

      // --- SPYWARES ---
      ThreatCatalogEntity(
        threatKey = "SPYWARE_JOKER_BREAD",
        name = "Joker / Bread (Spyware de SMS e Cobrança)",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 84,
        packagePatterns = "com.joker.bread,com.color.message.emoji.fake,com.beauty.camera.joker,com.fast.scanner.joker",
        sha256Signatures = "B2:C3:D4:E5:F6:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:99:88:77:66",
        permissionSignature = "READ_SMS,RECEIVE_SMS,READ_CONTACTS,INTERNET",
        indicatorTokens = "wap_billing_subscribe,steal_sms_otp,hidden_webview_click",
        descriptionPt =
          "Spyware famoso que entra até disfarçado em apps simples da loja para roubar SMS, contatos e assinar serviços pagos sem você ver.",
        recommendationPt =
          "Desinstale imediatamente e verifique se há cobranças desconhecidas na sua fatura ou operadora.",
        sourceReference = "Catálogo Sentinela • Spyware",
      ),
      ThreatCatalogEntity(
        threatKey = "SPYWARE_SPINOK_SDK",
        name = "SpinOk / Exfiltração Silenciosa",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 78,
        packagePatterns = "com.spinok.sdk,com.lucky.wheel.reward,com.video.editor.spinok",
        sha256Signatures = "",
        permissionSignature = "READ_EXTERNAL_STORAGE,ACCESS_FINE_LOCATION,INTERNET",
        indicatorTokens = "upload_clipboard_silent,list_device_files_c2,api.telegram.org/bot",
        descriptionPt =
          "Módulo espião que envia arquivos do celular, localização e texto copiado (Ctrl+C) silenciosamente para servidores externos.",
        recommendationPt =
          "Remova o aplicativo caso não seja essencial e nunca copie senhas com ele instalado.",
        sourceReference = "Catálogo Sentinela • Spyware SDK",
      ),
      ThreatCatalogEntity(
        threatKey = "SPYWARE_SPYNOTE_RAT",
        name = "SpyNote / CypherRAT",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 95,
        packagePatterns = "com.spynote,com.cypherrat,com.android.rat.client,com.camera.spy.remote",
        sha256Signatures = "C3:D4:E5:F6:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:12:34:56:78:9A:BC:DE:F0:00:11:22:33",
        permissionSignature = "RECORD_AUDIO,CAMERA,READ_CALL_LOG,ACCESS_FINE_LOCATION,READ_SMS,INTERNET",
        indicatorTokens = "AudioRecord_bg,Camera2_silent,shell_reverse_tcp",
        descriptionPt =
          "Programa espião completo capaz de gravar áudio do microfone, tirar fotos escondido, ler chamadas e rastrear sua localização.",
        recommendationPt =
          "Desinstale imediatamente. Se não permitir desinstalar, remova privilégios de Administrador/Acessibilidade primeiro.",
        sourceReference = "Catálogo Sentinela • Stalkerware / RAT",
      ),
      ThreatCatalogEntity(
        threatKey = "SPYWARE_FACESTEALER",
        name = "FaceStealer / Roubo de Login Social",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 82,
        packagePatterns = "com.facestealer,com.cartoon.photo.editor.fake,com.horoscope.daily.stealer",
        sha256Signatures = "",
        permissionSignature = "INTERNET,ACCESS_NETWORK_STATE",
        indicatorTokens = "facebook_cookie_steal,inject_js_login_form,discord.com/api/webhooks",
        descriptionPt =
          "Disfarça-se de editor de fotos ou filtro divertido e pede login em rede social para roubar seus cookies e senha da conta.",
        recommendationPt =
          "Desinstale e altere a senha das redes sociais que você conectou neste app.",
        sourceReference = "Catálogo Sentinela • Phishing / Spyware",
      ),
      ThreatCatalogEntity(
        threatKey = "SPYWARE_UTILITY_MIC_SMS",
        name = "Utilitário Espião (Lanterna/Calculadora com SMS e Áudio)",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 76,
        packagePatterns = "com.flashlight.sms.pro,com.calculator.vault.spy,com.torch.recorder.bg",
        sha256Signatures = "",
        permissionSignature = "RECORD_AUDIO,READ_SMS,READ_CONTACTS,INTERNET",
        indicatorTokens = "silent_mic_capture,contact_harvest_bg",
        descriptionPt =
          "App utilitário simples que abusa de permissões para ler suas mensagens SMS, copiar contatos ou gravar áudio em segundo plano.",
        recommendationPt =
          "Use apenas lanterna e calculadora nativas do sistema; desinstale este app.",
        sourceReference = "Catálogo Sentinela • Abuso Utilitário",
      ),
      ThreatCatalogEntity(
        threatKey = "SPYWARE_RATMILAD",
        name = "RatMilad Espião Corporativo",
        threatType = ThreatType.SPYWARE.name,
        severityScore = 90,
        packagePatterns = "com.ratmilad,com.numverify.fake,com.virtual.number.app",
        sha256Signatures = "",
        permissionSignature = "READ_CONTACTS,READ_CALL_LOG,RECORD_AUDIO,ACCESS_FINE_LOCATION,READ_SMS",
        indicatorTokens = "telegram_bot_c2,upload_mic_wav,mac_address_exfil",
        descriptionPt =
          "Spyware disfarçado de gerador de número virtual que envia gravações de voz e contatos para bots externos.",
        recommendationPt =
          "Desinstale e revogue todas as permissões sensíveis.",
        sourceReference = "Catálogo Sentinela • Spyware",
      ),

      // --- ADWARES ---
      ThreatCatalogEntity(
        threatKey = "ADWARE_HIDDENADS",
        name = "HiddenAds / Pop-Up Invisível",
        threatType = ThreatType.ADWARE.name,
        severityScore = 62,
        packagePatterns = "com.hiddenads,com.super.wallpaper.hd.ads,com.qr.barcode.popads,com.pdf.viewer.popup",
        sha256Signatures = "",
        permissionSignature = "SYSTEM_ALERT_WINDOW,RECEIVE_BOOT_COMPLETED,INTERNET",
        indicatorTokens = "hide_app_icon_alias,out_of_app_interstitial,popup_loop_service",
        descriptionPt =
          "Adware que esconde o próprio ícone da tela inicial e exibe propagandas invasivas por cima de outros aplicativos mesmo com a tela ociosa.",
        recommendationPt =
          "Desinstale o app pelas Configurações > Aplicativos do Android e desative 'Exibir sobre outros apps'.",
        sourceReference = "Catálogo Sentinela • Adware",
      ),
      ThreatCatalogEntity(
        threatKey = "ADWARE_GHOSTCLICKER",
        name = "GhostClicker / Fraude de Cliques",
        threatType = ThreatType.ADWARE.name,
        severityScore = 68,
        packagePatterns = "com.ghostclicker,com.battery.saver.ultra.ads,com.ram.cleaner.boost.ad",
        sha256Signatures = "",
        permissionSignature = "SYSTEM_ALERT_WINDOW,INTERNET,WAKE_LOCK",
        indicatorTokens = "auto_click_ad_banner,hidden_webview_ads,rapid_activity_launch",
        descriptionPt =
          "Finge limpar memória ou economizar bateria, mas abre páginas ocultas em segundo plano consumindo seus dados móveis e bateria.",
        recommendationPt =
          "Desinstale aplicativos falsos de limpeza ou economia de bateria.",
        sourceReference = "Catálogo Sentinela • Adware Oculto",
      ),
      ThreatCatalogEntity(
        threatKey = "ADWARE_TRIADA_MOD",
        name = "Triada (Injetado em APKs Modificados)",
        threatType = ThreatType.ADWARE.name,
        severityScore = 80,
        packagePatterns = "com.triada.sdk,com.whatsapp.gb.mod.triada,com.fmwhatsapp.ads",
        sha256Signatures = "",
        permissionSignature = "REQUEST_INSTALL_PACKAGES,SYSTEM_ALERT_WINDOW,READ_SMS,INTERNET",
        indicatorTokens = "libtriada.so,DexClassLoader,silent_apk_download",
        descriptionPt =
          "Código malicioso frequentemente escondido em versões modificadas ('Mods') de apps populares para exibir anúncios e baixar payloads.",
        recommendationPt =
          "Substitua versões modificadas pelos aplicativos oficiais da loja.",
        sourceReference = "Catálogo Sentinela • Adware / Trojan",
      ),
      ThreatCatalogEntity(
        threatKey = "ADWARE_MOBIDASH",
        name = "MobiDash Pop-Up Engine",
        threatType = ThreatType.ADWARE.name,
        severityScore = 56,
        packagePatterns = "com.mobidash,com.ringtone.maker.ads.bg,com.flash.led.alert.ads",
        sha256Signatures = "",
        permissionSignature = "RECEIVE_BOOT_COMPLETED,SYSTEM_ALERT_WINDOW,INTERNET",
        indicatorTokens = "ad_banner_outside_app,boot_ad_trigger",
        descriptionPt =
          "Exibe anúncios em tela cheia fora do aplicativo assim que você desbloqueia o celular.",
        recommendationPt =
          "Remova o aplicativo suspeito caso esteja vendo propagandas fora de hora.",
        sourceReference = "Catálogo Sentinela • Adware",
      ),

      // --- ARQUIVOS MALICIOSOS / DROPPERS / PAYLOADS ---
      ThreatCatalogEntity(
        threatKey = "FILE_MALICIOUS_DROPPER_APK",
        name = "Dropper com APK Oculto em Assets",
        threatType = ThreatType.ARQUIVO_MALICIOSO.name,
        severityScore = 90,
        packagePatterns = "com.dropper.installer,com.update.patch.apk,com.game.mod.installer",
        sha256Signatures = "D4:E5:F6:01:12:23:34:45:56:67:78:89:9A:AB:BC:CD:DE:EF:F0:01:12:23:34:45:56:67:78:89:9A:AB:BC:CD",
        permissionSignature = "REQUEST_INSTALL_PACKAGES,INTERNET",
        indicatorTokens = "nested_apk_in_assets,nested_jar_payload,DexClassLoader",
        descriptionPt =
          "Arquivo instalador falso que esconde outro aplicativo malicioso (.APK ou .DEX) dentro da própria pasta interna para burlar verificações.",
        recommendationPt =
          "Não instale este arquivo .APK e apague-o do gerenciador de arquivos.",
        sourceReference = "Catálogo Sentinela • Arquivo Malicioso",
      ),
      ThreatCatalogEntity(
        threatKey = "FILE_UNSIGNED_DEBUG_MOD",
        name = "APK Adulterado / Assinatura Debug Suspeita",
        threatType = ThreatType.ARQUIVO_MALICIOSO.name,
        severityScore = 75,
        packagePatterns = "com.whatsapp.plus.unsigned,com.spotify.premium.cracked,com.instagram.aero.fake",
        sha256Signatures = "E5:F6:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E",
        permissionSignature = "INTERNET,READ_CONTACTS,READ_EXTERNAL_STORAGE",
        indicatorTokens = "testkey_debug_cert,signature_mismatch_official",
        descriptionPt =
          "Arquivo modificado fora da loja oficial com certificado de teste ou divergente do desenvolvedor original — alto risco de código injetado.",
        recommendationPt =
          "Instale sempre o aplicativo oficial pela Google Play Store.",
        sourceReference = "Catálogo Sentinela • APK Modificado",
      ),
      ThreatCatalogEntity(
        threatKey = "FILE_RAW_IP_C2_PAYLOAD",
        name = "Arquivo com Servidor Externo Oculto (IP Direto / Tor)",
        threatType = ThreatType.ARQUIVO_MALICIOSO.name,
        severityScore = 82,
        packagePatterns = "com.payload.c2,com.remote.shell.apk",
        sha256Signatures = "",
        permissionSignature = "INTERNET,RECEIVE_BOOT_COMPLETED",
        indicatorTokens = "raw_ip_http_endpoint,onion_tor_c2,api.telegram.org/bot",
        descriptionPt =
          "Contém endereços diretos de servidor desconhecido ou rede oculta embutidos no código para enviar dados sem autorização.",
        recommendationPt =
          "Bloqueie a instalação e remova o arquivo imediatamente.",
        sourceReference = "Catálogo Sentinela • Comunicação Oculta",
      ),
      ThreatCatalogEntity(
        threatKey = "FILE_EMPTY_NO_DEX_SHELL",
        name = "Pacote APK Corrompido ou Carregador Nativo Oculto",
        threatType = ThreatType.ARQUIVO_MALICIOSO.name,
        severityScore = 70,
        packagePatterns = "com.empty.loader.apk,com.native.dropper",
        sha256Signatures = "",
        permissionSignature = "INTERNET",
        indicatorTokens = "missing_classes_dex,encrypted_so_payload",
        descriptionPt =
          "Arquivo incomum sem código DEX padrão ou com bibliotecas nativas ocultas usadas para carregar código externo na memória.",
        recommendationPt =
          "Evite instalar arquivos .APK com estrutura fora do padrão oficial.",
        sourceReference = "Catálogo Sentinela • Estrutura Maliciosa",
      ),
    )
}
