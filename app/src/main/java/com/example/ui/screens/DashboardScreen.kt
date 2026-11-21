package com.example.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.ui.CloudSyncUiState
import com.example.ui.SentinelaUiState
import com.example.ui.components.ThreatSignalBadgesRow
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.friendlyInstallerSource

@Composable
fun DashboardScreen(
  uiState: SentinelaUiState,
  cloudSyncState: CloudSyncUiState,
  onPickApk: () -> Unit,
  onScanNow: () -> Unit,
  onUpdateAntivirusNow: () -> Unit,
  onToggleAutoAntivirusUpdates: (Boolean) -> Unit,
  onSyncCloud: () -> Unit,
  onRestoreCloud: () -> Unit,
  onToggleCloudAutoSync: (Boolean) -> Unit,
  onSignOut: () -> Unit,
  onToggleMonitor: (Boolean) -> Unit,
  onTogglePushAlerts: (Boolean) -> Unit,
  onTestPushAlert: () -> Unit,
  onToggleDebugCerts: (Boolean) -> Unit,
  onToggleSigMismatch: (Boolean) -> Unit,
  onToggleHighRiskPerms: (Boolean) -> Unit,
  onToggleStrictSideload: (Boolean) -> Unit,
  onOpenUsageSettings: () -> Unit,
  onRequestNotificationPermission: () -> Unit,
  onOpenAuditDetail: (Long, String) -> Unit,
  onNavigateToCatalog: (AppsCatalogFilter) -> Unit,
  onNavigateToGatekeeper: () -> Unit,
  onNavigateToBehavior: () -> Unit,
  onNavigateToSignatures: (alertsOnly: Boolean) -> Unit,
  onNavigateToHistory: () -> Unit,
  onNavigateToWhitelist: () -> Unit,
  onNavigateToThreatCatalog: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val listState = rememberLazyListState()
  var showAdvancedSettings by rememberSaveable { mutableStateOf(false) }

  val stats = uiState.threatStats
  val blockedCount = stats.blockedCount
  val suspiciousCount = stats.suspiciousCount
  val authorizedCount =
    remember(uiState.installedApps, uiState.whitelistedPackageNames, uiState.certificateSummaries) {
      val trustedShas =
        uiState.certificateSummaries
          .filter { it.trustStatus == TrustStatus.TRUSTED }
          .map { it.sha256 }
          .toSet()
      uiState.installedApps.count {
        it.packageName in uiState.whitelistedPackageNames ||
          it.sha256Fingerprint in trustedShas ||
          it.verdict == SecurityVerdict.SEGURO.name
      }
    }
  val protectionScore =
    remember(stats.totalAppsAudited, blockedCount, suspiciousCount, uiState.settings.realTimeMonitorEnabled) {
      val base =
        100 -
          (blockedCount * 22) -
          (suspiciousCount * 7) -
          (if (!uiState.settings.realTimeMonitorEnabled) 12 else 0)
      base.coerceIn(10, 100)
    }
  val flaggedApps =
    remember(uiState.apkAudits, uiState.installedApps) {
      (uiState.apkAudits + uiState.installedApps)
        .filter { it.verdict != SecurityVerdict.SEGURO.name }
        .sortedByDescending { it.riskScore }
    }

  Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    LazyColumn(
      state = listState,
      modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
      contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
      verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
      // 1. Real-Time Security Status Hero Card with 'Sistema Protegido' Badge
      item(key = "dash_hero") {
        HeroProtectionCard(
          monitorActive = uiState.settings.realTimeMonitorEnabled,
          serviceRunning = uiState.serviceTelemetry.isServiceRunning,
          verifiedInSession = uiState.serviceTelemetry.packagesVerifiedInSession,
          protectionScore = protectionScore,
          blockedCount = blockedCount,
          suspiciousCount = suspiciousCount,
          lastScanTimestamp = stats.lastScanTimestamp,
          isScanning = uiState.isScanningDevice,
          onPickApk = onPickApk,
          onScanNow = onScanNow,
        )
      }

      // 2. Primary Summary Cards: 'Apps Analisados' & 'Ameaças Bloqueadas'
      item(key = "dash_summary_cards") {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Resumo de Segurança",
              style = MaterialTheme.typography.titleLarge,
            )
            TextButton(
              onClick = { onNavigateToCatalog(AppsCatalogFilter.TODOS) },
              modifier = Modifier.testTag("dashboard_view_all_apps_btn"),
            ) {
              Text("Ver todos")
            }
          }

          Row(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            SummaryMetricCard(
              title = "Apps Analisados",
              value = "${stats.totalAppsAudited}",
              subtitle = "$authorizedCount seguro(s)",
              icon = Icons.Filled.Security,
              accent = MaterialTheme.colorScheme.primary,
              containerColor = MaterialTheme.colorScheme.surfaceContainer,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.TODOS) },
              modifier = Modifier.weight(1f).testTag("summary_card_apps_analyzed"),
            )
            SummaryMetricCard(
              title = "Ameaças Bloqueadas",
              value = "$blockedCount",
              subtitle = if (blockedCount > 0) "Toque para revisar" else "Nenhuma ameaça",
              icon = Icons.Filled.GppBad,
              accent =
                if (blockedCount > 0) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.secondary,
              containerColor = MaterialTheme.colorScheme.surfaceContainer,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.BLOQUEADOS) },
              modifier = Modifier.weight(1f).testTag("summary_card_threats_blocked"),
            )
          }

          // Clean secondary row for Attention, Whitelist & History
          Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            CompactCategoryTile(
              title = "Em Atenção",
              value = "$suspiciousCount",
              icon = Icons.Filled.Warning,
              accent =
                if (suspiciousCount > 0) MaterialTheme.colorScheme.tertiary
                else MaterialTheme.colorScheme.onSurfaceVariant,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.SUSPEITOS) },
              modifier = Modifier.weight(1f).testTag("dashboard_btn_suspicious"),
            )
            CompactCategoryTile(
              title = "Confiáveis",
              value = "${uiState.whitelistedApps.size}",
              icon = Icons.Filled.CheckCircle,
              accent = MaterialTheme.colorScheme.secondary,
              onClick = onNavigateToWhitelist,
              modifier = Modifier.weight(1f).testTag("dashboard_whitelist_card"),
            )
            CompactCategoryTile(
              title = "Histórico",
              value = "${uiState.scanHistory.size}",
              icon = Icons.Filled.History,
              accent = MaterialTheme.colorScheme.primary,
              onClick = onNavigateToHistory,
              modifier = Modifier.weight(1f).testTag("dashboard_history_card"),
            )
          }

          // Deep Threat Analysis & Play Store Differentiation Card
          DeepDetectionOverviewCard(
            playStoreFlaggedCount = stats.playStoreFlaggedCount,
            externalFlaggedCount = stats.externalFlaggedCount,
            permissionAbuseCount = stats.permissionAbuseCount,
            accessibilityRiskCount = stats.accessibilityRiskCount,
            hiddenCommCount = stats.hiddenCommCount,
            catalogEntriesCount = uiState.threatCatalog.size,
            onFilterPlayStoreAlerts = { onNavigateToCatalog(AppsCatalogFilter.PLAY_STORE_ALERTAS) },
            onFilterExternal = { onNavigateToCatalog(AppsCatalogFilter.EXTERNOS) },
            onFilterAccessibility = { onNavigateToCatalog(AppsCatalogFilter.ACESSIBILIDADE) },
            onFilterHiddenComm = { onNavigateToCatalog(AppsCatalogFilter.COMUNICACAO_OCULTA) },
            onOpenThreatCatalog = onNavigateToThreatCatalog,
          )
        }
      }

      // 2b. Trusted Google Server Antivirus Updates Card
      item(key = "dash_antivirus_updates") {
        AntivirusUpdatesCard(
          catalogCount = uiState.threatCatalog.size,
          isUpdating = uiState.isUpdatingAntivirus,
          autoUpdateEnabled = uiState.settings.autoAntivirusUpdatesEnabled,
          lastUpdateAt = uiState.settings.lastAntivirusUpdateAt,
          versionLabel = uiState.settings.lastAntivirusUpdateVersion,
          statusMessage = uiState.settings.lastAntivirusUpdateStatus,
          sourceLabel = uiState.settings.lastAntivirusUpdateSource,
          providerVerified = uiState.settings.lastAntivirusProviderVerified,
          hadError = uiState.settings.lastAntivirusUpdateHadError,
          onToggleAutoUpdate = onToggleAutoAntivirusUpdates,
          onManualUpdate = onUpdateAntivirusNow,
          onOpenThreatCatalog = onNavigateToThreatCatalog,
        )
      }

      // 3. Flagged Apps Needing Attention
      if (flaggedApps.isNotEmpty()) {
        item(key = "dash_flagged_header") {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Apps que merecem atenção",
              style = MaterialTheme.typography.titleLarge,
            )
            TextButton(onClick = { onNavigateToCatalog(AppsCatalogFilter.BLOQUEADOS) }) {
              Text("Ver lista")
            }
          }
        }
        items(flaggedApps.take(3), key = { "flagged_${it.id}" }) { audit ->
          val verdict =
            remember(audit.verdict) {
              runCatching { SecurityVerdict.valueOf(audit.verdict) }.getOrDefault(SecurityVerdict.SUSPEITO)
            }
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            shape = MaterialTheme.shapes.large,
            modifier =
              Modifier.fillMaxWidth()
                .clickable { onOpenAuditDetail(audit.id, audit.packageName) }
                .testTag("flagged_audit_${audit.packageName}"),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(16.dp),
            ) {
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = audit.appName,
                  style = MaterialTheme.typography.titleMedium,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                  text =
                    friendlyInstallerSource(
                      audit.installerSource,
                      audit.isSystemApp,
                      audit.sourceType,
                    ),
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(6.dp))
                ThreatSignalBadgesRow(audit = audit)
                Spacer(Modifier.height(6.dp))
                Text(
                  text = audit.findingsSummary.lineSequence().firstOrNull()?.removePrefix("• ") ?: "",
                  style = MaterialTheme.typography.bodyMedium,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                  maxLines = 2,
                  overflow = TextOverflow.Ellipsis,
                )
              }
              Spacer(Modifier.width(12.dp))
              VerdictBadge(verdict)
            }
          }
        }
      }

      // 4. Real-Time Automatic Protection Card
      item(key = "dash_realtime_card") {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          shape = MaterialTheme.shapes.large,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Surface(
                color =
                  if (uiState.settings.realTimeMonitorEnabled)
                    MaterialTheme.colorScheme.secondaryContainer
                  else MaterialTheme.colorScheme.surfaceContainerHigh,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.size(44.dp),
              ) {
                Box(contentAlignment = Alignment.Center) {
                  Icon(
                    imageVector = Icons.Filled.Shield,
                    contentDescription = "Proteção automática",
                    tint =
                      if (uiState.settings.realTimeMonitorEnabled)
                        MaterialTheme.colorScheme.secondary
                      else MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
              }
              Spacer(Modifier.width(12.dp))
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = "Proteção em Tempo Real",
                  style = MaterialTheme.typography.titleMedium,
                )
                Text(
                  text =
                    if (uiState.settings.realTimeMonitorEnabled)
                      "Verifica novos aplicativos automaticamente ao instalar."
                    else
                      "Ative para proteger seu celular em segundo plano.",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
              Spacer(Modifier.width(8.dp))
              Switch(
                checked = uiState.settings.realTimeMonitorEnabled,
                onCheckedChange = onToggleMonitor,
                modifier = Modifier.testTag("switch_realtime_monitor"),
              )
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            PolicySwitchRow(
              title = "Notificações imediatas de ameaças",
              subtitle = "Mostra alertas na hora com atalhos para Desinstalar ou Bloquear",
              checked = uiState.settings.pushAlertsEnabled,
              onCheckedChange = onTogglePushAlerts,
              testTag = "switch_push_alerts",
            )

            AnimatedVisibility(
              visible = !uiState.notificationPermissionGranted || !uiState.usageAccessGranted
            ) {
              Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                if (!uiState.notificationPermissionGranted) {
                  PermissionPromptRow(
                    icon = Icons.Filled.NotificationsActive,
                    title = "Permitir alertas no celular",
                    description = "Necessário para avisar você quando houver risco.",
                    actionLabel = "Permitir",
                    testTag = "grant_notification_button",
                    onClick = onRequestNotificationPermission,
                  )
                }
                if (!uiState.usageAccessGranted) {
                  PermissionPromptRow(
                    icon = Icons.Filled.AdminPanelSettings,
                    title = "Detectar comportamento estranho",
                    description = "Permite notar se um app escondido consumir recursos demais.",
                    actionLabel = "Ativar",
                    testTag = "grant_usage_access_button",
                    onClick = onOpenUsageSettings,
                  )
                }
              }
            }
          }
        }
      }

      // 5. Google Account & Cloud Backup Card
      item(key = "dash_cloud_sync") {
        CloudBackupCard(
          cloudState = cloudSyncState,
          onSyncNow = onSyncCloud,
          onRestoreNow = onRestoreCloud,
          onToggleAutoSync = onToggleCloudAutoSync,
          onSignOut = onSignOut,
        )
      }

      // 6. Collapsible Advanced Settings
      item(key = "dash_advanced_settings") {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          shape = MaterialTheme.shapes.large,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.fillMaxWidth()) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier =
                Modifier.fillMaxWidth()
                  .heightIn(min = 60.dp)
                  .clickable(role = Role.Button) { showAdvancedSettings = !showAdvancedSettings }
                  .padding(horizontal = 16.dp, vertical = 14.dp)
                  .testTag("dashboard_advanced_toggle"),
            ) {
              Surface(
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.size(40.dp),
              ) {
                Box(contentAlignment = Alignment.Center) {
                  Icon(
                    imageVector = Icons.Filled.Tune,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp),
                  )
                }
              }
              Spacer(Modifier.width(12.dp))
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = "Configurações avançadas",
                  style = MaterialTheme.typography.titleMedium,
                )
                Text(
                  text = "Regras de bloqueio, assinaturas e teste de alerta",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
              Icon(
                imageVector =
                  if (showAdvancedSettings) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = if (showAdvancedSettings) "Recolher" else "Expandir",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
              )
            }

            AnimatedVisibility(visible = showAdvancedSettings) {
              Column(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
              ) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                PolicySwitchRow(
                  title = "Alertar se um app parecer falsificado",
                  subtitle = "Detecta quando a assinatura digital não bate com a original",
                  checked = uiState.settings.blockSignatureMismatch,
                  onCheckedChange = onToggleSigMismatch,
                  testTag = "policy_sig_mismatch",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                PolicySwitchRow(
                  title = "Bloquear apps de teste não oficiais",
                  subtitle = "Impede aplicativos feitos com chaves temporárias de desenvolvedor",
                  checked = uiState.settings.blockDebugCerts,
                  onCheckedChange = onToggleDebugCerts,
                  testTag = "policy_debug_certs",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                PolicySwitchRow(
                  title = "Alertar sobre permissões arriscadas",
                  subtitle = "Identifica combinações comuns em golpes (tela + mensagens)",
                  checked = uiState.settings.blockHighRiskPermissions,
                  onCheckedChange = onToggleHighRiskPerms,
                  testTag = "policy_high_risk_perms",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                PolicySwitchRow(
                  title = "Rigidez extra fora da Play Store",
                  subtitle = "Sinaliza aplicativos baixados de sites desconhecidos",
                  checked = uiState.settings.strictSideloadBlocking,
                  onCheckedChange = onToggleStrictSideload,
                  testTag = "policy_strict_sideload",
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(Modifier.height(2.dp))

                OutlinedButton(
                  onClick = onTestPushAlert,
                  modifier = Modifier.fillMaxWidth().height(48.dp).testTag("test_push_alert_button"),
                ) {
                  Icon(
                    imageVector = Icons.Filled.NotificationsActive,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                  )
                  Spacer(Modifier.width(8.dp))
                  Text("Testar notificação de alerta")
                }

                Row(
                  horizontalArrangement = Arrangement.spacedBy(8.dp),
                  modifier = Modifier.fillMaxWidth(),
                ) {
                  OutlinedButton(
                    onClick = { onNavigateToSignatures(false) },
                    modifier = Modifier.weight(1f).height(48.dp).testTag("dashboard_btn_signatures"),
                  ) {
                    Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Assinaturas", maxLines = 1, overflow = TextOverflow.Ellipsis)
                  }
                  OutlinedButton(
                    onClick = onNavigateToBehavior,
                    modifier = Modifier.weight(1f).height(48.dp).testTag("dashboard_btn_behavior"),
                  ) {
                    Icon(Icons.Filled.Radar, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Atividade", maxLines = 1, overflow = TextOverflow.Ellipsis)
                  }
                }
              }
            }
          }
        }
      }

      item(key = "dash_bottom_spacer") { Spacer(Modifier.height(12.dp)) }
    }
  }
}

@Composable
private fun HeroProtectionCard(
  monitorActive: Boolean,
  serviceRunning: Boolean,
  verifiedInSession: Int,
  protectionScore: Int,
  blockedCount: Int,
  suspiciousCount: Int,
  lastScanTimestamp: Long,
  isScanning: Boolean,
  onPickApk: () -> Unit,
  onScanNow: () -> Unit,
) {
  val badgeLabel =
    when {
      blockedCount > 0 -> "Ameaça Detectada"
      suspiciousCount > 0 -> "Atenção Recomendada"
      monitorActive -> "Sistema Protegido"
      else -> "Proteção Pausada"
    }
  val headline =
    when {
      blockedCount > 0 -> "$blockedCount ameaça(s) bloqueada(s)"
      suspiciousCount > 0 -> "$suspiciousCount app(s) merecem atenção"
      monitorActive -> "Nenhuma ameaça ativa"
      else -> "Escudo em tempo real desligado"
    }
  val realTimeSubline =
    when {
      !monitorActive -> "Ative a proteção automática abaixo para monitorar instalações."
      serviceRunning && verifiedInSession > 0 ->
        "Tempo real ativo • $verifiedInSession verificação(ões) na sessão"
      serviceRunning -> "Monitoramento em tempo real ativo"
      else -> "Proteção em tempo real configurada"
    }
  val statusColor =
    when {
      blockedCount > 0 -> MaterialTheme.colorScheme.error
      suspiciousCount > 0 -> MaterialTheme.colorScheme.tertiary
      monitorActive -> MaterialTheme.colorScheme.secondary
      else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
  val badgeContainer =
    when {
      blockedCount > 0 -> MaterialTheme.colorScheme.errorContainer
      suspiciousCount > 0 -> MaterialTheme.colorScheme.tertiaryContainer
      monitorActive -> MaterialTheme.colorScheme.secondaryContainer
      else -> MaterialTheme.colorScheme.surfaceContainerHigh
    }
  val animatedScore by
    animateFloatAsState(
      targetValue = protectionScore / 100f,
      animationSpec = tween(durationMillis = 700),
      label = "hero_protection_score",
    )
  val bg = MaterialTheme.colorScheme.background
  val surfaceMid = MaterialTheme.colorScheme.surfaceContainer

  Card(
    shape = MaterialTheme.shapes.extraLarge,
    border =
      BorderStroke(
        width = 1.dp,
        brush =
          Brush.linearGradient(
            colors =
              listOf(
                statusColor.copy(alpha = 0.7f),
                MaterialTheme.colorScheme.primary.copy(alpha = 0.45f),
              )
          ),
      ),
    modifier = Modifier.fillMaxWidth(),
  ) {
    Box(modifier = Modifier.fillMaxWidth()) {
      Image(
        painter = painterResource(id = R.drawable.img_security_banner_1795109549664),
        contentDescription = "Escudo de proteção Sentinela",
        contentScale = ContentScale.Crop,
        modifier = Modifier.matchParentSize(),
      )
      Box(
        modifier =
          Modifier.matchParentSize()
            .background(
              Brush.verticalGradient(
                colors =
                  listOf(
                    bg.copy(alpha = 0.84f),
                    surfaceMid.copy(alpha = 0.92f),
                    bg.copy(alpha = 0.97f),
                  )
              )
            )
      )

      Column(modifier = Modifier.padding(20.dp)) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.SpaceBetween,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Surface(
            color = badgeContainer.copy(alpha = 0.92f),
            contentColor = statusColor,
            shape = RoundedCornerShape(50),
            border = BorderStroke(1.dp, statusColor.copy(alpha = 0.55f)),
            modifier = Modifier.testTag("device_security_status_badge"),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            ) {
              Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(statusColor))
              Spacer(Modifier.width(7.dp))
              Icon(
                imageVector =
                  when {
                    blockedCount > 0 -> Icons.Filled.GppBad
                    suspiciousCount > 0 -> Icons.Filled.Warning
                    else -> Icons.Filled.VerifiedUser
                  },
                contentDescription = badgeLabel,
                tint = statusColor,
                modifier = Modifier.size(16.dp),
              )
              Spacer(Modifier.width(6.dp))
              Text(
                text = badgeLabel,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = statusColor,
              )
            }
          }

          if (monitorActive) {
            Text(
              text = "TEMPO REAL",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.primary,
            )
          }
        }

        Spacer(Modifier.height(16.dp))

        Row(
          verticalAlignment = Alignment.CenterVertically,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Box(contentAlignment = Alignment.Center, modifier = Modifier.size(86.dp)) {
            val arcTrackColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.16f)
            Canvas(modifier = Modifier.fillMaxSize().padding(4.dp)) {
              val stroke = 7.dp.toPx()
              val d = size.minDimension
              val tl = Offset((size.width - d) / 2f, (size.height - d) / 2f)
              val sz = Size(d, d)
              drawArc(
                color = arcTrackColor,
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                topLeft = tl,
                size = sz,
                style = Stroke(width = stroke, cap = StrokeCap.Round),
              )
              drawArc(
                color = statusColor,
                startAngle = 135f,
                sweepAngle = 270f * animatedScore,
                useCenter = false,
                topLeft = tl,
                size = sz,
                style = Stroke(width = stroke, cap = StrokeCap.Round),
              )
            }
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
              Text(
                text = "$protectionScore%",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
              )
              Text(
                text = "Saúde",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
            }
          }

          Spacer(Modifier.width(16.dp))

          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = headline,
              style = MaterialTheme.typography.headlineSmall,
              color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.height(4.dp))
            Text(
              text = realTimeSubline,
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (lastScanTimestamp > 0L) {
              Spacer(Modifier.height(2.dp))
              Text(
                text = "Último scan: ${formatTimestampPt(lastScanTimestamp)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
              )
            }
          }
        }

        Spacer(Modifier.height(18.dp))

        Button(
          onClick = onScanNow,
          enabled = !isScanning,
          shape = RoundedCornerShape(14.dp),
          colors =
            ButtonDefaults.buttonColors(
              containerColor = MaterialTheme.colorScheme.primary,
              contentColor = MaterialTheme.colorScheme.onPrimary,
            ),
          modifier = Modifier.fillMaxWidth().height(52.dp).testTag("hero_scan_now_button"),
        ) {
          if (isScanning) {
            CircularProgressIndicator(
              strokeWidth = 2.dp,
              color = MaterialTheme.colorScheme.onPrimary,
              modifier = Modifier.size(18.dp),
            )
          } else {
            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
          }
          Spacer(Modifier.width(8.dp))
          Text(
            text = if (isScanning) "Verificando aplicativos..." else "Verificar Celular Agora",
            style = MaterialTheme.typography.titleSmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }

        Spacer(Modifier.height(10.dp))

        OutlinedButton(
          onClick = onPickApk,
          shape = RoundedCornerShape(14.dp),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
          colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.onSurface),
          modifier = Modifier.fillMaxWidth().height(48.dp).testTag("hero_pick_apk_button"),
        ) {
          Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
          Spacer(Modifier.width(8.dp))
          Text(
            text = "Analisar arquivo .APK antes de instalar",
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
      }
    }
  }
}

@Composable
private fun SummaryMetricCard(
  title: String,
  value: String,
  subtitle: String,
  icon: ImageVector,
  accent: Color,
  containerColor: Color,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = containerColor),
    border = BorderStroke(1.dp, accent.copy(alpha = 0.45f)),
    shape = MaterialTheme.shapes.large,
    modifier = modifier.clickable(role = Role.Button, onClick = onClick),
  ) {
    Column(modifier = Modifier.padding(16.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Surface(
          color = accent.copy(alpha = 0.16f),
          shape = RoundedCornerShape(12.dp),
          modifier = Modifier.size(38.dp),
        ) {
          Box(contentAlignment = Alignment.Center) {
            Icon(
              imageVector = icon,
              contentDescription = title,
              tint = accent,
              modifier = Modifier.size(20.dp),
            )
          }
        }
        Icon(
          imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
          contentDescription = "Abrir $title",
          tint = MaterialTheme.colorScheme.onSurfaceVariant,
          modifier = Modifier.size(18.dp),
        )
      }
      Spacer(Modifier.height(12.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.displaySmall,
        color = MaterialTheme.colorScheme.onSurface,
      )
      Spacer(Modifier.height(2.dp))
      Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurface,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
      Text(
        text = subtitle,
        style = MaterialTheme.typography.bodySmall,
        color = accent,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun CompactCategoryTile(
  title: String,
  value: String,
  icon: ImageVector,
  accent: Color,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    shape = MaterialTheme.shapes.medium,
    modifier = modifier.clickable(role = Role.Button, onClick = onClick),
  ) {
    Column(
      horizontalAlignment = Alignment.Start,
      modifier = Modifier.padding(12.dp),
    ) {
      Icon(
        imageVector = icon,
        contentDescription = title,
        tint = accent,
        modifier = Modifier.size(18.dp),
      )
      Spacer(Modifier.height(8.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.onSurface,
      )
      Text(
        text = title,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun PermissionPromptRow(
  icon: ImageVector,
  title: String,
  description: String,
  actionLabel: String,
  testTag: String,
  onClick: () -> Unit,
) {
  Row(
    verticalAlignment = Alignment.CenterVertically,
    modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
  ) {
    Icon(
      imageVector = icon,
      contentDescription = title,
      tint = MaterialTheme.colorScheme.tertiary,
      modifier = Modifier.size(22.dp),
    )
    Spacer(Modifier.width(10.dp))
    Column(modifier = Modifier.weight(1f)) {
      Text(text = title, style = MaterialTheme.typography.labelLarge)
      Text(
        text = description,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    Spacer(Modifier.width(8.dp))
    OutlinedButton(
      onClick = onClick,
      modifier = Modifier.height(48.dp).testTag(testTag),
    ) {
      Text(actionLabel)
    }
  }
}

@Composable
private fun PolicySwitchRow(
  title: String,
  subtitle: String,
  checked: Boolean,
  onCheckedChange: (Boolean) -> Unit,
  testTag: String,
) {
  Row(
    verticalAlignment = Alignment.CenterVertically,
    modifier =
      Modifier.fillMaxWidth()
        .clip(RoundedCornerShape(10.dp))
        .clickable { onCheckedChange(!checked) }
        .padding(vertical = 6.dp),
  ) {
    Column(modifier = Modifier.weight(1f)) {
      Text(text = title, style = MaterialTheme.typography.titleSmall)
      Text(
        text = subtitle,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
    Spacer(Modifier.width(12.dp))
    Switch(
      checked = checked,
      onCheckedChange = onCheckedChange,
      modifier = Modifier.testTag(testTag),
    )
  }
}

@Composable
private fun CloudBackupCard(
  cloudState: CloudSyncUiState,
  onSyncNow: () -> Unit,
  onRestoreNow: () -> Unit,
  onToggleAutoSync: (Boolean) -> Unit,
  onSignOut: () -> Unit,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth().testTag("cloud_sync_card"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
          Surface(
            color = MaterialTheme.colorScheme.primaryContainer,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.size(44.dp),
          ) {
            Box(contentAlignment = Alignment.Center) {
              Icon(
                imageVector = Icons.Filled.CloudSync,
                contentDescription = "Backup na conta Google",
                tint = MaterialTheme.colorScheme.primary,
              )
            }
          }
          Spacer(Modifier.width(12.dp))
          Column {
            Text(
              text = "Backup na Conta Google",
              style = MaterialTheme.typography.titleMedium,
            )
            Text(
              text =
                if (cloudState.email.isNotBlank()) cloudState.email
                else cloudState.displayName,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
        TextButton(
          onClick = onSignOut,
          modifier = Modifier.testTag("cloud_sign_out_button"),
        ) {
          Text("Conta")
        }
      }

      PolicySwitchRow(
        title = "Salvar automaticamente na nuvem",
        subtitle = "Mantém seus apps confiáveis salvos se você trocar de celular",
        checked = cloudState.autoSyncEnabled,
        onCheckedChange = onToggleAutoSync,
        testTag = "switch_cloud_auto_sync",
      )

      if (!cloudState.errorMessage.isNullOrBlank()) {
        Surface(
          color = MaterialTheme.colorScheme.errorContainer,
          shape = RoundedCornerShape(10.dp),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = cloudState.errorMessage,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
            modifier = Modifier.padding(10.dp),
          )
        }
      } else if (!cloudState.statusMessage.isNullOrBlank()) {
        Surface(
          color = MaterialTheme.colorScheme.secondaryContainer,
          shape = RoundedCornerShape(10.dp),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = cloudState.statusMessage,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.padding(10.dp),
          )
        }
      }

      Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Button(
          onClick = onSyncNow,
          enabled = !cloudState.isSyncing,
          shape = RoundedCornerShape(12.dp),
          modifier = Modifier.weight(1f).height(48.dp).testTag("cloud_sync_now_button"),
        ) {
          if (cloudState.isSyncing) {
            CircularProgressIndicator(
              strokeWidth = 2.dp,
              color = MaterialTheme.colorScheme.onPrimary,
              modifier = Modifier.size(16.dp),
            )
          } else {
            Icon(Icons.Filled.CloudUpload, contentDescription = null, modifier = Modifier.size(18.dp))
          }
          Spacer(Modifier.width(6.dp))
          Text("Salvar Agora", maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        OutlinedButton(
          onClick = onRestoreNow,
          enabled = !cloudState.isSyncing,
          shape = RoundedCornerShape(12.dp),
          modifier = Modifier.weight(1f).height(48.dp).testTag("cloud_restore_button"),
        ) {
          Icon(Icons.Filled.CloudDownload, contentDescription = null, modifier = Modifier.size(18.dp))
          Spacer(Modifier.width(6.dp))
          Text("Restaurar", maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
      }
    }
  }
}

@Composable
private fun DeepDetectionOverviewCard(
  playStoreFlaggedCount: Int,
  externalFlaggedCount: Int,
  permissionAbuseCount: Int,
  accessibilityRiskCount: Int,
  hiddenCommCount: Int,
  catalogEntriesCount: Int,
  onFilterPlayStoreAlerts: () -> Unit,
  onFilterExternal: () -> Unit,
  onFilterAccessibility: () -> Unit,
  onFilterHiddenComm: () -> Unit,
  onOpenThreatCatalog: () -> Unit,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth().testTag("dashboard_deep_detection_card"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = "Detecção Profunda e Origem",
            style = MaterialTheme.typography.titleMedium,
          )
          Text(
            text = "Diferencia alertas da Play Store de ameaças externas",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        TextButton(
          onClick = onOpenThreatCatalog,
          modifier = Modifier.testTag("dashboard_open_threat_catalog_btn"),
        ) {
          Text("Banco ($catalogEntriesCount)")
        }
      }

      Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Surface(
          color = MaterialTheme.colorScheme.surfaceContainerHigh,
          shape = RoundedCornerShape(12.dp),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          modifier =
            Modifier.weight(1f)
              .clickable(onClick = onFilterPlayStoreAlerts)
              .testTag("dashboard_playstore_alerts_tile"),
        ) {
          Column(modifier = Modifier.padding(12.dp)) {
            Text(
              text = "$playStoreFlaggedCount",
              style = MaterialTheme.typography.titleLarge,
              fontWeight = FontWeight.Bold,
              color =
                if (playStoreFlaggedCount > 0) MaterialTheme.colorScheme.tertiary
                else MaterialTheme.colorScheme.secondary,
            )
            Text(
              text = "Da Play Store c/ alerta",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
        Surface(
          color = MaterialTheme.colorScheme.surfaceContainerHigh,
          shape = RoundedCornerShape(12.dp),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
          modifier =
            Modifier.weight(1f)
              .clickable(onClick = onFilterExternal)
              .testTag("dashboard_external_alerts_tile"),
        ) {
          Column(modifier = Modifier.padding(12.dp)) {
            Text(
              text = "$externalFlaggedCount",
              style = MaterialTheme.typography.titleLarge,
              fontWeight = FontWeight.Bold,
              color =
                if (externalFlaggedCount > 0) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.secondary,
            )
            Text(
              text = "Fora da Play Store",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
      }

      Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        CompactCategoryTile(
          title = "Permissões",
          value = "$permissionAbuseCount",
          icon = Icons.Filled.Warning,
          accent =
            if (permissionAbuseCount > 0) MaterialTheme.colorScheme.tertiary
            else MaterialTheme.colorScheme.onSurfaceVariant,
          onClick = onFilterPlayStoreAlerts,
          modifier = Modifier.weight(1f).testTag("dashboard_perm_abuse_tile"),
        )
        CompactCategoryTile(
          title = "Acessibilidade",
          value = "$accessibilityRiskCount",
          icon = Icons.Filled.AdminPanelSettings,
          accent =
            if (accessibilityRiskCount > 0) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.onSurfaceVariant,
          onClick = onFilterAccessibility,
          modifier = Modifier.weight(1f).testTag("dashboard_accessibility_tile"),
        )
        CompactCategoryTile(
          title = "Envio Oculto",
          value = "$hiddenCommCount",
          icon = Icons.Filled.Radar,
          accent =
            if (hiddenCommCount > 0) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.onSurfaceVariant,
          onClick = onFilterHiddenComm,
          modifier = Modifier.weight(1f).testTag("dashboard_hidden_comm_tile"),
        )
      }
    }
  }
}

@Composable
private fun AntivirusUpdatesCard(
  catalogCount: Int,
  isUpdating: Boolean,
  autoUpdateEnabled: Boolean,
  lastUpdateAt: Long,
  versionLabel: String,
  statusMessage: String,
  sourceLabel: String,
  providerVerified: Boolean,
  hadError: Boolean,
  onToggleAutoUpdate: (Boolean) -> Unit,
  onManualUpdate: () -> Unit,
  onOpenThreatCatalog: () -> Unit,
) {
  val statusBadgeText =
    when {
      isUpdating -> "Atualizando..."
      hadError -> "Erro de rede"
      lastUpdateAt > 0L -> "Atualizado"
      else -> "Pronto"
    }
  val statusTint =
    when {
      isUpdating -> MaterialTheme.colorScheme.primary
      hadError -> MaterialTheme.colorScheme.error
      lastUpdateAt > 0L -> MaterialTheme.colorScheme.secondary
      else -> MaterialTheme.colorScheme.primary
    }
  val statusBg =
    when {
      isUpdating -> MaterialTheme.colorScheme.primaryContainer
      hadError -> MaterialTheme.colorScheme.errorContainer
      lastUpdateAt > 0L -> MaterialTheme.colorScheme.secondaryContainer
      else -> MaterialTheme.colorScheme.surfaceContainerHigh
    }

  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth().testTag("dashboard_antivirus_update_card"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
          Surface(
            color = statusBg,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.size(44.dp),
          ) {
            Box(contentAlignment = Alignment.Center) {
              Icon(
                imageVector = Icons.Filled.CloudSync,
                contentDescription = "Atualizações do antivírus",
                tint = statusTint,
              )
            }
          }
          Spacer(Modifier.width(12.dp))
          Column {
            Text(
              text = "Atualizações do Antivírus",
              style = MaterialTheme.typography.titleMedium,
            )
            Text(
              text = sourceLabel,
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        }
        Spacer(Modifier.width(8.dp))
        Surface(
          color = statusBg,
          shape = RoundedCornerShape(50),
          border = BorderStroke(1.dp, statusTint.copy(alpha = 0.5f)),
        ) {
          Text(
            text = statusBadgeText,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            color = statusTint,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
          )
        }
      }

      Surface(
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(12.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(
          modifier = Modifier.padding(12.dp),
          verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "$catalogCount definições • $versionLabel",
              style = MaterialTheme.typography.labelLarge,
              color = MaterialTheme.colorScheme.onSurface,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
              modifier = Modifier.weight(1f),
            )
            TextButton(
              onClick = onOpenThreatCatalog,
              contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
            ) {
              Text("Ver base")
            }
          }
          Text(
            text =
              if (lastUpdateAt > 0L) {
                "Última sincronização: ${formatTimestampPt(lastUpdateAt)}"
              } else {
                "Nenhuma sincronização online realizada ainda."
              },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
          )
          Text(
            text = statusMessage,
            style = MaterialTheme.typography.bodySmall,
            color =
              if (hadError) MaterialTheme.colorScheme.error
              else MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
          )
          if (providerVerified) {
            Text(
              text = "Segurança TLS Google Play Services verificada",
              style = MaterialTheme.typography.labelSmall,
              color = MaterialTheme.colorScheme.secondary,
            )
          }
        }
      }

      HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

      PolicySwitchRow(
        title = "Atualização recorrente automática",
        subtitle = "Busca novas definições no servidor do Google a cada 12h",
        checked = autoUpdateEnabled,
        onCheckedChange = onToggleAutoUpdate,
        testTag = "switch_auto_antivirus_update",
      )

      Button(
        onClick = onManualUpdate,
        enabled = !isUpdating,
        shape = RoundedCornerShape(14.dp),
        colors =
          ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.secondary,
            contentColor = MaterialTheme.colorScheme.onSecondary,
          ),
        modifier =
          Modifier.fillMaxWidth().height(48.dp).testTag("dashboard_manual_update_button"),
      ) {
        if (isUpdating) {
          CircularProgressIndicator(
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.onSecondary,
            modifier = Modifier.size(18.dp),
          )
        } else {
          Icon(
            imageVector = Icons.Filled.Refresh,
            contentDescription = "Atualizar base do antivírus",
            modifier = Modifier.size(18.dp),
          )
        }
        Spacer(Modifier.width(8.dp))
        Text(
          text =
            if (isUpdating) "Atualizando do servidor Google..."
            else "Atualizar Antivírus Agora",
          style = MaterialTheme.typography.titleSmall,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
    }
  }
}
