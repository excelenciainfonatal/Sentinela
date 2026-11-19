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
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FileOpen
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
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.friendlyInstallerSource

@Composable
fun DashboardScreen(
  uiState: SentinelaUiState,
  cloudSyncState: CloudSyncUiState,
  onPickApk: () -> Unit,
  onScanNow: () -> Unit,
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
      // 1. Calm, Friendly Hero Protection Card
      item(key = "dash_hero") {
        HeroProtectionCard(
          monitorActive = uiState.settings.realTimeMonitorEnabled,
          protectionScore = protectionScore,
          blockedCount = blockedCount,
          suspiciousCount = suspiciousCount,
          lastScanTimestamp = stats.lastScanTimestamp,
          isScanning = uiState.isScanningDevice,
          onPickApk = onPickApk,
          onScanNow = onScanNow,
        )
      }

      // 2. Simple 3-Column App Status Overview
      item(key = "dash_overview") {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Resumo dos seus aplicativos",
              style = MaterialTheme.typography.titleLarge,
            )
            TextButton(
              onClick = { onNavigateToCatalog(AppsCatalogFilter.TODOS) },
              modifier = Modifier.testTag("dashboard_view_all_apps_btn"),
            ) {
              Text("Ver todos (${stats.totalAppsAudited})")
            }
          }

          Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            StatusTileCard(
              title = "Seguros",
              count = authorizedCount,
              icon = Icons.Filled.VerifiedUser,
              accent = MaterialTheme.colorScheme.secondary,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.AUTORIZADOS) },
              modifier = Modifier.weight(1f).testTag("dashboard_kpi_authorized"),
            )
            StatusTileCard(
              title = "Atenção",
              count = suspiciousCount,
              icon = Icons.Filled.Warning,
              accent =
                if (suspiciousCount > 0) MaterialTheme.colorScheme.tertiary
                else MaterialTheme.colorScheme.onSurfaceVariant,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.SUSPEITOS) },
              modifier = Modifier.weight(1f).testTag("dashboard_btn_suspicious"),
            )
            StatusTileCard(
              title = "Risco Alto",
              count = blockedCount,
              icon = Icons.Filled.Block,
              accent =
                if (blockedCount > 0) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.secondary,
              onClick = { onNavigateToCatalog(AppsCatalogFilter.BLOQUEADOS) },
              modifier = Modifier.weight(1f).testTag("dashboard_kpi_blocked"),
            )
          }
        }
      }

      // 3. Flagged Apps Needing Attention (Only shown when something needs review)
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
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
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

      // 4. Two Clean Quick Shortcuts (Apps Confiáveis & Histórico)
      item(key = "dash_shortcuts") {
        Row(
          horizontalArrangement = Arrangement.spacedBy(10.dp),
          modifier = Modifier.fillMaxWidth(),
        ) {
          ShortcutActionCard(
            title = "Apps Confiáveis",
            subtitle = "${uiState.whitelistedApps.size} salvo(s)",
            icon = Icons.Filled.CheckCircle,
            accent = MaterialTheme.colorScheme.secondary,
            onClick = onNavigateToWhitelist,
            modifier = Modifier.weight(1f).testTag("dashboard_whitelist_card"),
          )
          ShortcutActionCard(
            title = "Histórico",
            subtitle = "${uiState.scanHistory.size} scan(s)",
            icon = Icons.Filled.History,
            accent = MaterialTheme.colorScheme.primary,
            onClick = onNavigateToHistory,
            modifier = Modifier.weight(1f).testTag("dashboard_history_card"),
          )
        }
      }

      // 5. Automatic Protection Card (Simple, non-technical)
      item(key = "dash_realtime_card") {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
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
                  else MaterialTheme.colorScheme.surfaceVariant,
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
                  text = "Proteção Automática",
                  style = MaterialTheme.typography.titleMedium,
                )
                Text(
                  text =
                    if (uiState.settings.realTimeMonitorEnabled)
                      "Verifica novos aplicativos assim que são instalados."
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

            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))

            PolicySwitchRow(
              title = "Avisos na barra de notificações",
              subtitle = "Receba um alerta na hora se um app suspeito aparecer",
              checked = uiState.settings.pushAlertsEnabled,
              onCheckedChange = onTogglePushAlerts,
              testTag = "switch_push_alerts",
            )

            AnimatedVisibility(
              visible = !uiState.notificationPermissionGranted || !uiState.usageAccessGranted
            ) {
              Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
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

      // 6. Google Account & Cloud Backup Card
      item(key = "dash_cloud_sync") {
        CloudBackupCard(
          cloudState = cloudSyncState,
          onSyncNow = onSyncCloud,
          onRestoreNow = onRestoreCloud,
          onToggleAutoSync = onToggleCloudAutoSync,
          onSignOut = onSignOut,
        )
      }

      // 7. Collapsible Advanced Settings (Hidden by default for simplicity)
      item(key = "dash_advanced_settings") {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
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
                color = MaterialTheme.colorScheme.surfaceVariant,
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
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))

                PolicySwitchRow(
                  title = "Alertar se um app parecer falsificado",
                  subtitle = "Detecta quando a assinatura digital não bate com a original",
                  checked = uiState.settings.blockSignatureMismatch,
                  onCheckedChange = onToggleSigMismatch,
                  testTag = "policy_sig_mismatch",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                PolicySwitchRow(
                  title = "Bloquear apps de teste não oficiais",
                  subtitle = "Impede aplicativos feitos com chaves temporárias de desenvolvedor",
                  checked = uiState.settings.blockDebugCerts,
                  onCheckedChange = onToggleDebugCerts,
                  testTag = "policy_debug_certs",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                PolicySwitchRow(
                  title = "Alertar sobre permissões arriscadas",
                  subtitle = "Identifica combinações comuns em golpes (tela + mensagens)",
                  checked = uiState.settings.blockHighRiskPermissions,
                  onCheckedChange = onToggleHighRiskPerms,
                  testTag = "policy_high_risk_perms",
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                PolicySwitchRow(
                  title = "Rigidez extra fora da Play Store",
                  subtitle = "Sinaliza aplicativos baixados de sites desconhecidos",
                  checked = uiState.settings.strictSideloadBlocking,
                  onCheckedChange = onToggleStrictSideload,
                  testTag = "policy_strict_sideload",
                )

                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
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
  protectionScore: Int,
  blockedCount: Int,
  suspiciousCount: Int,
  lastScanTimestamp: Long,
  isScanning: Boolean,
  onPickApk: () -> Unit,
  onScanNow: () -> Unit,
) {
  val headline =
    when {
      blockedCount > 0 -> "$blockedCount app(s) com risco alto"
      suspiciousCount > 0 -> "$suspiciousCount app(s) merecem atenção"
      monitorActive -> "Seu celular está protegido"
      else -> "Proteção automática desligada"
    }
  val badgeLabel =
    when {
      blockedCount > 0 -> "Ação necessária"
      suspiciousCount > 0 -> "Atenção"
      monitorActive -> "Protegido"
      else -> "Pausado"
    }
  val statusColor =
    when {
      blockedCount > 0 -> MaterialTheme.colorScheme.error
      suspiciousCount > 0 -> MaterialTheme.colorScheme.tertiary
      monitorActive -> MaterialTheme.colorScheme.secondary
      else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
  val animatedScore by
    animateFloatAsState(
      targetValue = protectionScore / 100f,
      animationSpec = tween(durationMillis = 700),
      label = "hero_protection_score",
    )

  Card(
    shape = MaterialTheme.shapes.extraLarge,
    border =
      BorderStroke(
        width = 1.dp,
        brush =
          Brush.linearGradient(
            colors =
              listOf(
                statusColor.copy(alpha = 0.65f),
                MaterialTheme.colorScheme.primary.copy(alpha = 0.35f),
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
                    Color(0xD40A1017),
                    Color(0xEB0E1621),
                    Color(0xFA0A1017),
                  )
              )
            )
      )

      Column(modifier = Modifier.padding(20.dp)) {
        Surface(
          color = statusColor.copy(alpha = 0.16f),
          contentColor = statusColor,
          shape = RoundedCornerShape(50),
          border = BorderStroke(1.dp, statusColor.copy(alpha = 0.4f)),
          modifier = Modifier.testTag("device_security_status_badge"),
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 5.dp),
          ) {
            Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(statusColor))
            Spacer(Modifier.width(6.dp))
            Text(text = badgeLabel, style = MaterialTheme.typography.labelLarge, color = statusColor)
          }
        }

        Spacer(Modifier.height(16.dp))

        Row(
          verticalAlignment = Alignment.CenterVertically,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Box(contentAlignment = Alignment.Center, modifier = Modifier.size(84.dp)) {
            Canvas(modifier = Modifier.fillMaxSize().padding(4.dp)) {
              val stroke = 7.dp.toPx()
              val d = size.minDimension
              val tl = Offset((size.width - d) / 2f, (size.height - d) / 2f)
              val sz = Size(d, d)
              drawArc(
                color = Color.White.copy(alpha = 0.14f),
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
                color = Color.White,
              )
              Text(
                text = "Saúde",
                style = MaterialTheme.typography.labelSmall,
                color = Color(0xFFA3B3C6),
              )
            }
          }

          Spacer(Modifier.width(16.dp))

          Column(modifier = Modifier.weight(1f)) {
            Text(
              text = headline,
              style = MaterialTheme.typography.headlineSmall,
              color = Color.White,
            )
            Spacer(Modifier.height(4.dp))
            Text(
              text =
                if (lastScanTimestamp > 0L)
                  "Última verificação: ${formatTimestampPt(lastScanTimestamp)}"
                else
                  "Faça sua primeira verificação rápida abaixo.",
              style = MaterialTheme.typography.bodyMedium,
              color = Color(0xFFCBD5E1),
            )
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
          border = BorderStroke(1.dp, Color.White.copy(alpha = 0.25f)),
          colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
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
private fun StatusTileCard(
  title: String,
  count: Int,
  icon: ImageVector,
  accent: Color,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
    shape = MaterialTheme.shapes.large,
    modifier = modifier.clickable(role = Role.Button, onClick = onClick),
  ) {
    Column(
      horizontalAlignment = Alignment.Start,
      modifier = Modifier.padding(14.dp),
    ) {
      Surface(
        color = accent.copy(alpha = 0.14f),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.size(34.dp),
      ) {
        Box(contentAlignment = Alignment.Center) {
          Icon(
            imageVector = icon,
            contentDescription = title,
            tint = accent,
            modifier = Modifier.size(18.dp),
          )
        }
      }
      Spacer(Modifier.height(10.dp))
      Text(
        text = "$count",
        style = MaterialTheme.typography.headlineMedium,
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
private fun ShortcutActionCard(
  title: String,
  subtitle: String,
  icon: ImageVector,
  accent: Color,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
    shape = MaterialTheme.shapes.large,
    modifier = modifier.clickable(role = Role.Button, onClick = onClick),
  ) {
    Row(
      verticalAlignment = Alignment.CenterVertically,
      modifier = Modifier.padding(14.dp),
    ) {
      Surface(
        color = accent.copy(alpha = 0.14f),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.size(40.dp),
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
      Spacer(Modifier.width(10.dp))
      Column(modifier = Modifier.weight(1f)) {
        Text(
          text = title,
          style = MaterialTheme.typography.titleSmall,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
        Text(
          text = subtitle,
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }
      Icon(
        imageVector = Icons.AutoMirrored.Filled.KeyboardArrowRight,
        contentDescription = null,
        tint = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.size(18.dp),
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
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
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
          color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.55f),
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
          color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f),
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
