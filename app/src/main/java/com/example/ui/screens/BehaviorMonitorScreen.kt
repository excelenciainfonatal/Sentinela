package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.EventSeverity
import com.example.data.local.SecurityVerdict
import com.example.ui.BehaviorFilter
import com.example.ui.SentinelaUiState
import com.example.ui.components.ThreatSignalBadgesRow
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.friendlyInstallerSource
import com.example.ui.components.verdictColor

@Composable
fun BehaviorMonitorScreen(
  uiState: SentinelaUiState,
  onFilterChange: (BehaviorFilter) -> Unit,
  onSearchChange: (String) -> Unit,
  onScanNow: () -> Unit,
  onClearEvents: () -> Unit,
  onOpenUsageSettings: () -> Unit,
  onOpenAuditDetail: (Long) -> Unit,
  onNavigateToWhitelist: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val filteredApps =
    remember(
      uiState.installedApps,
      uiState.behaviorFilter,
      uiState.behaviorSearchQuery,
      uiState.whitelistedPackageNames,
    ) {
      uiState.installedApps.filter { app ->
        val matchesFilter =
          when (uiState.behaviorFilter) {
            BehaviorFilter.TODOS -> true
            BehaviorFilter.ALTO_RISCO -> app.verdict == SecurityVerdict.BLOQUEADO.name
            BehaviorFilter.SUSPEITOS -> app.verdict == SecurityVerdict.SUSPEITO.name
            BehaviorFilter.PLAY_STORE_ALERTAS ->
              (app.isPlayStoreApp || app.installerSource == "com.android.vending") &&
                app.verdict != SecurityVerdict.SEGURO.name
            BehaviorFilter.SEGUROS -> app.verdict == SecurityVerdict.SEGURO.name
            BehaviorFilter.SIDELOAD ->
              !app.isSystemApp && app.installerSource != "com.android.vending"
            BehaviorFilter.LISTA_BRANCA -> app.packageName in uiState.whitelistedPackageNames
          }
        val query = uiState.behaviorSearchQuery.trim()
        val matchesQuery =
          query.isEmpty() ||
            app.appName.contains(query, ignoreCase = true) ||
            app.packageName.contains(query, ignoreCase = true)
        matchesFilter && matchesQuery
      }
    }

  Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    LazyColumn(
      modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
      contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
      // Optional friendly Usage Access banner
      if (!uiState.usageAccessGranted) {
        item {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.tertiary.copy(alpha = 0.5f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(14.dp),
            ) {
              Icon(
                imageVector = Icons.Filled.AdminPanelSettings,
                contentDescription = "Permissão de monitoramento",
                tint = MaterialTheme.colorScheme.tertiary,
              )
              Spacer(Modifier.width(10.dp))
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = "Monitoramento de atividade desativado",
                  style = MaterialTheme.typography.titleSmall,
                  color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
                Text(
                  text = "Ative para perceber se algum app escondido consumir bateria ou dados demais.",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onTertiaryContainer,
                )
              }
              Spacer(Modifier.width(8.dp))
              OutlinedButton(
                onClick = onOpenUsageSettings,
                modifier = Modifier.height(48.dp).testTag("behavior_usage_access_btn"),
              ) {
                Text("Ativar")
              }
            }
          }
        }
      }

      // Recent Alerts (only shown cleanly if there are events, or compact card if none)
      if (uiState.behaviorEvents.isNotEmpty()) {
        item {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Icon(
                imageVector = Icons.Filled.NotificationsActive,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp),
              )
              Spacer(Modifier.width(8.dp))
              Text(
                text = "Alertas recentes",
                style = MaterialTheme.typography.titleLarge,
              )
            }
            IconButton(
              onClick = onClearEvents,
              modifier = Modifier.size(48.dp).testTag("clear_events_button"),
            ) {
              Icon(
                imageVector = Icons.Filled.DeleteSweep,
                contentDescription = "Limpar alertas",
              )
            }
          }
        }

        items(uiState.behaviorEvents.take(4), key = { "beh_evt_${it.id}" }) { event ->
          val sev = runCatching { EventSeverity.valueOf(event.severity) }.getOrDefault(EventSeverity.INFO)
          val color =
            when (sev) {
              EventSeverity.CRITICAL -> MaterialTheme.colorScheme.error
              EventSeverity.WARNING -> MaterialTheme.colorScheme.tertiary
              EventSeverity.INFO -> MaterialTheme.colorScheme.primary
            }
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, color.copy(alpha = 0.35f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Column(modifier = Modifier.padding(14.dp)) {
              Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth(),
              ) {
                Text(
                  text = event.appName,
                  style = MaterialTheme.typography.titleSmall,
                  color = color,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                  modifier = Modifier.weight(1f),
                )
                Text(
                  text = formatTimestampPt(event.timestamp),
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
              Spacer(Modifier.height(4.dp))
              Text(text = event.details, style = MaterialTheme.typography.bodyMedium)
            }
          }
        }
      }

      // Installed Apps Header & Controls
      item {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.SpaceBetween,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Text(
            text = "Apps do celular (${filteredApps.size})",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.weight(1f),
          )
          TextButton(
            onClick = onNavigateToWhitelist,
            modifier = Modifier.testTag("behavior_open_whitelist_btn"),
          ) {
            Icon(
              imageVector = Icons.Filled.VerifiedUser,
              contentDescription = null,
              modifier = Modifier.size(16.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text("Confiáveis (${uiState.whitelistedApps.size})")
          }
          TextButton(
            onClick = onScanNow,
            enabled = !uiState.isScanningDevice,
            modifier = Modifier.testTag("behavior_refresh_button"),
          ) {
            if (uiState.isScanningDevice) {
              CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
            } else {
              Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(4.dp))
            Text("Atualizar")
          }
        }
        Spacer(Modifier.height(6.dp))
        OutlinedTextField(
          value = uiState.behaviorSearchQuery,
          onValueChange = onSearchChange,
          placeholder = { Text("Procurar aplicativo pelo nome...") },
          leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
          singleLine = true,
          shape = RoundedCornerShape(14.dp),
          modifier = Modifier.fillMaxWidth().testTag("behavior_search_input"),
        )
        Spacer(Modifier.height(10.dp))
        Row(
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        ) {
          BehaviorFilter.entries.forEach { filter ->
            FilterChip(
              selected = uiState.behaviorFilter == filter,
              onClick = { onFilterChange(filter) },
              label = { Text(filter.labelPt) },
              modifier = Modifier.testTag("behavior_filter_${filter.name.lowercase()}"),
            )
          }
        }
      }

      if (filteredApps.isEmpty()) {
        item {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Nenhum aplicativo encontrado com esse filtro.",
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              modifier = Modifier.padding(18.dp),
            )
          }
        }
      } else {
        items(filteredApps, key = { "app_audit_${it.id}" }) { app ->
          val verdict =
            runCatching { SecurityVerdict.valueOf(app.verdict) }.getOrDefault(SecurityVerdict.SEGURO)
          val accent = verdictColor(verdict)
          val friendlySource =
            remember(app.installerSource, app.isSystemApp, app.sourceType) {
              friendlyInstallerSource(app.installerSource, app.isSystemApp, app.sourceType)
            }
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
            shape = MaterialTheme.shapes.large,
            modifier =
              Modifier.fillMaxWidth()
                .clickable { onOpenAuditDetail(app.id) }
                .testTag("installed_app_card_${app.packageName}"),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(16.dp),
            ) {
              Column(modifier = Modifier.weight(1f)) {
                Row(
                  verticalAlignment = Alignment.CenterVertically,
                  horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                  Text(
                    text = app.appName,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                  )
                  VerdictBadge(verdict)
                  if (app.packageName in uiState.whitelistedPackageNames) {
                    Surface(
                      color = MaterialTheme.colorScheme.secondaryContainer,
                      contentColor = MaterialTheme.colorScheme.secondary,
                      shape = RoundedCornerShape(50),
                    ) {
                      Text(
                        text = "Confiável",
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                      )
                    }
                  }
                }
                Spacer(Modifier.height(4.dp))
                Text(
                  text = friendlySource,
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                  maxLines = 1,
                  overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(6.dp))
                ThreatSignalBadgesRow(app)
              }
              Spacer(Modifier.width(12.dp))
              Column(horizontalAlignment = Alignment.End) {
                Text(
                  text = "${app.riskScore}",
                  style = MaterialTheme.typography.titleLarge,
                  color = accent,
                )
                Text(
                  text = "Risco",
                  style = MaterialTheme.typography.labelSmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
            }
          }
        }
      }

      item { Spacer(Modifier.height(12.dp)) }
    }
  }
}
