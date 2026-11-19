package com.example.ui.screens

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AssistChip
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.ScanAuditEntity
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.ui.SentinelaUiState
import com.example.ui.components.VerdictBadge
import com.example.ui.components.friendlyInstallerSource
import com.example.ui.components.verdictColor

enum class AppsCatalogFilter(val labelPt: String) {
  BLOQUEADOS("Risco Alto"),
  AUTORIZADOS("Seguros"),
  SUSPEITOS("Atenção"),
  TODOS("Todos"),
  APKS("Arquivos APK"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsCatalogScreen(
  uiState: SentinelaUiState,
  initialFilter: AppsCatalogFilter,
  onBack: () -> Unit,
  onOpenAuditDetail: (Long, String) -> Unit,
  onAddToWhitelist: (packageName: String, appName: String, sha256: String) -> Unit,
  onRemoveFromWhitelist: (packageName: String) -> Unit,
  onBlockCert: (sha256: String, label: String, pkg: String) -> Unit,
  onTrustCert: (sha256: String, label: String, pkg: String) -> Unit,
  onScanNow: () -> Unit,
  onNavigateToWhitelist: () -> Unit,
  onNavigateToGatekeeper: () -> Unit,
  onNavigateToSignatures: () -> Unit,
  onNavigateToHistory: () -> Unit,
  onShowMessage: (String) -> Unit,
) {
  BackHandler(onBack = onBack)

  var selectedFilter by rememberSaveable(initialFilter) { mutableStateOf(initialFilter) }
  var searchQuery by rememberSaveable { mutableStateOf("") }
  val listState = rememberLazyListState()
  val filterScrollState = rememberScrollState()
  val quickNavScrollState = rememberScrollState()

  val trustedCertShas =
    remember(uiState.certificateSummaries) {
      uiState.certificateSummaries
        .filter { it.trustStatus == TrustStatus.TRUSTED }
        .map { it.sha256 }
        .toSet()
    }

  val allCombinedAudits =
    remember(uiState.installedApps, uiState.apkAudits) {
      (uiState.apkAudits + uiState.installedApps).sortedByDescending { it.riskScore }
    }

  val counts =
    remember(allCombinedAudits, uiState.whitelistedPackageNames, trustedCertShas) {
      val blocked = allCombinedAudits.count { it.verdict == SecurityVerdict.BLOQUEADO.name }
      val suspicious = allCombinedAudits.count { it.verdict == SecurityVerdict.SUSPEITO.name }
      val authorized =
        allCombinedAudits.count {
          it.packageName in uiState.whitelistedPackageNames ||
            it.sha256Fingerprint in trustedCertShas ||
            it.verdict == SecurityVerdict.SEGURO.name
        }
      intArrayOf(blocked, authorized, suspicious, allCombinedAudits.size)
    }

  val filteredAudits =
    remember(
      allCombinedAudits,
      selectedFilter,
      searchQuery,
      uiState.whitelistedPackageNames,
      trustedCertShas,
    ) {
      val query = searchQuery.trim()
      allCombinedAudits.filter { app ->
        val isWhitelisted = app.packageName in uiState.whitelistedPackageNames
        val isTrustedCert = app.sha256Fingerprint in trustedCertShas
        val matchesTab =
          when (selectedFilter) {
            AppsCatalogFilter.BLOQUEADOS -> app.verdict == SecurityVerdict.BLOQUEADO.name
            AppsCatalogFilter.AUTORIZADOS ->
              isWhitelisted || isTrustedCert || app.verdict == SecurityVerdict.SEGURO.name
            AppsCatalogFilter.SUSPEITOS ->
              app.verdict == SecurityVerdict.SUSPEITO.name ||
                (!app.isSystemApp &&
                  app.sourceType != "APK_PRE_INSTALL" &&
                  app.installerSource != "com.android.vending")
            AppsCatalogFilter.TODOS -> true
            AppsCatalogFilter.APKS -> app.sourceType == "APK_PRE_INSTALL"
          }
        val matchesQuery =
          query.isEmpty() ||
            app.appName.contains(query, ignoreCase = true) ||
            app.packageName.contains(query, ignoreCase = true)
        matchesTab && matchesQuery
      }
    }

  Scaffold(
    topBar = {
      TopAppBar(
        title = {
          Text(
            text = "Meus Aplicativos",
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        },
        navigationIcon = {
          IconButton(onClick = onBack, modifier = Modifier.testTag("catalog_back_button")) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
          }
        },
        actions = {
          TextButton(
            onClick = {
              onScanNow()
              onShowMessage("Verificação iniciada...")
            },
            modifier = Modifier.testTag("catalog_scan_now_button"),
          ) {
            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text("Verificar")
          }
        },
      )
    }
  ) { innerPadding ->
    Box(
      contentAlignment = Alignment.TopCenter,
      modifier = Modifier.fillMaxSize().padding(innerPadding),
    ) {
      LazyColumn(
        state = listState,
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        // Summary Pills Strip
        item(key = "catalog_summary") {
          Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
          ) {
            CatalogStatPill(
              label = "Risco Alto",
              count = counts[0],
              color = MaterialTheme.colorScheme.error,
              selected = selectedFilter == AppsCatalogFilter.BLOQUEADOS,
              onClick = { selectedFilter = AppsCatalogFilter.BLOQUEADOS },
              modifier = Modifier.weight(1f).testTag("catalog_pill_blocked"),
            )
            CatalogStatPill(
              label = "Seguros",
              count = counts[1],
              color = MaterialTheme.colorScheme.secondary,
              selected = selectedFilter == AppsCatalogFilter.AUTORIZADOS,
              onClick = { selectedFilter = AppsCatalogFilter.AUTORIZADOS },
              modifier = Modifier.weight(1f).testTag("catalog_pill_authorized"),
            )
            CatalogStatPill(
              label = "Atenção",
              count = counts[2],
              color = MaterialTheme.colorScheme.tertiary,
              selected = selectedFilter == AppsCatalogFilter.SUSPEITOS,
              onClick = { selectedFilter = AppsCatalogFilter.SUSPEITOS },
              modifier = Modifier.weight(1f).testTag("catalog_pill_suspicious"),
            )
          }
        }

        // Quick Shortcuts Row
        item(key = "catalog_functions") {
          Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth().horizontalScroll(quickNavScrollState),
          ) {
            AssistChip(
              onClick = onNavigateToWhitelist,
              leadingIcon = {
                Icon(
                  Icons.Filled.VerifiedUser,
                  contentDescription = null,
                  modifier = Modifier.size(16.dp),
                )
              },
              label = { Text("Apps Confiáveis (${uiState.whitelistedApps.size})") },
              modifier = Modifier.testTag("catalog_fn_whitelist"),
            )
            AssistChip(
              onClick = onNavigateToGatekeeper,
              leadingIcon = {
                Icon(
                  Icons.Filled.FileOpen,
                  contentDescription = null,
                  modifier = Modifier.size(16.dp),
                )
              },
              label = { Text("Verificar .APK") },
              modifier = Modifier.testTag("catalog_fn_gatekeeper"),
            )
            AssistChip(
              onClick = onNavigateToHistory,
              leadingIcon = {
                Icon(
                  Icons.Filled.History,
                  contentDescription = null,
                  modifier = Modifier.size(16.dp),
                )
              },
              label = { Text("Histórico") },
              modifier = Modifier.testTag("catalog_fn_history"),
            )
            AssistChip(
              onClick = onNavigateToSignatures,
              leadingIcon = {
                Icon(
                  Icons.Filled.Key,
                  contentDescription = null,
                  modifier = Modifier.size(16.dp),
                )
              },
              label = { Text("Assinaturas") },
              modifier = Modifier.testTag("catalog_fn_signatures"),
            )
          }
        }

        // Search & Filter Chips
        item(key = "catalog_controls") {
          Column {
            OutlinedTextField(
              value = searchQuery,
              onValueChange = { searchQuery = it },
              placeholder = { Text("Procurar aplicativo...") },
              leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
              singleLine = true,
              shape = RoundedCornerShape(14.dp),
              modifier = Modifier.fillMaxWidth().testTag("catalog_search_input"),
            )
            Spacer(Modifier.height(8.dp))
            Row(
              horizontalArrangement = Arrangement.spacedBy(8.dp),
              modifier = Modifier.fillMaxWidth().horizontalScroll(filterScrollState),
            ) {
              AppsCatalogFilter.entries.forEach { filter ->
                FilterChip(
                  selected = selectedFilter == filter,
                  onClick = { selectedFilter = filter },
                  label = { Text(filter.labelPt, maxLines = 1, softWrap = false) },
                  modifier = Modifier.testTag("catalog_filter_${filter.name.lowercase()}"),
                )
              }
            }
          }
        }

        if (filteredAudits.isEmpty()) {
          item(key = "catalog_empty") {
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth().padding(28.dp),
              ) {
                Icon(
                  imageVector =
                    when (selectedFilter) {
                      AppsCatalogFilter.BLOQUEADOS -> Icons.Filled.CheckCircle
                      AppsCatalogFilter.SUSPEITOS -> Icons.Filled.Security
                      else -> Icons.Filled.VerifiedUser
                    },
                  contentDescription = null,
                  tint = MaterialTheme.colorScheme.secondary,
                  modifier = Modifier.size(36.dp),
                )
                Text(
                  text =
                    when (selectedFilter) {
                      AppsCatalogFilter.BLOQUEADOS -> "Nenhum aplicativo perigoso encontrado"
                      AppsCatalogFilter.SUSPEITOS -> "Nenhum aplicativo em atenção"
                      AppsCatalogFilter.AUTORIZADOS -> "Nenhum aplicativo seguro listado"
                      AppsCatalogFilter.APKS -> "Nenhum arquivo .APK analisado ainda"
                      AppsCatalogFilter.TODOS -> "Nenhum aplicativo encontrado"
                    },
                  style = MaterialTheme.typography.titleMedium,
                )
                Text(
                  text = "Você pode trocar o filtro acima ou fazer uma nova verificação.",
                  style = MaterialTheme.typography.bodyMedium,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
            }
          }
        } else {
          items(
            items = filteredAudits,
            key = { "cat_${it.id}_${it.packageName}" },
          ) { app ->
            val isWhitelisted = app.packageName in uiState.whitelistedPackageNames
            val isTrustedCert = app.sha256Fingerprint in trustedCertShas
            CatalogAppCard(
              app = app,
              isWhitelisted = isWhitelisted,
              isTrustedCert = isTrustedCert,
              onOpenDetail = { onOpenAuditDetail(app.id, app.packageName) },
              onToggleWhitelist = {
                if (isWhitelisted) {
                  onRemoveFromWhitelist(app.packageName)
                  onShowMessage("${app.appName} removido dos apps confiáveis.")
                } else {
                  onAddToWhitelist(app.packageName, app.appName, app.sha256Fingerprint)
                  onShowMessage("${app.appName} marcado como confiável.")
                }
              },
              onBlockCert = {
                onBlockCert(app.sha256Fingerprint, app.appName, app.packageName)
                onShowMessage("${app.appName} marcado como bloqueado.")
              },
              onTrustCert = {
                onTrustCert(app.sha256Fingerprint, app.appName, app.packageName)
                onShowMessage("Assinatura de ${app.appName} autorizada.")
              },
            )
          }
        }

        item(key = "catalog_spacer") { Spacer(Modifier.height(12.dp)) }
      }
    }
  }
}

@Composable
private fun CatalogStatPill(
  label: String,
  count: Int,
  color: androidx.compose.ui.graphics.Color,
  selected: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Surface(
    color = if (selected) color.copy(alpha = 0.18f) else MaterialTheme.colorScheme.surface,
    contentColor = color,
    shape = RoundedCornerShape(16.dp),
    border =
      BorderStroke(
        width = if (selected) 1.5.dp else 1.dp,
        color = if (selected) color else MaterialTheme.colorScheme.outline.copy(alpha = 0.35f),
      ),
    modifier = modifier.height(68.dp).clickable(onClick = onClick),
  ) {
    Column(
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center,
      modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
    ) {
      Text(
        text = "$count",
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
      )
      Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun CatalogAppCard(
  app: ScanAuditEntity,
  isWhitelisted: Boolean,
  isTrustedCert: Boolean,
  onOpenDetail: () -> Unit,
  onToggleWhitelist: () -> Unit,
  onBlockCert: () -> Unit,
  onTrustCert: () -> Unit,
) {
  val verdict =
    remember(app.verdict) {
      runCatching { SecurityVerdict.valueOf(app.verdict) }.getOrDefault(SecurityVerdict.SEGURO)
    }
  val accent = verdictColor(verdict)
  val firstFinding =
    remember(app.findingsSummary) {
      app.findingsSummary.lineSequence().firstOrNull()?.removePrefix("• ") ?: ""
    }
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
        .clickable(onClick = onOpenDetail)
        .testTag("catalog_app_card_${app.packageName}"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
          ) {
            Text(
              text = app.appName,
              style = MaterialTheme.typography.titleMedium,
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
              modifier = Modifier.weight(1f, fill = false),
            )
            VerdictBadge(verdict)
          }
          Text(
            text = "$friendlySource • v${app.versionName}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
          Text(
            text = "${app.riskScore}",
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = accent,
          )
          Text(
            text = "Risco",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }

      if (isWhitelisted || isTrustedCert || app.sourceType == "APK_PRE_INSTALL") {
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
          if (isWhitelisted) {
            Surface(
              color = MaterialTheme.colorScheme.secondaryContainer,
              contentColor = MaterialTheme.colorScheme.secondary,
              shape = RoundedCornerShape(50),
            ) {
              Text(
                text = "App Confiável",
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
              )
            }
          }
          if (isTrustedCert) {
            Surface(
              color = MaterialTheme.colorScheme.primaryContainer,
              contentColor = MaterialTheme.colorScheme.primary,
              shape = RoundedCornerShape(50),
            ) {
              Text(
                text = "Autorizado",
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
              )
            }
          }
        }
      }

      if (firstFinding.isNotBlank()) {
        Text(
          text = firstFinding,
          style = MaterialTheme.typography.bodyMedium,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 2,
          overflow = TextOverflow.Ellipsis,
        )
      }

      Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        if (app.sourceType != "APK_PRE_INSTALL") {
          OutlinedButton(
            onClick = onToggleWhitelist,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.weight(1f).height(48.dp),
          ) {
            Icon(
              imageVector = Icons.Filled.VerifiedUser,
              contentDescription = null,
              modifier = Modifier.size(16.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(
              text = if (isWhitelisted) "Remover Confiança" else "Confiar neste app",
              maxLines = 1,
              overflow = TextOverflow.Ellipsis,
            )
          }
        } else if (app.sha256Fingerprint != "SEM ASSINATURA") {
          OutlinedButton(
            onClick = onTrustCert,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.weight(1f).height(48.dp),
          ) {
            Text("Confiar", maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
        }

        if (app.verdict != SecurityVerdict.BLOQUEADO.name && app.sha256Fingerprint != "SEM ASSINATURA") {
          OutlinedButton(
            onClick = onBlockCert,
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            modifier = Modifier.height(48.dp),
          ) {
            Icon(
              imageVector = Icons.Filled.Block,
              contentDescription = "Bloquear",
              modifier = Modifier.size(16.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text("Bloquear")
          }
        } else {
          OutlinedButton(
            onClick = onOpenDetail,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.height(48.dp),
          ) {
            Text("Ver detalhes")
          }
        }
      }
    }
  }
}
