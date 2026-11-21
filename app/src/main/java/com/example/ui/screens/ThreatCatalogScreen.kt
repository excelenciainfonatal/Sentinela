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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Campaign
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.ThreatCatalogEntity
import com.example.data.local.ThreatType
import com.example.ui.SentinelaUiState
import com.example.ui.components.TechnicalDetailsExpandable

enum class ThreatCatalogFilter(val labelPt: String) {
  TODOS("Todos"),
  VIRUS("Vírus"),
  SPYWARE("Spywares"),
  ADWARE("Adwares"),
  ARQUIVO_MALICIOSO("Arquivos"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatCatalogScreen(
  uiState: SentinelaUiState,
  onBack: () -> Unit,
  onAddCustomThreat: (name: String, type: ThreatType, packagePattern: String, sha256: String, desc: String) -> Unit,
  onDeleteCustomThreat: (threatKey: String) -> Unit,
  onRestoreDefaults: () -> Unit,
  onShowMessage: (String) -> Unit,
) {
  BackHandler(onBack = onBack)

  var selectedFilter by rememberSaveable { mutableStateOf(ThreatCatalogFilter.TODOS) }
  var searchQuery by rememberSaveable { mutableStateOf("") }
  var showAddDialog by rememberSaveable { mutableStateOf(false) }

  val counts =
    remember(uiState.threatCatalog) {
      val virus = uiState.threatCatalog.count { it.threatType == ThreatType.VIRUS.name }
      val spyware = uiState.threatCatalog.count { it.threatType == ThreatType.SPYWARE.name }
      val adware = uiState.threatCatalog.count { it.threatType == ThreatType.ADWARE.name }
      val files = uiState.threatCatalog.count { it.threatType == ThreatType.ARQUIVO_MALICIOSO.name }
      intArrayOf(virus, spyware, adware, files)
    }

  val matchedNamesOnDevice =
    remember(uiState.installedApps, uiState.apkAudits) {
      (uiState.installedApps + uiState.apkAudits)
        .mapNotNull { it.matchedThreatName.takeIf { name -> name.isNotBlank() } }
        .toSet()
    }

  val filteredCatalog =
    remember(uiState.threatCatalog, selectedFilter, searchQuery) {
      val query = searchQuery.trim()
      uiState.threatCatalog.filter { item ->
        val matchesType =
          when (selectedFilter) {
            ThreatCatalogFilter.TODOS -> true
            ThreatCatalogFilter.VIRUS -> item.threatType == ThreatType.VIRUS.name
            ThreatCatalogFilter.SPYWARE -> item.threatType == ThreatType.SPYWARE.name
            ThreatCatalogFilter.ADWARE -> item.threatType == ThreatType.ADWARE.name
            ThreatCatalogFilter.ARQUIVO_MALICIOSO ->
              item.threatType == ThreatType.ARQUIVO_MALICIOSO.name
          }
        val matchesQuery =
          query.isEmpty() ||
            item.name.contains(query, ignoreCase = true) ||
            item.descriptionPt.contains(query, ignoreCase = true) ||
            item.packagePatterns.contains(query, ignoreCase = true)
        matchesType && matchesQuery
      }
    }

  if (showAddDialog) {
    AddCustomThreatDialog(
      onDismiss = { showAddDialog = false },
      onConfirm = { name, type, pkg, sha, desc ->
        onAddCustomThreat(name, type, pkg, sha, desc)
        showAddDialog = false
        onShowMessage("Assinatura adicionada ao banco de ameaças.")
      },
    )
  }

  Scaffold(
    topBar = {
      TopAppBar(
        title = {
          Text(
            text = "Banco de Ameaças",
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        },
        navigationIcon = {
          IconButton(onClick = onBack, modifier = Modifier.testTag("threat_catalog_back_btn")) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
          }
        },
        actions = {
          IconButton(
            onClick = {
              onRestoreDefaults()
              onShowMessage("Catálogo oficial atualizado.")
            },
            modifier = Modifier.testTag("threat_catalog_restore_btn"),
          ) {
            Icon(Icons.Filled.Restore, contentDescription = "Restaurar catálogo padrão")
          }
        },
      )
    },
    floatingActionButton = {
      FloatingActionButton(
        onClick = { showAddDialog = true },
        containerColor = MaterialTheme.colorScheme.primary,
        contentColor = MaterialTheme.colorScheme.onPrimary,
        modifier = Modifier.testTag("threat_catalog_add_fab"),
      ) {
        Icon(Icons.Filled.Add, contentDescription = "Cadastrar nova assinatura")
      }
    },
  ) { innerPadding ->
    Box(
      contentAlignment = Alignment.TopCenter,
      modifier = Modifier.fillMaxSize().padding(innerPadding),
    ) {
      LazyColumn(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        item(key = "catalog_intro") {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
              Text(
                text = "Base local de vírus, spywares, adwares e arquivos maliciosos",
                style = MaterialTheme.typography.titleMedium,
              )
              Text(
                text =
                  "O Sentinela compara todos os apps da Play Store, downloads externos e arquivos .APK contra ${uiState.threatCatalog.size} assinaturas catalogadas.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
              Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth(),
              ) {
                CatalogCategoryTile(
                  label = "Vírus",
                  count = counts[0],
                  color = MaterialTheme.colorScheme.error,
                  selected = selectedFilter == ThreatCatalogFilter.VIRUS,
                  onClick = {
                    selectedFilter =
                      if (selectedFilter == ThreatCatalogFilter.VIRUS) ThreatCatalogFilter.TODOS
                      else ThreatCatalogFilter.VIRUS
                  },
                  modifier = Modifier.weight(1f).testTag("threat_pill_virus"),
                )
                CatalogCategoryTile(
                  label = "Spywares",
                  count = counts[1],
                  color = MaterialTheme.colorScheme.tertiary,
                  selected = selectedFilter == ThreatCatalogFilter.SPYWARE,
                  onClick = {
                    selectedFilter =
                      if (selectedFilter == ThreatCatalogFilter.SPYWARE) ThreatCatalogFilter.TODOS
                      else ThreatCatalogFilter.SPYWARE
                  },
                  modifier = Modifier.weight(1f).testTag("threat_pill_spyware"),
                )
                CatalogCategoryTile(
                  label = "Adwares",
                  count = counts[2],
                  color = MaterialTheme.colorScheme.primary,
                  selected = selectedFilter == ThreatCatalogFilter.ADWARE,
                  onClick = {
                    selectedFilter =
                      if (selectedFilter == ThreatCatalogFilter.ADWARE) ThreatCatalogFilter.TODOS
                      else ThreatCatalogFilter.ADWARE
                  },
                  modifier = Modifier.weight(1f).testTag("threat_pill_adware"),
                )
                CatalogCategoryTile(
                  label = "Arquivos",
                  count = counts[3],
                  color = MaterialTheme.colorScheme.error,
                  selected = selectedFilter == ThreatCatalogFilter.ARQUIVO_MALICIOSO,
                  onClick = {
                    selectedFilter =
                      if (selectedFilter == ThreatCatalogFilter.ARQUIVO_MALICIOSO)
                        ThreatCatalogFilter.TODOS
                      else ThreatCatalogFilter.ARQUIVO_MALICIOSO
                  },
                  modifier = Modifier.weight(1f).testTag("threat_pill_files"),
                )
              }
            }
          }
        }

        item(key = "catalog_search") {
          Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = searchQuery,
              onValueChange = { searchQuery = it },
              placeholder = { Text("Buscar vírus, spyware, adware ou pacote...") },
              leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
              singleLine = true,
              shape = RoundedCornerShape(14.dp),
              modifier = Modifier.fillMaxWidth().testTag("threat_catalog_search_input"),
            )
            Row(
              horizontalArrangement = Arrangement.spacedBy(8.dp),
              modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            ) {
              ThreatCatalogFilter.entries.forEach { filter ->
                FilterChip(
                  selected = selectedFilter == filter,
                  onClick = { selectedFilter = filter },
                  label = { Text(filter.labelPt) },
                  modifier = Modifier.testTag("threat_filter_${filter.name.lowercase()}"),
                )
              }
            }
          }
        }

        items(filteredCatalog, key = { "threat_${it.threatKey}" }) { entry ->
          ThreatCatalogEntryCard(
            entry = entry,
            isDetectedOnDevice = entry.name in matchedNamesOnDevice,
            isCustom = entry.threatKey.startsWith("CUSTOM_"),
            onDelete = {
              onDeleteCustomThreat(entry.threatKey)
              onShowMessage("Regra removida do catálogo.")
            },
          )
        }

        item(key = "threat_catalog_bottom_spacer") { Spacer(Modifier.height(72.dp)) }
      }
    }
  }
}

@Composable
private fun CatalogCategoryTile(
  label: String,
  count: Int,
  color: Color,
  selected: Boolean,
  onClick: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Surface(
    color = if (selected) color.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surface,
    contentColor = color,
    shape = RoundedCornerShape(14.dp),
    border =
      BorderStroke(
        width = if (selected) 1.5.dp else 1.dp,
        color = if (selected) color else MaterialTheme.colorScheme.outlineVariant,
      ),
    modifier = modifier.height(62.dp).clickable(onClick = onClick),
  ) {
    Column(
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center,
      modifier = Modifier.padding(horizontal = 4.dp),
    ) {
      Text(
        text = "$count",
        style = MaterialTheme.typography.titleMedium,
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
private fun ThreatCatalogEntryCard(
  entry: ThreatCatalogEntity,
  isDetectedOnDevice: Boolean,
  isCustom: Boolean,
  onDelete: () -> Unit,
) {
  val type =
    remember(entry.threatType) {
      runCatching { ThreatType.valueOf(entry.threatType) }.getOrDefault(ThreatType.VIRUS)
    }
  val (accent, container, icon) =
    when (type) {
      ThreatType.VIRUS ->
        Triple(
          MaterialTheme.colorScheme.error,
          MaterialTheme.colorScheme.errorContainer,
          Icons.Filled.BugReport,
        )
      ThreatType.SPYWARE ->
        Triple(
          MaterialTheme.colorScheme.tertiary,
          MaterialTheme.colorScheme.tertiaryContainer,
          Icons.Filled.Visibility,
        )
      ThreatType.ADWARE ->
        Triple(
          MaterialTheme.colorScheme.primary,
          MaterialTheme.colorScheme.primaryContainer,
          Icons.Filled.Campaign,
        )
      ThreatType.ARQUIVO_MALICIOSO ->
        Triple(
          MaterialTheme.colorScheme.error,
          MaterialTheme.colorScheme.errorContainer,
          Icons.Filled.InsertDriveFile,
        )
    }

  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border =
      BorderStroke(
        width = if (isDetectedOnDevice) 1.5.dp else 1.dp,
        color = if (isDetectedOnDevice) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outlineVariant,
      ),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth().testTag("threat_card_${entry.threatKey}"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          modifier = Modifier.weight(1f),
        ) {
          Surface(
            color = container,
            contentColor = accent,
            shape = RoundedCornerShape(50),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            ) {
              Icon(icon as ImageVector, contentDescription = type.labelPt, modifier = Modifier.size(14.dp))
              Spacer(Modifier.width(4.dp))
              Text(
                text = type.labelPt,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.SemiBold,
              )
            }
          }
          if (isDetectedOnDevice) {
            Surface(
              color = MaterialTheme.colorScheme.error,
              contentColor = MaterialTheme.colorScheme.onError,
              shape = RoundedCornerShape(50),
            ) {
              Text(
                text = "Detectado",
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
              )
            }
          }
        }
        Text(
          text = "Risco ${entry.severityScore}/100",
          style = MaterialTheme.typography.labelMedium,
          fontWeight = FontWeight.Bold,
          color = accent,
        )
        if (isCustom) {
          IconButton(onClick = onDelete, modifier = Modifier.size(40.dp)) {
            Icon(
              imageVector = Icons.Filled.DeleteOutline,
              contentDescription = "Excluir regra",
              tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
        }
      }

      Text(text = entry.name, style = MaterialTheme.typography.titleMedium)

      Text(
        text = entry.descriptionPt,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )

      Surface(
        color = MaterialTheme.colorScheme.surfaceContainer,
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Text(
          text = "O que fazer: ${entry.recommendationPt}",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurface,
          modifier = Modifier.padding(10.dp),
        )
      }

      TechnicalDetailsExpandable(
        title = "Indicadores técnicos",
        subtitle = entry.sourceReference,
        testTag = "threat_tech_${entry.threatKey}",
      ) {
        if (entry.packagePatterns.isNotBlank()) {
          Text(
            text = "Pacotes monitorados: ${entry.packagePatterns}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        if (entry.permissionSignature.isNotBlank()) {
          Text(
            text = "Permissões típicas: ${entry.permissionSignature}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        if (entry.indicatorTokens.isNotBlank()) {
          Text(
            text = "Assinaturas de código/rede: ${entry.indicatorTokens}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
          )
        }
        if (entry.sha256Signatures.isNotBlank()) {
          Text(
            text = "SHA-256 catalogado: ${entry.sha256Signatures}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }
    }
  }
}

@Composable
private fun AddCustomThreatDialog(
  onDismiss: () -> Unit,
  onConfirm: (name: String, type: ThreatType, packagePattern: String, sha256: String, desc: String) -> Unit,
) {
  var name by rememberSaveable { mutableStateOf("") }
  var selectedType by rememberSaveable { mutableStateOf(ThreatType.VIRUS) }
  var packagePattern by rememberSaveable { mutableStateOf("") }
  var sha256 by rememberSaveable { mutableStateOf("") }
  var description by rememberSaveable { mutableStateOf("") }

  AlertDialog(
    onDismissRequest = onDismiss,
    title = { Text("Adicionar assinatura maliciosa") },
    text = {
      Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
          value = name,
          onValueChange = { name = it },
          label = { Text("Nome da ameaça") },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().testTag("custom_threat_name_input"),
        )
        Row(
          horizontalArrangement = Arrangement.spacedBy(6.dp),
          modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        ) {
          ThreatType.entries.forEach { t ->
            FilterChip(
              selected = selectedType == t,
              onClick = { selectedType = t },
              label = { Text(t.labelPt, maxLines = 1) },
            )
          }
        }
        OutlinedTextField(
          value = packagePattern,
          onValueChange = { packagePattern = it },
          label = { Text("Pacote (ex: com.app.falso)") },
          singleLine = true,
          modifier = Modifier.fillMaxWidth().testTag("custom_threat_pkg_input"),
        )
        OutlinedTextField(
          value = sha256,
          onValueChange = { sha256 = it },
          label = { Text("SHA-256 (opcional)") },
          singleLine = true,
          modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
          value = description,
          onValueChange = { description = it },
          label = { Text("Descrição") },
          modifier = Modifier.fillMaxWidth(),
        )
      }
    },
    confirmButton = {
      Button(
        onClick = { onConfirm(name, selectedType, packagePattern, sha256, description) },
        enabled = name.isNotBlank() && (packagePattern.isNotBlank() || sha256.isNotBlank()),
        modifier = Modifier.testTag("confirm_custom_threat_btn"),
      ) {
        Text("Salvar")
      }
    },
    dismissButton = {
      TextButton(onClick = onDismiss) {
        Text("Cancelar")
      }
    },
  )
}
