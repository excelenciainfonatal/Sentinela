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
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CalendarToday
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.ScanHistoryEntity
import com.example.data.local.SecurityVerdict
import com.example.ui.HistoryFilter
import com.example.ui.components.VerdictBadge
import com.example.ui.components.verdictColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val detailedScanDateFormatter =
  object : ThreadLocal<SimpleDateFormat>() {
    override fun initialValue(): SimpleDateFormat {
      return SimpleDateFormat("dd/MM/yyyy 'às' HH:mm", Locale("pt", "BR"))
    }
  }

@Composable
fun ScanHistoryScreen(
  scanHistory: List<ScanHistoryEntity>,
  historyFilter: HistoryFilter,
  historySearchQuery: String,
  onFilterChange: (HistoryFilter) -> Unit,
  onSearchChange: (String) -> Unit,
  onDeleteEntry: (Long) -> Unit,
  onClearHistory: () -> Unit,
  onOpenAuditDetail: (Long, String) -> Unit,
  modifier: Modifier = Modifier,
) {
  var showClearConfirm by remember { mutableStateOf(false) }
  val listState = rememberLazyListState()
  val filterScrollState = rememberScrollState()

  val filteredHistory =
    remember(scanHistory, historyFilter, historySearchQuery) {
      val query = historySearchQuery.trim()
      scanHistory.filter { entry ->
        val matchesFilter =
          when (historyFilter) {
            HistoryFilter.TODOS -> true
            HistoryFilter.BLOQUEADOS -> entry.verdict == SecurityVerdict.BLOQUEADO.name
            HistoryFilter.SUSPEITOS -> entry.verdict == SecurityVerdict.SUSPEITO.name
            HistoryFilter.SEGUROS -> entry.verdict == SecurityVerdict.SEGURO.name
          }
        val matchesQuery =
          query.isEmpty() ||
            entry.appName.contains(query, ignoreCase = true) ||
            entry.packageName.contains(query, ignoreCase = true)
        matchesFilter && matchesQuery
      }
    }

  val counts =
    remember(scanHistory) {
      var blocked = 0
      var suspicious = 0
      var safe = 0
      for (entry in scanHistory) {
        when (entry.verdict) {
          SecurityVerdict.BLOQUEADO.name -> blocked++
          SecurityVerdict.SUSPEITO.name -> suspicious++
          SecurityVerdict.SEGURO.name -> safe++
        }
      }
      intArrayOf(scanHistory.size, blocked, suspicious, safe)
    }

  val totalScans = counts[0]
  val blockedTotal = counts[1]
  val suspiciousTotal = counts[2]
  val safeTotal = counts[3]

  if (showClearConfirm) {
    AlertDialog(
      onDismissRequest = { showClearConfirm = false },
      title = { Text("Limpar histórico?") },
      text = {
        Text(
          "Isso apagará os $totalScans registros de verificações antigas. Novas verificações continuarão sendo salvas."
        )
      },
      confirmButton = {
        TextButton(
          onClick = {
            onClearHistory()
            showClearConfirm = false
          },
          modifier = Modifier.testTag("confirm_clear_history_btn"),
        ) {
          Text("Limpar Tudo", color = MaterialTheme.colorScheme.error)
        }
      },
      dismissButton = {
        TextButton(onClick = { showClearConfirm = false }) { Text("Cancelar") }
      },
    )
  }

  Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    LazyColumn(
      state = listState,
      modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
      contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
      // Friendly Summary Card
      item(key = "history_summary", contentType = "summary") {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
          shape = MaterialTheme.shapes.large,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.SpaceBetween,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                Icon(
                  imageVector = Icons.Filled.History,
                  contentDescription = "Histórico de verificações",
                  tint = MaterialTheme.colorScheme.primary,
                )
                Spacer(Modifier.width(10.dp))
                Column {
                  Text(
                    text = "Verificações realizadas",
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                  )
                  Text(
                    text = "$totalScans registro(s) salvo(s) no aparelho",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
              }
              if (totalScans > 0) {
                IconButton(
                  onClick = { showClearConfirm = true },
                  modifier = Modifier.size(48.dp).testTag("clear_scan_history_button"),
                ) {
                  Icon(
                    imageVector = Icons.Filled.DeleteSweep,
                    contentDescription = "Limpar histórico",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
              }
            }

            Row(
              horizontalArrangement = Arrangement.spacedBy(8.dp),
              modifier = Modifier.fillMaxWidth(),
            ) {
              HistoryStatPill(
                label = "Seguros",
                count = safeTotal,
                color = MaterialTheme.colorScheme.secondary,
                modifier = Modifier.weight(1f),
              )
              HistoryStatPill(
                label = "Atenção",
                count = suspiciousTotal,
                color = MaterialTheme.colorScheme.tertiary,
                modifier = Modifier.weight(1f),
              )
              HistoryStatPill(
                label = "Risco Alto",
                count = blockedTotal,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.weight(1f),
              )
            }
          }
        }
      }

      // Search & Filter Controls
      item(key = "history_controls", contentType = "controls") {
        Column {
          OutlinedTextField(
            value = historySearchQuery,
            onValueChange = onSearchChange,
            placeholder = { Text("Procurar no histórico...") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth().testTag("history_search_input"),
          )
          Spacer(Modifier.height(8.dp))
          Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth().horizontalScroll(filterScrollState),
          ) {
            HistoryFilter.entries.forEach { filter ->
              FilterChip(
                selected = historyFilter == filter,
                onClick = { onFilterChange(filter) },
                label = { Text(filter.labelPt, maxLines = 1, softWrap = false) },
                modifier = Modifier.testTag("history_filter_${filter.name.lowercase()}"),
              )
            }
          }
        }
      }

      if (filteredHistory.isEmpty()) {
        item(key = "history_empty", contentType = "empty") {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text =
                if (totalScans == 0)
                  "Nenhuma verificação feita ainda. Toque em \"Verificar Celular Agora\" no Início para começar."
                else "Nenhum registro encontrado para esse filtro.",
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              modifier = Modifier.padding(18.dp),
            )
          }
        }
      } else {
        items(
          items = filteredHistory,
          key = { "history_${it.id}" },
          contentType = { "history_row" },
        ) { entry ->
          ScanHistoryRowCard(
            entry = entry,
            onOpenAuditDetail = onOpenAuditDetail,
            onDeleteEntry = onDeleteEntry,
          )
        }
      }

      item(key = "history_bottom_spacer", contentType = "spacer") {
        Spacer(Modifier.height(12.dp))
      }
    }
  }
}

@Composable
private fun HistoryStatPill(
  label: String,
  count: Int,
  color: androidx.compose.ui.graphics.Color,
  modifier: Modifier = Modifier,
) {
  Surface(
    color = color.copy(alpha = 0.12f),
    contentColor = color,
    shape = RoundedCornerShape(14.dp),
    border = BorderStroke(1.dp, color.copy(alpha = 0.3f)),
    modifier = modifier,
  ) {
    Column(
      horizontalAlignment = Alignment.CenterHorizontally,
      modifier = Modifier.padding(vertical = 10.dp, horizontal = 6.dp),
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
        softWrap = false,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

@Composable
private fun ScanHistoryRowCard(
  entry: ScanHistoryEntity,
  onOpenAuditDetail: (Long, String) -> Unit,
  onDeleteEntry: (Long) -> Unit,
) {
  val verdict =
    remember(entry.verdict) {
      runCatching { SecurityVerdict.valueOf(entry.verdict) }.getOrDefault(SecurityVerdict.SEGURO)
    }
  val accent = verdictColor(verdict)
  val sourceLabel =
    when (entry.scanSource) {
      "GATEKEEPER_APK" -> "Verificação de arquivo"
      "TEMPO_REAL" -> "Instalação automática"
      else -> "Verificação do celular"
    }
  val formattedDate = remember(entry.scannedAt) { formatDetailedScanDate(entry.scannedAt) }
  val firstFinding =
    remember(entry.findingsSummary) {
      entry.findingsSummary.lineSequence().firstOrNull()?.removePrefix("• ") ?: ""
    }

  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
    shape = MaterialTheme.shapes.large,
    modifier =
      Modifier.fillMaxWidth()
        .clickable { onOpenAuditDetail(entry.auditId ?: -1L, entry.packageName) }
        .testTag("history_entry_${entry.id}"),
  ) {
    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = entry.appName,
            style = MaterialTheme.typography.titleMedium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
          Text(
            text = "$sourceLabel • v${entry.versionName}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
        Spacer(Modifier.width(8.dp))
        VerdictBadge(verdict)
      }

      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          modifier = Modifier.weight(1f),
        ) {
          Icon(
            imageVector = Icons.Filled.CalendarToday,
            contentDescription = "Data da verificação",
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(14.dp),
          )
          Spacer(Modifier.width(6.dp))
          Text(
            text = formattedDate,
            style = MaterialTheme.typography.labelMedium,
            color = accent,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        }
        IconButton(
          onClick = { onDeleteEntry(entry.id) },
          modifier = Modifier.size(48.dp).testTag("delete_history_entry_${entry.id}"),
        ) {
          Icon(
            imageVector = Icons.Filled.DeleteOutline,
            contentDescription = "Excluir registro",
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      }

      if (firstFinding.isNotBlank()) {
        Text(
          text = firstFinding,
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 2,
          overflow = TextOverflow.Ellipsis,
        )
      }
    }
  }
}

private fun formatDetailedScanDate(millis: Long): String {
  if (millis <= 0L) return "N/D"
  val sdf = detailedScanDateFormatter.get() ?: return "N/D"
  return sdf.format(Date(millis))
}
