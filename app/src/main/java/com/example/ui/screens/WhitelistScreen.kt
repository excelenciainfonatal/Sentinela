package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AddCircleOutline
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.SecurityVerdict
import com.example.ui.SentinelaUiState
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.friendlyInstallerSource

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WhitelistScreen(
  uiState: SentinelaUiState,
  onBack: () -> Unit,
  onAddToWhitelist: (packageName: String, appName: String, sha256: String) -> Unit,
  onRemoveFromWhitelist: (packageName: String) -> Unit,
  onClearWhitelist: () -> Unit,
  onShowMessage: (String) -> Unit,
) {
  BackHandler(onBack = onBack)

  var searchQuery by rememberSaveable { mutableStateOf("") }

  val availableApps =
    remember(uiState.installedApps, uiState.whitelistedPackageNames, searchQuery) {
      val query = searchQuery.trim()
      uiState.installedApps.filter { app ->
        val notWhitelisted = app.packageName !in uiState.whitelistedPackageNames
        val matchesQuery =
          query.isEmpty() ||
            app.appName.contains(query, ignoreCase = true) ||
            app.packageName.contains(query, ignoreCase = true)
        notWhitelisted && matchesQuery
      }
    }

  Scaffold(
    topBar = {
      TopAppBar(
        title = { Text("Apps Confiáveis") },
        navigationIcon = {
          IconButton(onClick = onBack, modifier = Modifier.testTag("whitelist_back_button")) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
          }
        },
        actions = {
          if (uiState.whitelistedApps.isNotEmpty()) {
            IconButton(
              onClick = {
                onClearWhitelist()
                onShowMessage("Lista limpa — aplicativos voltarão a ser verificados.")
              },
              modifier = Modifier.testTag("whitelist_clear_button"),
            ) {
              Icon(
                imageVector = Icons.Filled.DeleteSweep,
                contentDescription = "Limpar lista de confiáveis",
              )
            }
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
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        // Friendly Info Card
        item {
          Card(
            colors =
              CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.45f)
              ),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary.copy(alpha = 0.4f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(16.dp),
            ) {
              Surface(
                color = MaterialTheme.colorScheme.secondaryContainer,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.size(44.dp),
              ) {
                Box(contentAlignment = Alignment.Center) {
                  Icon(
                    imageVector = Icons.Filled.VerifiedUser,
                    contentDescription = "Apps confiáveis",
                    tint = MaterialTheme.colorScheme.secondary,
                  )
                }
              }
              Spacer(Modifier.width(12.dp))
              Column(modifier = Modifier.weight(1f)) {
                Text(
                  text = "Apps que você já confia",
                  style = MaterialTheme.typography.titleMedium,
                )
                Text(
                  text =
                    "Aplicativos marcados aqui não geram alertas nem são sinalizados pelo monitoramento automático.",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
            }
          }
        }

        // Current Trusted Apps Header
        item {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Text(
              text = "Na sua lista (${uiState.whitelistedApps.size})",
              style = MaterialTheme.typography.titleLarge,
            )
            if (uiState.whitelistedApps.isNotEmpty()) {
              TextButton(
                onClick = {
                  onClearWhitelist()
                  onShowMessage("Lista de apps confiáveis limpa.")
                }
              ) {
                Text("Limpar tudo")
              }
            }
          }
        }

        if (uiState.whitelistedApps.isEmpty()) {
          item {
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth().testTag("whitelist_empty_card"),
            ) {
              Text(
                text =
                  "Nenhum aplicativo na lista ainda. Toque em \"Confiar\" abaixo em qualquer aplicativo que você conhece e confia.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
              )
            }
          }
        } else {
          items(uiState.whitelistedApps, key = { "wl_${it.packageName}" }) { app ->
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary.copy(alpha = 0.4f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth().testTag("whitelist_item_${app.packageName}"),
            ) {
              Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(14.dp),
              ) {
                Column(modifier = Modifier.weight(1f)) {
                  Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                      text = app.appName,
                      style = MaterialTheme.typography.titleMedium,
                      maxLines = 1,
                      overflow = TextOverflow.Ellipsis,
                      modifier = Modifier.weight(1f, fill = false),
                    )
                    Spacer(Modifier.width(8.dp))
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
                  Spacer(Modifier.height(4.dp))
                  Text(
                    text = "Adicionado em ${formatTimestampPt(app.addedAt)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                  onClick = {
                    onRemoveFromWhitelist(app.packageName)
                    onShowMessage("${app.appName} removido da lista.")
                  },
                  colors =
                    ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                  shape = RoundedCornerShape(12.dp),
                  modifier = Modifier.height(48.dp).testTag("whitelist_remove_${app.packageName}"),
                ) {
                  Icon(
                    imageVector = Icons.Filled.DeleteOutline,
                    contentDescription = "Remover ${app.appName}",
                    modifier = Modifier.size(18.dp),
                  )
                  Spacer(Modifier.width(4.dp))
                  Text("Remover")
                }
              }
            }
          }
        }

        // Section 2: Add Installed App
        item {
          Spacer(Modifier.height(4.dp))
          Text(
            text = "Adicionar aplicativo do celular",
            style = MaterialTheme.typography.titleLarge,
          )
          Spacer(Modifier.height(8.dp))
          OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Procurar app para confiar...") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(14.dp),
            modifier = Modifier.fillMaxWidth().testTag("whitelist_search_input"),
          )
        }

        if (availableApps.isEmpty()) {
          item {
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Text(
                text =
                  if (uiState.installedApps.isEmpty())
                    "Faça uma verificação no Início para listar seus aplicativos."
                  else "Nenhum aplicativo encontrado com esse nome.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
              )
            }
          }
        } else {
          items(availableApps, key = { "avail_${it.packageName}" }) { app ->
            val verdict =
              runCatching { SecurityVerdict.valueOf(app.verdict) }.getOrDefault(SecurityVerdict.SEGURO)
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth().testTag("whitelist_candidate_${app.packageName}"),
            ) {
              Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(14.dp),
              ) {
                Column(modifier = Modifier.weight(1f)) {
                  Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                      text = app.appName,
                      style = MaterialTheme.typography.titleMedium,
                      maxLines = 1,
                      overflow = TextOverflow.Ellipsis,
                      modifier = Modifier.weight(1f, fill = false),
                    )
                    Spacer(Modifier.width(8.dp))
                    VerdictBadge(verdict)
                  }
                  Spacer(Modifier.height(4.dp))
                  Text(
                    text =
                      friendlyInstallerSource(
                        app.installerSource,
                        app.isSystemApp,
                        app.sourceType,
                      ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                  )
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                  onClick = {
                    onAddToWhitelist(app.packageName, app.appName, app.sha256Fingerprint)
                    onShowMessage("${app.appName} adicionado aos apps confiáveis.")
                  },
                  shape = RoundedCornerShape(12.dp),
                  modifier = Modifier.height(48.dp).testTag("whitelist_add_${app.packageName}"),
                ) {
                  Icon(
                    imageVector = Icons.Filled.AddCircleOutline,
                    contentDescription = "Confiar em ${app.appName}",
                    modifier = Modifier.size(18.dp),
                  )
                  Spacer(Modifier.width(4.dp))
                  Text("Confiar")
                }
              }
            }
          }
        }

        item { Spacer(Modifier.height(12.dp)) }
      }
    }
  }
}
