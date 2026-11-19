package com.example.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.OpenInNew
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.ScanAuditEntity
import com.example.data.local.SecurityVerdict
import com.example.security.BehaviorMonitorEngine
import com.example.ui.AuditDetailUiState
import com.example.ui.components.FingerprintMonospaceBox
import com.example.ui.components.RiskScoreGauge
import com.example.ui.components.TechnicalDetailsExpandable
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatDateOnlyPt
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.friendlyInstallerSource
import com.example.ui.components.friendlyVerdictExplanation

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AppDetailScreen(
  detailState: AuditDetailUiState,
  isWhitelisted: Boolean = false,
  onBack: () -> Unit,
  onTrustCert: (sha256: String, label: String, pkg: String) -> Unit,
  onBlockCert: (sha256: String, label: String, pkg: String) -> Unit,
  onToggleWhitelist: (ScanAuditEntity) -> Unit = {},
  onShowMessage: (String) -> Unit,
) {
  BackHandler(onBack = onBack)

  val context = LocalContext.current
  val clipboard = LocalClipboardManager.current
  val listState = rememberLazyListState()
  val loadedAudit = (detailState as? AuditDetailUiState.Ready)?.audit

  Scaffold(
    topBar = {
      TopAppBar(
        title = {
          Text(
            text = loadedAudit?.appName ?: "Detalhes do Aplicativo",
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
          )
        },
        navigationIcon = {
          IconButton(onClick = onBack, modifier = Modifier.testTag("detail_back_button")) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
          }
        },
      )
    }
  ) { innerPadding ->
    when (detailState) {
      AuditDetailUiState.Loading -> {
        Box(
          contentAlignment = Alignment.Center,
          modifier = Modifier.fillMaxSize().padding(innerPadding),
        ) {
          CircularProgressIndicator()
        }
      }

      AuditDetailUiState.NotFound -> {
        Box(
          contentAlignment = Alignment.Center,
          modifier = Modifier.fillMaxSize().padding(innerPadding).padding(24.dp),
        ) {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.widthIn(max = 440.dp).fillMaxWidth(),
          ) {
            Column(
              horizontalAlignment = Alignment.CenterHorizontally,
              verticalArrangement = Arrangement.spacedBy(12.dp),
              modifier = Modifier.padding(20.dp),
            ) {
              Text(
                text = "Detalhes indisponíveis",
                style = MaterialTheme.typography.titleLarge,
              )
              Text(
                text = "Esse registro foi substituído por uma verificação mais recente ou removido.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
              )
              Button(
                onClick = onBack,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().height(48.dp),
              ) {
                Text("Voltar")
              }
            }
          }
        }
      }

      is AuditDetailUiState.Ready -> {
        val audit = detailState.audit
        val verdict =
          remember(audit.verdict) {
            runCatching { SecurityVerdict.valueOf(audit.verdict) }.getOrDefault(SecurityVerdict.SEGURO)
          }
        val permissionsList =
          remember(audit.dangerousPermissions) {
            audit.dangerousPermissions.split(",").filter { it.isNotBlank() }
          }
        val formattedValidUntil = remember(audit.validUntilMillis) { formatDateOnlyPt(audit.validUntilMillis) }
        val formattedScannedAt = remember(audit.scannedAt) { formatTimestampPt(audit.scannedAt) }
        val friendlySource =
          remember(audit.installerSource, audit.isSystemApp, audit.sourceType) {
            friendlyInstallerSource(audit.installerSource, audit.isSystemApp, audit.sourceType)
          }

        Box(
          contentAlignment = Alignment.TopCenter,
          modifier = Modifier.fillMaxSize().padding(innerPadding),
        ) {
          LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
            contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
          ) {
            // 1. Calm Overview Card
            item(key = "detail_header") {
              Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
              ) {
                Column(
                  verticalArrangement = Arrangement.spacedBy(12.dp),
                  modifier = Modifier.padding(18.dp),
                ) {
                  Row(verticalAlignment = Alignment.CenterVertically) {
                    RiskScoreGauge(score = audit.riskScore, verdict = verdict, size = 88.dp)
                    Spacer(Modifier.width(14.dp))
                    Column(modifier = Modifier.weight(1f)) {
                      Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                      ) {
                        VerdictBadge(verdict)
                        if (isWhitelisted) {
                          Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            contentColor = MaterialTheme.colorScheme.secondary,
                            shape = RoundedCornerShape(50),
                            modifier = Modifier.testTag("detail_whitelist_badge"),
                          ) {
                            Text(
                              text = "Confiável",
                              style = MaterialTheme.typography.labelSmall,
                              modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                            )
                          }
                        }
                      }
                      Spacer(Modifier.height(6.dp))
                      Text(text = audit.appName, style = MaterialTheme.typography.titleLarge)
                      Spacer(Modifier.height(2.dp))
                      Text(
                        text = "$friendlySource • Versão ${audit.versionName}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                      )
                    }
                  }

                  Text(
                    text = friendlyVerdictExplanation(verdict),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface,
                  )
                }
              }
            }

            // 2. Plain Summary & Simple Actions Card
            item(key = "detail_behavior") {
              Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
              ) {
                Column(
                  modifier = Modifier.padding(18.dp),
                  verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                  Text(text = "O que foi verificado", style = MaterialTheme.typography.titleMedium)
                  Text(
                    text = audit.findingsSummary,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                  )

                  if (audit.sourceType != "APK_PRE_INSTALL") {
                    OutlinedButton(
                      onClick = {
                        onToggleWhitelist(audit)
                        onShowMessage(
                          if (isWhitelisted) "${audit.appName} removido dos apps confiáveis."
                          else "${audit.appName} marcado como confiável."
                        )
                      },
                      shape = RoundedCornerShape(12.dp),
                      modifier = Modifier.fillMaxWidth().height(48.dp).testTag("detail_whitelist_toggle_btn"),
                    ) {
                      Icon(Icons.Filled.VerifiedUser, contentDescription = null)
                      Spacer(Modifier.width(8.dp))
                      Text(
                        if (isWhitelisted) "Remover dos apps confiáveis"
                        else "Confiar neste aplicativo"
                      )
                    }
                  }

                  if (audit.sourceType != "APK_PRE_INSTALL" && !audit.isSystemApp) {
                    OutlinedButton(
                      onClick = {
                        val intent =
                          Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                            data = Uri.fromParts("package", audit.packageName, null)
                            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                          }
                        runCatching { context.startActivity(intent) }
                      },
                      shape = RoundedCornerShape(12.dp),
                      modifier = Modifier.fillMaxWidth().height(48.dp).testTag("open_system_app_info_btn"),
                    ) {
                      Icon(Icons.Filled.OpenInNew, contentDescription = null)
                      Spacer(Modifier.width(8.dp))
                      Text("Abrir nas configurações / Desinstalar")
                    }
                  }
                }
              }
            }

            // 3. Collapsible Technical Details (for curious/advanced users)
            item(key = "detail_signature") {
              TechnicalDetailsExpandable(
                title = "Detalhes técnicos e certificado",
                subtitle = "Código SHA-256, permissões, pacote e consumo de rede",
                testTag = "detail_technical_toggle",
              ) {
                Text(
                  text = "Identificador do pacote: ${audit.packageName}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                  text = "Versão Android alvo (SDK): ${audit.targetSdk} • Verificado em $formattedScannedAt",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (audit.sourceType != "APK_PRE_INSTALL") {
                  Text(
                    text =
                      "Uso de rede na sessão: Enviados ${BehaviorMonitorEngine.formatBytes(audit.txBytes)} • Recebidos ${BehaviorMonitorEngine.formatBytes(audit.rxBytes)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                  )
                }

                FingerprintMonospaceBox(
                  label = "SHA-256",
                  fingerprint = audit.sha256Fingerprint,
                  onCopy = {
                    clipboard.setText(AnnotatedString(audit.sha256Fingerprint))
                    onShowMessage("SHA-256 copiado")
                  },
                )

                FingerprintMonospaceBox(
                  label = "SHA-1",
                  fingerprint = audit.sha1Fingerprint,
                  onCopy = {
                    clipboard.setText(AnnotatedString(audit.sha1Fingerprint))
                    onShowMessage("SHA-1 copiado")
                  },
                )

                Text(
                  text = "Responsável: ${audit.signerSubject}",
                  style = MaterialTheme.typography.bodySmall,
                )
                Text(
                  text = "Emissor: ${audit.signerIssuer}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                  text = "Chave: ${audit.keyAlgorithmInfo} • Validade: $formattedValidUntil",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                if (permissionsList.isNotEmpty()) {
                  HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
                  Text(text = "Permissões sensíveis", style = MaterialTheme.typography.titleSmall)
                  FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                  ) {
                    permissionsList.forEach { perm ->
                      AssistChip(
                        onClick = {},
                        label = {
                          Text(
                            text = perm.removePrefix("android.permission."),
                            style = MaterialTheme.typography.labelSmall,
                          )
                        },
                      )
                    }
                  }
                }

                if (audit.sha256Fingerprint != "SEM ASSINATURA") {
                  Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                  ) {
                    Button(
                      onClick = {
                        onBlockCert(audit.sha256Fingerprint, audit.appName, audit.packageName)
                        onShowMessage("Assinatura bloqueada")
                      },
                      shape = RoundedCornerShape(12.dp),
                      colors =
                        ButtonDefaults.buttonColors(
                          containerColor = MaterialTheme.colorScheme.error,
                          contentColor = MaterialTheme.colorScheme.onError,
                        ),
                      modifier = Modifier.weight(1f).height(48.dp).testTag("detail_block_cert_btn"),
                    ) {
                      Text("Bloquear Assinatura", maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    OutlinedButton(
                      onClick = {
                        onTrustCert(audit.sha256Fingerprint, audit.appName, audit.packageName)
                        onShowMessage("Assinatura confiável")
                      },
                      shape = RoundedCornerShape(12.dp),
                      modifier = Modifier.weight(1f).height(48.dp).testTag("detail_trust_cert_btn"),
                    ) {
                      Text("Confiar", maxLines = 1)
                    }
                  }
                }
              }
            }

            item(key = "detail_spacer") { Spacer(Modifier.height(12.dp)) }
          }
        }
      }
    }
  }
}
