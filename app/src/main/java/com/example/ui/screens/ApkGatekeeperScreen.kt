package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.SecurityVerdict
import com.example.security.ApkInspectionReport
import com.example.security.BehaviorMonitorEngine
import com.example.ui.SentinelaUiState
import com.example.ui.components.FingerprintMonospaceBox
import com.example.ui.components.RiskScoreGauge
import com.example.ui.components.TechnicalDetailsExpandable
import com.example.ui.components.ThreatSignalBadgesRow
import com.example.ui.components.VerdictBadge
import com.example.ui.components.formatDateOnlyPt
import com.example.ui.components.formatTimestampPt
import com.example.ui.components.verdictColor
import com.example.ui.components.verdictContainerColor

@Composable
fun ApkGatekeeperScreen(
  uiState: SentinelaUiState,
  onPickApk: () -> Unit,
  onClearReport: () -> Unit,
  onDismissError: () -> Unit,
  onBlockCert: (sha256: String, label: String, pkg: String) -> Unit,
  onTrustCert: (sha256: String, label: String, pkg: String) -> Unit,
  onDeleteAudit: (Long) -> Unit,
  onOpenAuditDetail: (Long) -> Unit,
  onShowMessage: (String) -> Unit,
  modifier: Modifier = Modifier,
) {
  val clipboard = LocalClipboardManager.current

  Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
    LazyColumn(
      modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
      contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
      verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
      // Friendly Upload / Inspection Card
      item {
        Card(
          colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
          shape = MaterialTheme.shapes.large,
          modifier = Modifier.fillMaxWidth(),
        ) {
          Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
              Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier.size(48.dp),
              ) {
                Box(contentAlignment = Alignment.Center) {
                  Icon(
                    imageVector = Icons.Filled.Security,
                    contentDescription = "Verificador de arquivo APK",
                    tint = MaterialTheme.colorScheme.primary,
                  )
                }
              }
              Spacer(Modifier.width(14.dp))
              Column {
                Text(
                  text = "Verificar antes de instalar",
                  style = MaterialTheme.typography.titleLarge,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                  text =
                    "Baixou um aplicativo pela internet? Analise o arquivo .APK aqui antes de instalar no celular.",
                  style = MaterialTheme.typography.bodyMedium,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
            }

            Spacer(Modifier.height(18.dp))

            Button(
              onClick = onPickApk,
              enabled = !uiState.isInspectingApk,
              shape = RoundedCornerShape(14.dp),
              modifier = Modifier.fillMaxWidth().height(52.dp).testTag("select_apk_button"),
            ) {
              if (uiState.isInspectingApk) {
                CircularProgressIndicator(
                  strokeWidth = 2.dp,
                  color = MaterialTheme.colorScheme.onPrimary,
                  modifier = Modifier.size(18.dp),
                )
                Spacer(Modifier.width(10.dp))
                Text("Analisando arquivo...")
              } else {
                Icon(Icons.Filled.FileOpen, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Escolher arquivo .APK")
              }
            }
          }
        }
      }

      // Friendly Error Card
      uiState.apkErrorMessage?.let { errorMsg ->
        item {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.5f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(14.dp),
            ) {
              Icon(
                imageVector = Icons.Filled.GppBad,
                contentDescription = "Erro na leitura do arquivo",
                tint = MaterialTheme.colorScheme.error,
              )
              Spacer(Modifier.width(10.dp))
              Text(
                text = errorMsg,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.weight(1f),
              )
              TextButton(onClick = onDismissError) {
                Text("Fechar", color = MaterialTheme.colorScheme.onErrorContainer)
              }
            }
          }
        }
      }

      // Active Detailed Verdict Report
      uiState.latestApkReport?.let { report ->
        item {
          GatekeeperReportCard(
            report = report,
            onCopySha = {
              clipboard.setText(AnnotatedString(report.signatureAnalysis.sha256Fingerprint))
              onShowMessage("Código de verificação copiado")
            },
            onBlockCert = {
              onBlockCert(
                report.signatureAnalysis.sha256Fingerprint,
                report.audit.appName,
                report.audit.packageName,
              )
              onShowMessage("Aplicativo marcado como bloqueado")
            },
            onTrustCert = {
              onTrustCert(
                report.signatureAnalysis.sha256Fingerprint,
                report.audit.appName,
                report.audit.packageName,
              )
              onShowMessage("Aplicativo marcado como confiável")
            },
            onClose = onClearReport,
          )
        }
      }

      // History Section
      item {
        Text(
          text = "Arquivos analisados recentemente",
          style = MaterialTheme.typography.titleLarge,
          modifier = Modifier.padding(top = 4.dp),
        )
      }

      if (uiState.apkAudits.isEmpty()) {
        item {
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
          ) {
            Column(
              horizontalAlignment = Alignment.CenterHorizontally,
              modifier = Modifier.fillMaxWidth().padding(28.dp),
            ) {
              Icon(
                imageVector = Icons.Filled.VerifiedUser,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(38.dp),
              )
              Spacer(Modifier.height(10.dp))
              Text(
                text = "Nenhum arquivo verificado ainda",
                style = MaterialTheme.typography.titleMedium,
                textAlign = TextAlign.Center,
              )
              Spacer(Modifier.height(4.dp))
              Text(
                text =
                  "Toque em \"Escolher arquivo .APK\" acima sempre que baixar um aplicativo fora da Play Store.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
              )
            }
          }
        }
      } else {
        items(uiState.apkAudits, key = { "apk_hist_${it.id}" }) { audit ->
          val verdict =
            runCatching { SecurityVerdict.valueOf(audit.verdict) }.getOrDefault(SecurityVerdict.SUSPEITO)
          Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
            shape = MaterialTheme.shapes.large,
            modifier =
              Modifier.fillMaxWidth()
                .clickable { onOpenAuditDetail(audit.id) }
                .testTag("apk_history_item_${audit.id}"),
          ) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              modifier = Modifier.padding(14.dp),
            ) {
              Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                  Text(
                    text = audit.appName,
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
                  text = "Versão ${audit.versionName} • ${formatTimestampPt(audit.scannedAt)}",
                  style = MaterialTheme.typography.bodySmall,
                  color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
              }
              IconButton(
                onClick = { onDeleteAudit(audit.id) },
                modifier = Modifier.size(48.dp).testTag("delete_apk_audit_${audit.id}"),
              ) {
                Icon(
                  imageVector = Icons.Filled.DeleteOutline,
                  contentDescription = "Remover registro",
                  tint = MaterialTheme.colorScheme.onSurfaceVariant,
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun GatekeeperReportCard(
  report: ApkInspectionReport,
  onCopySha: () -> Unit,
  onBlockCert: () -> Unit,
  onTrustCert: () -> Unit,
  onClose: () -> Unit,
) {
  val verdict =
    runCatching { SecurityVerdict.valueOf(report.audit.verdict) }.getOrDefault(SecurityVerdict.SUSPEITO)
  val accent = verdictColor(verdict)
  val container = verdictContainerColor(verdict)

  val headline =
    when (verdict) {
      SecurityVerdict.BLOQUEADO -> "Não recomendamos instalar este app"
      SecurityVerdict.SUSPEITO -> "Atenção: verifique se você confia na fonte"
      SecurityVerdict.SEGURO -> "Parece seguro para instalar"
    }

  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.5.dp, accent.copy(alpha = 0.7f)),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth().testTag("gatekeeper_report_card"),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
      Surface(
        color = container,
        contentColor = accent,
        shape = RoundedCornerShape(14.dp),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Row(
          verticalAlignment = Alignment.CenterVertically,
          modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
        ) {
          Icon(
            imageVector =
              when (verdict) {
                SecurityVerdict.BLOQUEADO -> Icons.Filled.Block
                SecurityVerdict.SUSPEITO -> Icons.Filled.Warning
                SecurityVerdict.SEGURO -> Icons.Filled.CheckCircle
              },
            contentDescription = headline,
          )
          Spacer(Modifier.width(10.dp))
          Text(
            text = headline,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold,
          )
        }
      }

      Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
      ) {
        RiskScoreGauge(score = report.audit.riskScore, verdict = verdict, size = 84.dp)
        Spacer(Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
          Text(text = report.audit.appName, style = MaterialTheme.typography.titleLarge)
          Spacer(Modifier.height(2.dp))
          Text(
            text =
              "${report.fileName} (${BehaviorMonitorEngine.formatBytes(report.fileSizeBytes)})",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
          Spacer(Modifier.height(6.dp))
          ThreatSignalBadgesRow(audit = report.audit)
        }
      }

      Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(text = "O que encontramos", style = MaterialTheme.typography.titleMedium)
        report.findings.forEach { finding ->
          Text(
            text = "• $finding",
            style = MaterialTheme.typography.bodyMedium,
            color =
              if (verdict == SecurityVerdict.BLOQUEADO) MaterialTheme.colorScheme.error
              else MaterialTheme.colorScheme.onSurface,
          )
        }
      }

      if (report.signatureAnalysis.hasSignature) {
        Row(
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          modifier = Modifier.fillMaxWidth(),
        ) {
          Button(
            onClick = onBlockCert,
            colors =
              ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
                contentColor = MaterialTheme.colorScheme.onError,
              ),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.weight(1f).height(48.dp).testTag("report_block_cert_button"),
          ) {
            Text("Bloquear App", maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
          OutlinedButton(
            onClick = onTrustCert,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.weight(1f).height(48.dp).testTag("report_trust_cert_button"),
          ) {
            Text("Confiar", maxLines = 1, overflow = TextOverflow.Ellipsis)
          }
        }
      }

      TechnicalDetailsExpandable(
        title = "Detalhes técnicos",
        subtitle = "Certificado digital, pacote e permissões",
        testTag = "gatekeeper_technical_toggle",
      ) {
        Text(
          text = "Pacote: ${report.audit.packageName}",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
          text =
            "Target SDK ${report.audit.targetSdk} • ${report.dexCount} DEX" +
              if (report.nativeAbis.isNotEmpty()) " • ABIs: ${report.nativeAbis.joinToString()}"
              else "",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.primary,
        )
        FingerprintMonospaceBox(
          label = "Assinatura SHA-256",
          fingerprint = report.signatureAnalysis.sha256Fingerprint,
          onCopy = onCopySha,
        )
        Text(
          text = "Responsável: ${report.signatureAnalysis.subject}",
          style = MaterialTheme.typography.bodySmall,
        )
        Text(
          text = "Validade: ${formatDateOnlyPt(report.signatureAnalysis.validUntilMillis)}",
          style = MaterialTheme.typography.bodySmall,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (report.fileSha256.isNotBlank()) {
          Text(
            text = "SHA-256 do arquivo .APK: ${report.fileSha256}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        if (report.staticIndicators.isNotEmpty()) {
          Text(
            text = "Indicadores estáticos detectados: ${report.staticIndicators.joinToString()}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
          )
        }
        if (report.dangerousPermissions.isNotEmpty()) {
          Text(text = "Permissões solicitadas", style = MaterialTheme.typography.titleSmall)
          FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
          ) {
            report.dangerousPermissions.forEach { perm ->
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
      }

      TextButton(onClick = onClose, modifier = Modifier.align(Alignment.End)) {
        Text("Fechar resultado")
      }
    }
  }
}
