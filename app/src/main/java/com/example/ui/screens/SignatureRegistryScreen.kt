package com.example.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.local.TrustStatus
import com.example.ui.CertificateSummary
import com.example.ui.SentinelaUiState
import com.example.ui.SignatureFilter
import com.example.ui.components.FingerprintMonospaceBox
import com.example.ui.components.TrustStatusBadge
import com.example.ui.components.formatDateOnlyPt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignatureRegistryScreen(
  uiState: SentinelaUiState,
  onBack: () -> Unit,
  onFilterChange: (SignatureFilter) -> Unit,
  onTrustCert: (sha256: String, label: String, pkgHint: String) -> Unit,
  onBlockCert: (sha256: String, label: String, pkgHint: String) -> Unit,
  onResetRule: (sha256: String) -> Unit,
  onShowMessage: (String) -> Unit,
  modifier: Modifier = Modifier,
) {
  BackHandler(onBack = onBack)

  val clipboard = LocalClipboardManager.current
  val filtered =
    uiState.certificateSummaries.filter { cert ->
      when (uiState.signatureFilter) {
        SignatureFilter.TODOS -> true
        SignatureFilter.CONFIAVEIS -> cert.trustStatus == TrustStatus.TRUSTED
        SignatureFilter.BLOQUEADOS -> cert.trustStatus == TrustStatus.BLOCKED
        SignatureFilter.ALERTAS -> cert.isDebugCert || cert.isExpiredCert
      }
    }

  Scaffold(
    topBar = {
      TopAppBar(
        title = { Text("Assinaturas Digitais") },
        navigationIcon = {
          IconButton(onClick = onBack, modifier = Modifier.testTag("signatures_back_button")) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Voltar")
          }
        },
      )
    },
    modifier = modifier,
  ) { innerPadding ->
    Box(
      modifier = Modifier.fillMaxSize().padding(innerPadding),
      contentAlignment = Alignment.TopCenter,
    ) {
      LazyColumn(
        modifier = Modifier.fillMaxSize().widthIn(max = 720.dp),
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        item {
          Column {
            Text(
              text =
                "Cada desenvolvedor assina seus aplicativos com uma chave única. Aqui você decide quais criadores são confiáveis ou devem ser bloqueados.",
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            Row(
              horizontalArrangement = Arrangement.spacedBy(8.dp),
              modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            ) {
              SignatureFilter.entries.forEach { filter ->
                FilterChip(
                  selected = uiState.signatureFilter == filter,
                  onClick = { onFilterChange(filter) },
                  label = { Text(filter.labelPt) },
                  modifier = Modifier.testTag("sig_filter_${filter.name.lowercase()}"),
                )
              }
            }
          }
        }

        if (filtered.isEmpty()) {
          item {
            Card(
              colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
              border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.3f)),
              shape = MaterialTheme.shapes.large,
              modifier = Modifier.fillMaxWidth(),
            ) {
              Text(
                text = "Nenhuma assinatura encontrada para esse filtro.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(18.dp),
              )
            }
          }
        } else {
          items(filtered, key = { it.sha256 }) { cert ->
            CertificateCard(
              cert = cert,
              onCopy = {
                clipboard.setText(AnnotatedString(cert.sha256))
                onShowMessage("Código copiado")
              },
              onTrust = {
                onTrustCert(
                  cert.sha256,
                  cert.appNames.firstOrNull() ?: cert.subject,
                  cert.primaryPackageHint,
                )
                onShowMessage("Assinatura marcada como confiável")
              },
              onBlock = {
                onBlockCert(
                  cert.sha256,
                  cert.appNames.firstOrNull() ?: cert.subject,
                  cert.primaryPackageHint,
                )
                onShowMessage("Assinatura bloqueada")
              },
              onReset = {
                onResetRule(cert.sha256)
                onShowMessage("Regra removida")
              },
            )
          }
        }

        item { Spacer(Modifier.height(12.dp)) }
      }
    }
  }
}

@Composable
private fun CertificateCard(
  cert: CertificateSummary,
  onCopy: () -> Unit,
  onTrust: () -> Unit,
  onBlock: () -> Unit,
  onReset: () -> Unit,
) {
  val borderColor =
    when {
      cert.trustStatus == TrustStatus.BLOCKED -> MaterialTheme.colorScheme.error.copy(alpha = 0.6f)
      cert.isDebugCert || cert.isExpiredCert -> MaterialTheme.colorScheme.tertiary.copy(alpha = 0.6f)
      cert.trustStatus == TrustStatus.TRUSTED -> MaterialTheme.colorScheme.secondary.copy(alpha = 0.6f)
      else -> MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)
    }

  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, borderColor),
    shape = MaterialTheme.shapes.large,
    modifier = Modifier.fillMaxWidth(),
  ) {
    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Text(
          text = cert.appNames.joinToString(", "),
          style = MaterialTheme.typography.titleMedium,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
          modifier = Modifier.weight(1f),
        )
        TrustStatusBadge(cert.trustStatus)
      }

      FingerprintMonospaceBox(
        label = "Código de verificação (SHA-256)",
        fingerprint = cert.sha256,
        onCopy = onCopy,
      )

      Text(
        text = "Responsável: ${cert.subject}",
        style = MaterialTheme.typography.bodySmall,
        maxLines = 2,
        overflow = TextOverflow.Ellipsis,
      )
      Text(
        text = "Validade: ${formatDateOnlyPt(cert.validUntilMillis)}",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )

      if (cert.isDebugCert || cert.isExpiredCert) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Icon(
            imageVector = Icons.Filled.Warning,
            contentDescription = "Alerta de certificado",
            tint = MaterialTheme.colorScheme.tertiary,
            modifier = Modifier.padding(end = 6.dp),
          )
          Text(
            text =
              buildList {
                if (cert.isDebugCert) add("Chave de teste não oficial")
                if (cert.isExpiredCert) add("Assinatura expirada")
              }.joinToString(" • "),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.tertiary,
          )
        }
      }

      Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth().padding(top = 2.dp),
      ) {
        if (cert.trustStatus != TrustStatus.TRUSTED) {
          OutlinedButton(
            onClick = onTrust,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.weight(1f).height(48.dp).testTag("trust_cert_${cert.sha256.take(8)}"),
          ) {
            Text("Confiar", maxLines = 1)
          }
        }
        if (cert.trustStatus != TrustStatus.BLOCKED) {
          Button(
            onClick = onBlock,
            shape = RoundedCornerShape(12.dp),
            colors =
              ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.error,
                contentColor = MaterialTheme.colorScheme.onError,
              ),
            modifier = Modifier.weight(1f).height(48.dp).testTag("block_cert_${cert.sha256.take(8)}"),
          ) {
            Text("Bloquear", maxLines = 1)
          }
        }
        if (cert.trustStatus != TrustStatus.NEUTRAL) {
          TextButton(
            onClick = onReset,
            modifier = Modifier.height(48.dp).testTag("reset_cert_${cert.sha256.take(8)}"),
          ) {
            Text("Remover regra")
          }
        }
      }
    }
  }
}
