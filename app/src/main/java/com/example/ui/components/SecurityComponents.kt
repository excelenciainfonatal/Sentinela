package com.example.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.example.data.local.SecurityVerdict
import com.example.data.local.TrustStatus
import com.example.ui.theme.MonoCodeStyle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun verdictColor(verdict: SecurityVerdict): Color {
  return when (verdict) {
    SecurityVerdict.SEGURO -> MaterialTheme.colorScheme.secondary
    SecurityVerdict.SUSPEITO -> MaterialTheme.colorScheme.tertiary
    SecurityVerdict.BLOQUEADO -> MaterialTheme.colorScheme.error
  }
}

@Composable
fun verdictContainerColor(verdict: SecurityVerdict): Color {
  return when (verdict) {
    SecurityVerdict.SEGURO -> MaterialTheme.colorScheme.secondaryContainer
    SecurityVerdict.SUSPEITO -> MaterialTheme.colorScheme.tertiaryContainer
    SecurityVerdict.BLOQUEADO -> MaterialTheme.colorScheme.errorContainer
  }
}

fun friendlyVerdictLabel(verdict: SecurityVerdict): String {
  return when (verdict) {
    SecurityVerdict.SEGURO -> "Seguro"
    SecurityVerdict.SUSPEITO -> "Atenção"
    SecurityVerdict.BLOQUEADO -> "Risco Alto"
  }
}

fun friendlyVerdictExplanation(verdict: SecurityVerdict): String {
  return when (verdict) {
    SecurityVerdict.SEGURO -> "Nenhum sinal de risco foi encontrado neste aplicativo."
    SecurityVerdict.SUSPEITO -> "Alguns comportamentos ou permissões merecem sua atenção."
    SecurityVerdict.BLOQUEADO -> "Este aplicativo apresenta sinais de risco elevado e foi sinalizado."
  }
}

fun friendlyInstallerSource(source: String?, isSystemApp: Boolean = false, sourceType: String = ""): String {
  if (sourceType == "APK_PRE_INSTALL") return "Arquivo baixado (.APK)"
  if (isSystemApp) return "App de fábrica do celular"
  return when {
    source.isNullOrBlank() -> "Fonte não informada"
    source.contains("com.android.vending", ignoreCase = true) ||
      source.contains("Play Store", ignoreCase = true) -> "Google Play Store"
    source.contains("galaxystore", ignoreCase = true) ||
      source.contains("sec.android.app.samsungapps", ignoreCase = true) -> "Galaxy Store"
    source.contains("amazon", ignoreCase = true) -> "Amazon Appstore"
    source.contains("packageinstaller", ignoreCase = true) ||
      source.contains("sideload", ignoreCase = true) ||
      source.contains("Desconhecida", ignoreCase = true) -> "Instalado fora da loja"
    else -> source
  }
}

@Composable
fun VerdictBadge(verdict: SecurityVerdict, modifier: Modifier = Modifier) {
  val fg = verdictColor(verdict)
  val bg = verdictContainerColor(verdict)
  val label = friendlyVerdictLabel(verdict)
  val icon =
    when (verdict) {
      SecurityVerdict.SEGURO -> Icons.Filled.VerifiedUser
      SecurityVerdict.SUSPEITO -> Icons.Filled.Warning
      SecurityVerdict.BLOQUEADO -> Icons.Filled.Block
    }

  Surface(
    color = bg.copy(alpha = 0.8f),
    contentColor = fg,
    shape = RoundedCornerShape(50),
    border = BorderStroke(1.dp, fg.copy(alpha = 0.3f)),
    modifier = modifier,
  ) {
    Row(
      verticalAlignment = Alignment.CenterVertically,
      modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
      Icon(
        imageVector = icon,
        contentDescription = label,
        modifier = Modifier.size(14.dp),
      )
      Spacer(Modifier.width(4.dp))
      Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        fontWeight = FontWeight.SemiBold,
      )
    }
  }
}

@Composable
fun TrustStatusBadge(status: TrustStatus, modifier: Modifier = Modifier) {
  val (fg, bg, icon, label) =
    when (status) {
      TrustStatus.TRUSTED ->
        listOf(
          MaterialTheme.colorScheme.secondary,
          MaterialTheme.colorScheme.secondaryContainer,
          Icons.Filled.CheckCircle,
          "Confiável",
        )
      TrustStatus.BLOCKED ->
        listOf(
          MaterialTheme.colorScheme.error,
          MaterialTheme.colorScheme.errorContainer,
          Icons.Filled.GppBad,
          "Bloqueada",
        )
      TrustStatus.NEUTRAL ->
        listOf(
          MaterialTheme.colorScheme.onSurfaceVariant,
          MaterialTheme.colorScheme.surfaceVariant,
          Icons.Filled.Shield,
          "Padrão",
        )
    }
  val typedFg = fg as Color
  val typedBg = bg as Color
  val typedIcon = icon as ImageVector
  val typedLabel = label as String

  Surface(
    color = typedBg,
    contentColor = typedFg,
    shape = RoundedCornerShape(50),
    modifier = modifier,
  ) {
    Row(
      verticalAlignment = Alignment.CenterVertically,
      modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
    ) {
      Icon(typedIcon, contentDescription = typedLabel, modifier = Modifier.size(13.dp))
      Spacer(Modifier.width(4.dp))
      Text(text = typedLabel, style = MaterialTheme.typography.labelSmall)
    }
  }
}

@Composable
fun RiskScoreGauge(
  score: Int,
  verdict: SecurityVerdict,
  size: Dp = 84.dp,
  modifier: Modifier = Modifier,
) {
  val animatedProgress by
    animateFloatAsState(
      targetValue = (score.coerceIn(0, 100) / 100f),
      animationSpec = tween(durationMillis = 650),
      label = "risk_gauge",
    )
  val activeColor = verdictColor(verdict)
  val trackColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)

  Box(contentAlignment = Alignment.Center, modifier = modifier.size(size)) {
    Canvas(modifier = Modifier.fillMaxSize().padding(6.dp)) {
      val strokeWidth = 8.dp.toPx()
      val diameter = this.size.minDimension
      val topLeft = Offset((this.size.width - diameter) / 2f, (this.size.height - diameter) / 2f)
      val arcSize = Size(diameter, diameter)

      drawArc(
        color = trackColor,
        startAngle = 135f,
        sweepAngle = 270f,
        useCenter = false,
        topLeft = topLeft,
        size = arcSize,
        style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
      )

      drawArc(
        color = activeColor,
        startAngle = 135f,
        sweepAngle = 270f * animatedProgress,
        useCenter = false,
        topLeft = topLeft,
        size = arcSize,
        style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
      )
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
      Text(
        text = "$score",
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
        color = activeColor,
      )
      Text(
        text = "Risco",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
  }
}

@Composable
fun TechnicalDetailsExpandable(
  title: String = "Detalhes técnicos",
  subtitle: String = "Certificado digital, pacote e permissões avançadas",
  initiallyExpanded: Boolean = false,
  testTag: String = "technical_details_toggle",
  content: @Composable ColumnScope.() -> Unit,
) {
  var expanded by rememberSaveable { mutableStateOf(initiallyExpanded) }

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
            .heightIn(min = 56.dp)
            .clickable(role = Role.Button) { expanded = !expanded }
            .padding(horizontal = 16.dp, vertical = 14.dp)
            .testTag(testTag),
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
          )
          Text(
            text = subtitle,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
        Spacer(Modifier.width(12.dp))
        Icon(
          imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
          contentDescription = if (expanded) "Recolher detalhes" else "Expandir detalhes",
          tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
      }

      AnimatedVisibility(visible = expanded) {
        Column(
          verticalArrangement = Arrangement.spacedBy(10.dp),
          modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
        ) {
          HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f))
          content()
        }
      }
    }
  }
}

@Composable
fun FingerprintMonospaceBox(
  label: String,
  fingerprint: String,
  onCopy: () -> Unit,
  modifier: Modifier = Modifier,
) {
  Column(
    modifier =
      modifier
        .fillMaxWidth()
        .background(
          color = MaterialTheme.colorScheme.background.copy(alpha = 0.7f),
          shape = RoundedCornerShape(12.dp),
        )
        .border(
          width = 1.dp,
          color = MaterialTheme.colorScheme.outline.copy(alpha = 0.4f),
          shape = RoundedCornerShape(12.dp),
        )
        .padding(horizontal = 12.dp, vertical = 8.dp)
  ) {
    Row(
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.SpaceBetween,
      modifier = Modifier.fillMaxWidth(),
    ) {
      Text(
        text = label,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
      )
      IconButton(
        onClick = onCopy,
        modifier = Modifier.size(40.dp).testTag("copy_fingerprint_button"),
      ) {
        Icon(
          imageVector = Icons.Filled.ContentCopy,
          contentDescription = "Copiar código de verificação",
          tint = MaterialTheme.colorScheme.onSurfaceVariant,
          modifier = Modifier.size(16.dp),
        )
      }
    }
    Text(
      text = fingerprint,
      style = MonoCodeStyle,
      color = MaterialTheme.colorScheme.onSurface,
    )
  }
}

@Composable
fun StatusMetricCard(
  title: String,
  value: String,
  subtitle: String,
  icon: ImageVector,
  accentColor: Color,
  modifier: Modifier = Modifier,
) {
  Card(
    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
    shape = MaterialTheme.shapes.medium,
    modifier = modifier,
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Text(
          text = title,
          style = MaterialTheme.typography.labelLarge,
          color = MaterialTheme.colorScheme.onSurfaceVariant,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
          modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(4.dp))
        Icon(
          imageVector = icon,
          contentDescription = title,
          tint = accentColor,
          modifier = Modifier.size(18.dp),
        )
      }
      Spacer(Modifier.height(8.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.headlineMedium,
        color = MaterialTheme.colorScheme.onSurface,
      )
      Spacer(Modifier.height(2.dp))
      Text(
        text = subtitle,
        style = MaterialTheme.typography.bodyMedium,
        color = accentColor,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
      )
    }
  }
}

fun formatTimestampPt(millis: Long): String {
  if (millis <= 0L) return "N/D"
  val sdf = SimpleDateFormat("dd/MM/yyyy 'às' HH:mm", Locale("pt", "BR"))
  return sdf.format(Date(millis))
}

fun formatDateOnlyPt(millis: Long): String {
  if (millis <= 0L) return "N/D"
  val sdf = SimpleDateFormat("dd/MM/yyyy", Locale("pt", "BR"))
  return sdf.format(Date(millis))
}
