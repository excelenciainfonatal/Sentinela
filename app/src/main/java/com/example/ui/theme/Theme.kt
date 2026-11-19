package com.example.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val SentinelaDarkColorScheme = darkColorScheme(
  primary = CyberCyan,
  onPrimary = Color(0xFF042231),
  primaryContainer = CyberCyanContainer,
  onPrimaryContainer = CyberCyanOnContainer,
  secondary = ShieldEmerald,
  onSecondary = Color(0xFF03261B),
  secondaryContainer = ShieldEmeraldContainer,
  onSecondaryContainer = ShieldEmeraldOnContainer,
  tertiary = AlertAmber,
  onTertiary = Color(0xFF2B1800),
  tertiaryContainer = AlertAmberContainer,
  onTertiaryContainer = AlertAmberOnContainer,
  error = ThreatCrimson,
  onError = Color(0xFF330609),
  errorContainer = ThreatCrimsonContainer,
  onErrorContainer = ThreatCrimsonOnContainer,
  background = ObsidianBg,
  onBackground = TextPrimaryDark,
  surface = ObsidianSurface,
  onSurface = TextPrimaryDark,
  surfaceVariant = ObsidianSurfaceVariant,
  onSurfaceVariant = TextSecondaryDark,
  surfaceContainerHighest = ObsidianSurfaceHigh,
  outline = ObsidianOutline,
)

private val SentinelaLightColorScheme = lightColorScheme(
  primary = CyberCyanDark,
  onPrimary = Color.White,
  primaryContainer = Color(0xFFE0F2FE),
  onPrimaryContainer = Color(0xFF0C4A6E),
  secondary = ShieldEmeraldDark,
  onSecondary = Color.White,
  secondaryContainer = Color(0xFFD1FAE5),
  onSecondaryContainer = Color(0xFF064E3B),
  tertiary = Color(0xFFD97706),
  onTertiary = Color.White,
  tertiaryContainer = Color(0xFFFEF3C7),
  onTertiaryContainer = Color(0xFF451A03),
  error = ThreatCrimsonDark,
  onError = Color.White,
  errorContainer = Color(0xFFFEE2E2),
  onErrorContainer = Color(0xFF450A0A),
  background = LightBg,
  onBackground = LightTextPrimary,
  surface = LightSurface,
  onSurface = LightTextPrimary,
  surfaceVariant = LightSurfaceVariant,
  onSurfaceVariant = LightTextSecondary,
  outline = LightOutline,
)

val SentinelaShapes = Shapes(
  small = RoundedCornerShape(12.dp),
  medium = RoundedCornerShape(18.dp),
  large = RoundedCornerShape(24.dp),
  extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun SentinelaTheme(
  darkTheme: Boolean = true,
  useSystemTheme: Boolean = false,
  content: @Composable () -> Unit,
) {
  val effectiveDark = if (useSystemTheme) isSystemInDarkTheme() else darkTheme
  val colorScheme = if (effectiveDark) SentinelaDarkColorScheme else SentinelaLightColorScheme

  MaterialTheme(
    colorScheme = colorScheme,
    typography = AppTypography,
    shapes = SentinelaShapes,
    content = content,
  )
}
