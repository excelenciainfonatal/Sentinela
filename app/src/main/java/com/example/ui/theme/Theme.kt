package com.example.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat

private val SentinelaDarkColorScheme = darkColorScheme(
  primary = CyberCyan,
  onPrimary = CyberCyanOnPrimary,
  primaryContainer = CyberCyanContainer,
  onPrimaryContainer = CyberCyanOnContainer,
  secondary = ShieldEmerald,
  onSecondary = ShieldEmeraldOnSecondary,
  secondaryContainer = ShieldEmeraldContainer,
  onSecondaryContainer = ShieldEmeraldOnContainer,
  tertiary = AlertAmber,
  onTertiary = AlertAmberOnTertiary,
  tertiaryContainer = AlertAmberContainer,
  onTertiaryContainer = AlertAmberOnContainer,
  error = ThreatCrimson,
  onError = ThreatCrimsonOnError,
  errorContainer = ThreatCrimsonContainer,
  onErrorContainer = ThreatCrimsonOnContainer,
  background = ObsidianBg,
  onBackground = TextPrimaryDark,
  surface = ObsidianSurface,
  onSurface = TextPrimaryDark,
  surfaceVariant = ObsidianSurfaceVariant,
  onSurfaceVariant = TextSecondaryDark,
  surfaceContainerLowest = ObsidianBg,
  surfaceContainerLow = ObsidianSurfaceLow,
  surfaceContainer = ObsidianSurfaceContainer,
  surfaceContainerHigh = ObsidianSurfaceVariant,
  surfaceContainerHighest = ObsidianSurfaceHigh,
  outline = ObsidianOutline,
  outlineVariant = ObsidianOutlineVariant,
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
  tertiary = Color(0xFFB45309),
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
  outlineVariant = LightOutlineVariant,
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
  val view = LocalView.current

  if (!view.isInEditMode) {
    SideEffect {
      val window = (view.context as? Activity)?.window
      if (window != null) {
        val insetsController = WindowCompat.getInsetsController(window, view)
        insetsController.isAppearanceLightStatusBars = !effectiveDark
        insetsController.isAppearanceLightNavigationBars = !effectiveDark
      }
    }
  }

  MaterialTheme(
    colorScheme = colorScheme,
    typography = AppTypography,
    shapes = SentinelaShapes,
    content = content,
  )
}
