package com.example.ui.screens

import android.util.Log
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.CloudDone
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import com.example.R
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

private const val AUTH_TAG = "SentinelaAuthScreen"

@Composable
fun AuthScreen(
  auth: FirebaseAuth,
  modifier: Modifier = Modifier,
) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val credentialManager = remember(context) { CredentialManager.create(context) }

  var isLoading by remember { mutableStateOf(false) }
  var errorMessage by remember { mutableStateOf<String?>(null) }

  // 1. Silent Auto Sign-In via GetGoogleIdOption in its own GetCredentialRequest
  LaunchedEffect(Unit) {
    if (auth.currentUser != null) return@LaunchedEffect
    try {
      val webClientId = context.getString(R.string.default_web_client_id)
      val googleIdOption =
        GetGoogleIdOption.Builder()
          .setFilterByAuthorizedAccounts(true)
          .setServerClientId(webClientId)
          .setAutoSelectEnabled(true)
          .build()
      val request = GetCredentialRequest.Builder().addCredentialOption(googleIdOption).build()
      val result = credentialManager.getCredential(context, request)
      val credential = result.credential
      if (credential is CustomCredential &&
        credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
      ) {
        val googleIdToken = GoogleIdTokenCredential.createFrom(credential.data)
        val firebaseCred = GoogleAuthProvider.getCredential(googleIdToken.idToken, null)
        auth.signInWithCredential(firebaseCred).await()
      }
    } catch (e: CancellationException) {
      throw e
    } catch (_: NoCredentialException) {
      // Expected on first launch; leave user on interactive sign-in screen
    } catch (e: GetCredentialException) {
      Log.d(AUTH_TAG, "Silent auto sign-in skipped: ${e.message}")
    } catch (e: Exception) {
      Log.d(AUTH_TAG, "Silent auto sign-in failed silently", e)
    }
  }

  // 2. Interactive Google Sign-In via GetSignInWithGoogleOption in its own GetCredentialRequest
  val startInteractiveSignIn: () -> Unit = {
    if (!isLoading) {
      scope.launch {
        isLoading = true
        errorMessage = null
        try {
          val webClientId = context.getString(R.string.default_web_client_id)
          val signInWithGoogleOption =
            GetSignInWithGoogleOption.Builder(webClientId).build()
          val request =
            GetCredentialRequest.Builder().addCredentialOption(signInWithGoogleOption).build()

          val result = credentialManager.getCredential(context, request)
          val credential = result.credential
          if (credential is CustomCredential &&
            credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
          ) {
            val googleIdToken = GoogleIdTokenCredential.createFrom(credential.data)
            val firebaseCred = GoogleAuthProvider.getCredential(googleIdToken.idToken, null)
            auth.signInWithCredential(firebaseCred).await()
          } else {
            errorMessage = "Não foi possível entrar com esta conta Google."
          }
        } catch (e: CancellationException) {
          throw e
        } catch (e: GetCredentialCancellationException) {
          Log.w(AUTH_TAG, "Google Sign-In cancelled (check SHA-1/SHA-256 or user cancel)", e)
          errorMessage = "Entrada cancelada. Escolha sua conta Google para continuar."
        } catch (e: GoogleIdTokenParsingException) {
          Log.w(AUTH_TAG, "Failed to parse Google ID token", e)
          errorMessage = "Não foi possível validar sua conta Google."
        } catch (e: GetCredentialException) {
          Log.w(AUTH_TAG, "CredentialManager error during Google Sign-In", e)
          errorMessage = e.localizedMessage ?: "Falha ao conectar com sua conta Google."
        } catch (e: Exception) {
          Log.e(AUTH_TAG, "Firebase sign-in with Google credential failed", e)
          errorMessage = e.localizedMessage ?: "Não foi possível entrar agora. Tente novamente."
        } finally {
          isLoading = false
        }
      }
    }
  }

  val bg = MaterialTheme.colorScheme.background
  val surfaceContainer = MaterialTheme.colorScheme.surfaceContainer

  Box(
    modifier =
      modifier
        .fillMaxSize()
        .background(
          Brush.verticalGradient(
            colors = listOf(bg, surfaceContainer, bg)
          )
        )
        .safeDrawingPadding(),
    contentAlignment = Alignment.Center,
  ) {
    Column(
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.spacedBy(18.dp),
      modifier =
        Modifier.fillMaxWidth()
          .widthIn(max = 520.dp)
          .verticalScroll(rememberScrollState())
          .padding(horizontal = 24.dp, vertical = 20.dp),
    ) {
      Card(
        shape = MaterialTheme.shapes.extraLarge,
        border =
          BorderStroke(
            1.dp,
            Brush.linearGradient(
              colors =
                listOf(
                  MaterialTheme.colorScheme.primary.copy(alpha = 0.65f),
                  MaterialTheme.colorScheme.secondary.copy(alpha = 0.45f),
                )
            ),
          ),
        modifier = Modifier.fillMaxWidth(),
      ) {
        Box(modifier = Modifier.fillMaxWidth()) {
          Image(
            painter = painterResource(id = R.drawable.img_security_banner_1795109549664),
            contentDescription = "Escudo Sentinela de Proteção",
            contentScale = ContentScale.Crop,
            modifier = Modifier.matchParentSize(),
          )
          Box(
            modifier =
              Modifier.matchParentSize()
                .background(
                  Brush.verticalGradient(
                    colors =
                      listOf(
                        bg.copy(alpha = 0.78f),
                        surfaceContainer.copy(alpha = 0.92f),
                        bg.copy(alpha = 0.98f),
                      )
                  )
                )
          )
          Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.fillMaxWidth().padding(24.dp),
          ) {
            Surface(
              color = MaterialTheme.colorScheme.primary.copy(alpha = 0.16f),
              shape = CircleShape,
              border = BorderStroke(1.5.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.55f)),
              modifier = Modifier.size(72.dp),
            ) {
              Box(contentAlignment = Alignment.Center) {
                Icon(
                  imageVector = Icons.Filled.Shield,
                  contentDescription = "Sentinela",
                  tint = MaterialTheme.colorScheme.primary,
                  modifier = Modifier.size(38.dp),
                )
              }
            }

            Spacer(Modifier.height(16.dp))
            Text(
              text = "Proteja seu celular com o Sentinela",
              style = MaterialTheme.typography.headlineSmall,
              color = MaterialTheme.colorScheme.onSurface,
              textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(8.dp))
            Text(
              text =
                "Identifique aplicativos suspeitos de forma simples e mantenha seus dados seguros na sua conta Google.",
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
              textAlign = TextAlign.Center,
            )
          }
        }
      }

      Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.35f)),
        shape = MaterialTheme.shapes.large,
        modifier = Modifier.fillMaxWidth(),
      ) {
        Column(
          modifier = Modifier.padding(18.dp),
          verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
          AuthFeatureRow(
            icon = Icons.Filled.VerifiedUser,
            accent = MaterialTheme.colorScheme.secondary,
            title = "Proteção sem complicação",
            subtitle = "Avisa na hora se algum aplicativo suspeito tentar se instalar",
          )
          AuthFeatureRow(
            icon = Icons.Filled.CloudDone,
            accent = MaterialTheme.colorScheme.primary,
            title = "Backup automático",
            subtitle = "Seus aplicativos confiáveis ficam salvos se você trocar de celular",
          )
          AuthFeatureRow(
            icon = Icons.Filled.Lock,
            accent = MaterialTheme.colorScheme.tertiary,
            title = "Privacidade garantida",
            subtitle = "Apenas você tem acesso ao seu histórico de verificações",
          )
        }
      }

      AnimatedVisibility(visible = errorMessage != null) {
        Surface(
          color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.7f),
          border = BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.6f)),
          shape = RoundedCornerShape(14.dp),
          modifier = Modifier.fillMaxWidth().testTag("auth_error_banner"),
        ) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(12.dp),
          ) {
            Icon(
              imageVector = Icons.Filled.Warning,
              contentDescription = "Erro de entrada",
              tint = MaterialTheme.colorScheme.error,
              modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.width(10.dp))
            Text(
              text = errorMessage.orEmpty(),
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onErrorContainer,
            )
          }
        }
      }

      Button(
        onClick = startInteractiveSignIn,
        enabled = !isLoading,
        shape = RoundedCornerShape(16.dp),
        colors =
          ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
          ),
        modifier =
          Modifier.fillMaxWidth()
            .height(54.dp)
            .testTag("google_signin_button"),
      ) {
        if (isLoading) {
          CircularProgressIndicator(
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.onPrimary,
            modifier = Modifier.size(20.dp),
          )
          Spacer(Modifier.width(10.dp))
          Text(
            text = "Entrando...",
            style = MaterialTheme.typography.titleMedium,
          )
        } else {
          Icon(
            imageVector = Icons.AutoMirrored.Filled.Login,
            contentDescription = "Continuar com o Google",
            modifier = Modifier.size(20.dp),
          )
          Spacer(Modifier.width(10.dp))
          Text(
            text = "Continuar com o Google",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold,
          )
        }
      }

      Text(
        text = "Acesso rápido e seguro usando sua conta Google.",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
      )
    }
  }
}

@Composable
private fun AuthFeatureRow(
  icon: ImageVector,
  accent: Color,
  title: String,
  subtitle: String,
) {
  Row(verticalAlignment = Alignment.CenterVertically) {
    Box(
      contentAlignment = Alignment.Center,
      modifier =
        Modifier.size(42.dp)
          .clip(RoundedCornerShape(12.dp))
          .background(accent.copy(alpha = 0.14f)),
    ) {
      Icon(
        imageVector = icon,
        contentDescription = title,
        tint = accent,
        modifier = Modifier.size(20.dp),
      )
    }
    Spacer(Modifier.width(12.dp))
    Column(modifier = Modifier.weight(1f)) {
      Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
      )
      Text(
        text = subtitle,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
      )
    }
  }
}
