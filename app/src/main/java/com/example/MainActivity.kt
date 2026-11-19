package com.example

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ViewModelProvider.AndroidViewModelFactory.Companion.APPLICATION_KEY
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.example.data.local.TrustStatus
import com.example.data.remote.CloudSecurityRepository
import com.example.data.remote.authStateFlow
import com.example.service.SecurityNotifier
import com.example.ui.AuditDetailUiState
import com.example.ui.CloudSyncViewModel
import com.example.ui.SentinelaViewModel
import com.example.ui.SignatureFilter
import com.example.ui.screens.ApkGatekeeperScreen
import com.example.ui.screens.AppDetailScreen
import com.example.ui.screens.AppsCatalogFilter
import com.example.ui.screens.AppsCatalogScreen
import com.example.ui.screens.AuthScreen
import com.example.ui.screens.BehaviorMonitorScreen
import com.example.ui.screens.DashboardScreen
import com.example.ui.screens.ScanHistoryScreen
import com.example.ui.screens.SignatureRegistryScreen
import com.example.ui.screens.WhitelistScreen
import com.example.ui.theme.SentinelaTheme
import com.google.firebase.Firebase
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.auth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private object Routes {
  const val DASHBOARD = "dashboard"
  const val GATEKEEPER = "gatekeeper"
  const val BEHAVIOR = "behavior"
  const val SIGNATURES = "signatures"
  const val HISTORY = "history"
  const val WHITELIST = "whitelist"
  const val APPS_CATALOG = "apps_catalog/{filter}"
  const val DETAIL = "app_detail/{auditId}?pkg={pkg}"

  fun catalogRoute(filter: AppsCatalogFilter) = "apps_catalog/${filter.name}"

  fun detailRoute(auditId: Long, pkg: String = "") = "app_detail/$auditId?pkg=${Uri.encode(pkg)}"
}

private data class NavTab(
  val route: String,
  val label: String,
  val selectedIcon: ImageVector,
  val unselectedIcon: ImageVector,
  val testTag: String,
)

class MainActivity : ComponentActivity() {

  private val incomingApkUri = MutableStateFlow<Uri?>(null)
  private val pendingNotificationAuditId = MutableStateFlow<Long?>(null)
  private val pendingNotificationTab = MutableStateFlow<String?>(null)

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    extractIncomingIntent(intent)

    setContent {
      SentinelaTheme {
        val pendingUri by incomingApkUri.collectAsStateWithLifecycle()
        val notifAuditId by pendingNotificationAuditId.collectAsStateWithLifecycle()
        val notifTab by pendingNotificationTab.collectAsStateWithLifecycle()
        SentinelaAuthGate(
          pendingApkUri = pendingUri,
          onConsumedPendingApkUri = { incomingApkUri.value = null },
          pendingNotificationAuditId = notifAuditId,
          pendingNotificationTab = notifTab,
          onConsumedNotificationNav = {
            pendingNotificationAuditId.value = null
            pendingNotificationTab.value = null
          },
        )
      }
    }
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    extractIncomingIntent(intent)
  }

  private fun extractIncomingIntent(intent: Intent?) {
    if (intent?.action == Intent.ACTION_VIEW) {
      intent.data?.let { uri -> incomingApkUri.value = uri }
    }
    val auditId = intent?.getLongExtra(SecurityNotifier.EXTRA_AUDIT_ID, -1L) ?: -1L
    if (auditId > 0L) {
      pendingNotificationAuditId.value = auditId
    } else {
      intent?.getStringExtra(SecurityNotifier.EXTRA_TARGET_TAB)?.let { tab ->
        pendingNotificationTab.value = tab
      }
    }
  }
}

@Composable
private fun SentinelaAuthGate(
  pendingApkUri: Uri?,
  onConsumedPendingApkUri: () -> Unit,
  pendingNotificationAuditId: Long?,
  pendingNotificationTab: String?,
  onConsumedNotificationNav: () -> Unit,
  auth: FirebaseAuth = Firebase.auth,
) {
  val currentUser by auth.authStateFlow().collectAsStateWithLifecycle(initialValue = auth.currentUser)
  val user = currentUser
  if (user == null) {
    AuthScreen(auth = auth)
  } else {
    key(user.uid) {
      val sentinelaViewModel: SentinelaViewModel =
        viewModel(
          key = "sentinela_${user.uid}",
          factory =
            viewModelFactory {
              initializer {
                val app =
                  checkNotNull(this[APPLICATION_KEY]) as SentinelaApplication
                SentinelaViewModel(app)
              }
            },
        )
      val cloudSyncViewModel: CloudSyncViewModel =
        viewModel(
          key = user.uid,
          factory =
            viewModelFactory {
              initializer {
                val app =
                  checkNotNull(this[APPLICATION_KEY]) as SentinelaApplication
                val databaseId = app.getString(R.string.firestore_database_id)
                val db = FirebaseFirestore.getInstance(databaseId)
                CloudSyncViewModel(
                  cloudRepo = CloudSecurityRepository(db, auth),
                  localRepo = app.repository,
                  currentUserId = user.uid,
                  userDisplayName = user.displayName ?: "Usuário Sentinela",
                  userEmail = user.email.orEmpty(),
                )
              }
            },
        )
      SentinelaAppRoot(
        viewModel = sentinelaViewModel,
        cloudSyncViewModel = cloudSyncViewModel,
        auth = auth,
        pendingApkUri = pendingApkUri,
        onConsumedPendingApkUri = onConsumedPendingApkUri,
        pendingNotificationAuditId = pendingNotificationAuditId,
        pendingNotificationTab = pendingNotificationTab,
        onConsumedNotificationNav = onConsumedNotificationNav,
      )
    }
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SentinelaAppRoot(
  viewModel: SentinelaViewModel,
  cloudSyncViewModel: CloudSyncViewModel,
  auth: FirebaseAuth,
  pendingApkUri: Uri?,
  onConsumedPendingApkUri: () -> Unit,
  pendingNotificationAuditId: Long?,
  pendingNotificationTab: String?,
  onConsumedNotificationNav: () -> Unit,
) {
  val context = LocalContext.current
  val lifecycleOwner = LocalLifecycleOwner.current
  val uiState by viewModel.uiState.collectAsStateWithLifecycle()
  val cloudSyncState by cloudSyncViewModel.uiState.collectAsStateWithLifecycle()
  val navController = rememberNavController()
  val snackbarHostState = remember { SnackbarHostState() }
  val scope = rememberCoroutineScope()
  var showAccountDialog by remember { mutableStateOf(false) }

  val tabs = remember {
    listOf(
      NavTab(Routes.DASHBOARD, "Início", Icons.Filled.Shield, Icons.Outlined.Shield, "tab_dashboard"),
      NavTab(Routes.GATEKEEPER, "Verificar", Icons.Filled.Security, Icons.Outlined.Security, "tab_gatekeeper"),
      NavTab(Routes.BEHAVIOR, "Apps", Icons.Filled.Apps, Icons.Outlined.Apps, "tab_behavior"),
      NavTab(Routes.HISTORY, "Histórico", Icons.Filled.History, Icons.Outlined.History, "tab_history"),
    )
  }

  val apkPickerLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
      if (uri != null) {
        viewModel.inspectApkUri(uri)
        navController.navigate(Routes.GATEKEEPER) {
          popUpTo(navController.graph.findStartDestination().id) { saveState = true }
          launchSingleTop = true
          restoreState = true
        }
      }
    }

  val notificationPermissionLauncher =
    rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
      viewModel.refreshSystemPermissionsStatus()
    }

  val launchApkPicker: () -> Unit = {
    apkPickerLauncher.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "*/*"))
  }

  val openUsageSettings: () -> Unit = {
    val intent =
      Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
    runCatching { context.startActivity(intent) }
  }

  val requestNotificationPermission: () -> Unit = {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
  }

  val showSnackbar: (String) -> Unit = { message ->
    scope.launch { snackbarHostState.showSnackbar(message) }
  }

  val signOutUser: () -> Unit = {
    scope.launch {
      withContext(NonCancellable) {
        runCatching {
          CredentialManager.create(context).clearCredentialState(ClearCredentialStateRequest())
        }
        auth.signOut()
      }
    }
  }

  if (showAccountDialog) {
    AlertDialog(
      onDismissRequest = { showAccountDialog = false },
      title = { Text("Sua Conta Google") },
      text = {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text(
            text = cloudSyncState.displayName,
            style = MaterialTheme.typography.titleMedium,
          )
          if (cloudSyncState.email.isNotBlank()) {
            Text(
              text = cloudSyncState.email,
              style = MaterialTheme.typography.bodyMedium,
              color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
          }
          Text(
            text = "Seus apps confiáveis e preferências ficam salvos com segurança na sua conta.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
          )
        }
      },
      confirmButton = {
        TextButton(
          onClick = {
            showAccountDialog = false
            signOutUser()
          },
          modifier = Modifier.testTag("confirm_sign_out_button"),
        ) {
          Text("Sair da conta", color = MaterialTheme.colorScheme.error)
        }
      },
      dismissButton = {
        TextButton(onClick = { showAccountDialog = false }) {
          Text("Fechar")
        }
      },
    )
  }

  DisposableEffect(lifecycleOwner) {
    val observer = LifecycleEventObserver { _, event ->
      if (event == Lifecycle.Event.ON_RESUME) {
        viewModel.refreshSystemPermissionsStatus()
      }
    }
    lifecycleOwner.lifecycle.addObserver(observer)
    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
  }

  LaunchedEffect(pendingApkUri) {
    if (pendingApkUri != null) {
      viewModel.inspectApkUri(pendingApkUri)
      navController.navigate(Routes.GATEKEEPER) {
        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
      }
      onConsumedPendingApkUri()
    }
  }

  LaunchedEffect(pendingNotificationAuditId, pendingNotificationTab) {
    if (pendingNotificationAuditId != null && pendingNotificationAuditId > 0L) {
      navController.navigate(Routes.detailRoute(pendingNotificationAuditId))
      onConsumedNotificationNav()
    } else if (pendingNotificationTab != null) {
      val target = if (pendingNotificationTab == "behavior") Routes.BEHAVIOR else Routes.DASHBOARD
      navController.navigate(target) {
        popUpTo(navController.graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
      }
      onConsumedNotificationNav()
    }
  }

  val navBackStackEntry by navController.currentBackStackEntryAsState()
  val currentRoute = navBackStackEntry?.destination?.route
  val isSecondaryRoute =
    currentRoute?.startsWith("app_detail") == true ||
      currentRoute == Routes.WHITELIST ||
      currentRoute == Routes.SIGNATURES ||
      currentRoute?.startsWith("apps_catalog") == true

  BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
    val useNavigationRail = maxWidth >= 600.dp

    Scaffold(
      contentWindowInsets = WindowInsets(0, 0, 0, 0),
      snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
      topBar = {
        if (!isSecondaryRoute) {
          val title =
            when (currentRoute) {
              Routes.GATEKEEPER -> "Verificar Arquivo"
              Routes.BEHAVIOR -> "Meus Aplicativos"
              Routes.HISTORY -> "Histórico"
              else -> "Sentinela"
            }
          CenterAlignedTopAppBar(
            title = {
              Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
              )
            },
            actions = {
              IconButton(
                onClick = { showAccountDialog = true },
                modifier = Modifier.testTag("topbar_sign_out_button"),
              ) {
                Icon(
                  imageVector = Icons.Filled.AccountCircle,
                  contentDescription = "Minha conta e sair",
                )
              }
            },
            colors =
              TopAppBarDefaults.centerAlignedTopAppBarColors(
                containerColor = MaterialTheme.colorScheme.background
              ),
          )
        }
      },
      bottomBar = {
        if (!useNavigationRail && !isSecondaryRoute) {
          NavigationBar(
            containerColor = MaterialTheme.colorScheme.surface,
          ) {
            tabs.forEach { tab ->
              val selected = currentRoute == tab.route
              NavigationBarItem(
                selected = selected,
                onClick = {
                  if (!selected) {
                    navController.navigate(tab.route) {
                      popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                      launchSingleTop = true
                      restoreState = true
                    }
                  }
                },
                icon = {
                  Icon(
                    imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                    contentDescription = tab.label,
                  )
                },
                label = {
                  Text(
                    text = tab.label,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                  )
                },
                modifier = Modifier.testTag(tab.testTag),
              )
            }
          }
        }
      },
    ) { innerPadding ->
      Row(modifier = Modifier.fillMaxSize().padding(innerPadding)) {
        if (useNavigationRail && !isSecondaryRoute) {
          NavigationRail(containerColor = MaterialTheme.colorScheme.surface) {
            tabs.forEach { tab ->
              val selected = currentRoute == tab.route
              NavigationRailItem(
                selected = selected,
                onClick = {
                  if (!selected) {
                    navController.navigate(tab.route) {
                      popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                      launchSingleTop = true
                      restoreState = true
                    }
                  }
                },
                icon = {
                  Icon(
                    imageVector = if (selected) tab.selectedIcon else tab.unselectedIcon,
                    contentDescription = tab.label,
                  )
                },
                label = {
                  Text(
                    text = tab.label,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                  )
                },
                modifier = Modifier.testTag(tab.testTag),
              )
            }
          }
        }

        Box(modifier = Modifier.weight(1f).fillMaxSize()) {
          NavHost(
            navController = navController,
            startDestination = Routes.DASHBOARD,
            enterTransition = { EnterTransition.None },
            exitTransition = { ExitTransition.None },
            popEnterTransition = { EnterTransition.None },
            popExitTransition = { ExitTransition.None },
          ) {
            composable(Routes.DASHBOARD) {
              DashboardScreen(
                uiState = uiState,
                cloudSyncState = cloudSyncState,
                onPickApk = launchApkPicker,
                onScanNow = {
                  viewModel.scanDeviceApps { count ->
                    showSnackbar("Verificação concluída: $count aplicativo(s) analisados.")
                    if (cloudSyncState.autoSyncEnabled) {
                      cloudSyncViewModel.syncLocalToCloud()
                    }
                  }
                },
                onSyncCloud = { cloudSyncViewModel.syncLocalToCloud(showSnackbar) },
                onRestoreCloud = { cloudSyncViewModel.restoreFromCloudToRoom(showSnackbar) },
                onToggleCloudAutoSync = { cloudSyncViewModel.toggleAutoSync(it) },
                onSignOut = { showAccountDialog = true },
                onToggleMonitor = { enabled ->
                  if (enabled && !uiState.notificationPermissionGranted) {
                    requestNotificationPermission()
                  }
                  viewModel.toggleRealTimeMonitor(enabled)
                },
                onTogglePushAlerts = { enabled ->
                  if (enabled && !uiState.notificationPermissionGranted) {
                    requestNotificationPermission()
                  }
                  viewModel.updatePushAlertsEnabled(enabled)
                },
                onTestPushAlert = {
                  if (!uiState.notificationPermissionGranted) {
                    requestNotificationPermission()
                    showSnackbar("Ative as notificações para receber alertas de segurança.")
                  } else {
                    val sent = viewModel.sendTestPushAlert()
                    if (sent) {
                      showSnackbar("Alerta de teste enviado para sua barra de notificações.")
                    }
                  }
                },
                onToggleDebugCerts = { viewModel.updatePolicyDebugCerts(it) },
                onToggleSigMismatch = { viewModel.updatePolicySigMismatch(it) },
                onToggleHighRiskPerms = { viewModel.updatePolicyHighRiskPerms(it) },
                onToggleStrictSideload = { viewModel.updatePolicyStrictSideload(it) },
                onOpenUsageSettings = openUsageSettings,
                onRequestNotificationPermission = requestNotificationPermission,
                onOpenAuditDetail = { id, pkg -> navController.navigate(Routes.detailRoute(id, pkg)) },
                onNavigateToCatalog = { filter ->
                  navController.navigate(Routes.catalogRoute(filter))
                },
                onNavigateToGatekeeper = {
                  navController.navigate(Routes.GATEKEEPER) {
                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                  }
                },
                onNavigateToBehavior = {
                  navController.navigate(Routes.BEHAVIOR) {
                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                  }
                },
                onNavigateToSignatures = { alertsOnly ->
                  viewModel.setSignatureFilter(
                    if (alertsOnly) SignatureFilter.ALERTAS else SignatureFilter.TODOS
                  )
                  navController.navigate(Routes.SIGNATURES)
                },
                onNavigateToHistory = {
                  navController.navigate(Routes.HISTORY) {
                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                  }
                },
                onNavigateToWhitelist = { navController.navigate(Routes.WHITELIST) },
              )
            }

            composable(Routes.GATEKEEPER) {
              ApkGatekeeperScreen(
                uiState = uiState,
                onPickApk = launchApkPicker,
                onClearReport = { viewModel.clearLatestApkReport() },
                onDismissError = { viewModel.dismissApkError() },
                onBlockCert = { sha, label, pkg -> viewModel.blockCertificate(sha, label, pkg) },
                onTrustCert = { sha, label, pkg -> viewModel.trustCertificate(sha, label, pkg) },
                onDeleteAudit = { id -> viewModel.deleteAudit(id) },
                onOpenAuditDetail = { id -> navController.navigate(Routes.detailRoute(id)) },
                onShowMessage = showSnackbar,
              )
            }

            composable(Routes.BEHAVIOR) {
              BehaviorMonitorScreen(
                uiState = uiState,
                onFilterChange = { viewModel.setBehaviorFilter(it) },
                onSearchChange = { viewModel.setBehaviorSearchQuery(it) },
                onScanNow = { viewModel.scanDeviceApps() },
                onClearEvents = { viewModel.clearBehaviorEvents() },
                onOpenUsageSettings = openUsageSettings,
                onOpenAuditDetail = { id -> navController.navigate(Routes.detailRoute(id)) },
                onNavigateToWhitelist = { navController.navigate(Routes.WHITELIST) },
              )
            }

            composable(Routes.SIGNATURES) {
              SignatureRegistryScreen(
                uiState = uiState,
                onBack = { navController.popBackStack() },
                onFilterChange = { viewModel.setSignatureFilter(it) },
                onTrustCert = { sha, label, pkg ->
                  viewModel.trustCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.TRUSTED)
                },
                onBlockCert = { sha, label, pkg ->
                  viewModel.blockCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.BLOCKED)
                },
                onResetRule = { sha ->
                  viewModel.resetCertificateRule(sha)
                  cloudSyncViewModel.mirrorCertificateRule(sha, "", "", TrustStatus.NEUTRAL)
                },
                onShowMessage = showSnackbar,
              )
            }

            composable(Routes.HISTORY) {
              ScanHistoryScreen(
                scanHistory = uiState.scanHistory,
                historyFilter = uiState.historyFilter,
                historySearchQuery = uiState.historySearchQuery,
                onFilterChange = { viewModel.setHistoryFilter(it) },
                onSearchChange = { viewModel.setHistorySearchQuery(it) },
                onDeleteEntry = { id -> viewModel.deleteScanHistoryEntry(id) },
                onClearHistory = { viewModel.clearScanHistory() },
                onOpenAuditDetail = { id, pkg -> navController.navigate(Routes.detailRoute(id, pkg)) },
              )
            }

            composable(Routes.WHITELIST) {
              WhitelistScreen(
                uiState = uiState,
                onBack = { navController.popBackStack() },
                onAddToWhitelist = { pkg, name, sha ->
                  viewModel.addToWhitelist(pkg, name, sha)
                  cloudSyncViewModel.mirrorWhitelistAdd(pkg, name, sha)
                },
                onRemoveFromWhitelist = { pkg ->
                  viewModel.removeFromWhitelist(pkg)
                  cloudSyncViewModel.mirrorWhitelistRemove(pkg)
                },
                onClearWhitelist = { viewModel.clearWhitelist() },
                onShowMessage = showSnackbar,
              )
            }

            composable(
              route = Routes.APPS_CATALOG,
              arguments = listOf(navArgument("filter") { type = NavType.StringType }),
            ) { backStackEntry ->
              val filterArg = backStackEntry.arguments?.getString("filter")
              val initialFilter =
                runCatching { AppsCatalogFilter.valueOf(filterArg ?: "") }
                  .getOrDefault(AppsCatalogFilter.BLOQUEADOS)
              AppsCatalogScreen(
                uiState = uiState,
                initialFilter = initialFilter,
                onBack = { navController.popBackStack() },
                onOpenAuditDetail = { id, pkg -> navController.navigate(Routes.detailRoute(id, pkg)) },
                onAddToWhitelist = { pkg, name, sha ->
                  viewModel.addToWhitelist(pkg, name, sha)
                  cloudSyncViewModel.mirrorWhitelistAdd(pkg, name, sha)
                },
                onRemoveFromWhitelist = { pkg ->
                  viewModel.removeFromWhitelist(pkg)
                  cloudSyncViewModel.mirrorWhitelistRemove(pkg)
                },
                onBlockCert = { sha, label, pkg ->
                  viewModel.blockCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.BLOCKED)
                },
                onTrustCert = { sha, label, pkg ->
                  viewModel.trustCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.TRUSTED)
                },
                onScanNow = {
                  viewModel.scanDeviceApps { count ->
                    showSnackbar("Verificação completa: $count aplicativo(s) analisados.")
                    if (cloudSyncState.autoSyncEnabled) {
                      cloudSyncViewModel.syncLocalToCloud()
                    }
                  }
                },
                onNavigateToWhitelist = { navController.navigate(Routes.WHITELIST) },
                onNavigateToGatekeeper = {
                  navController.navigate(Routes.GATEKEEPER) {
                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                  }
                },
                onNavigateToSignatures = { navController.navigate(Routes.SIGNATURES) },
                onNavigateToHistory = {
                  navController.navigate(Routes.HISTORY) {
                    popUpTo(navController.graph.findStartDestination().id) { saveState = true }
                    launchSingleTop = true
                    restoreState = true
                  }
                },
                onShowMessage = showSnackbar,
              )
            }

            composable(
              route = Routes.DETAIL,
              arguments =
                listOf(
                  navArgument("auditId") { type = NavType.LongType },
                  navArgument("pkg") {
                    type = NavType.StringType
                    defaultValue = ""
                  },
                ),
            ) { backStackEntry ->
              val auditId = backStackEntry.arguments?.getLong("auditId") ?: -1L
              val pkgHint = backStackEntry.arguments?.getString("pkg").orEmpty()
              val detailFlow =
                remember(auditId, pkgHint) { viewModel.observeAuditDetail(auditId, pkgHint) }
              val detailState by detailFlow.collectAsStateWithLifecycle()
              val loadedPkg = (detailState as? AuditDetailUiState.Ready)?.audit?.packageName
              val isWhitelisted =
                loadedPkg != null && loadedPkg in uiState.whitelistedPackageNames
              AppDetailScreen(
                detailState = detailState,
                isWhitelisted = isWhitelisted,
                onBack = { navController.popBackStack() },
                onTrustCert = { sha, label, pkg ->
                  viewModel.trustCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.TRUSTED)
                },
                onBlockCert = { sha, label, pkg ->
                  viewModel.blockCertificate(sha, label, pkg)
                  cloudSyncViewModel.mirrorCertificateRule(sha, label, pkg, TrustStatus.BLOCKED)
                },
                onToggleWhitelist = { current ->
                  if (current.packageName in uiState.whitelistedPackageNames) {
                    viewModel.removeFromWhitelist(current.packageName)
                    cloudSyncViewModel.mirrorWhitelistRemove(current.packageName)
                  } else {
                    viewModel.addToWhitelist(
                      packageName = current.packageName,
                      appName = current.appName,
                      sha256Fingerprint = current.sha256Fingerprint,
                    )
                    cloudSyncViewModel.mirrorWhitelistAdd(
                      current.packageName,
                      current.appName,
                      current.sha256Fingerprint,
                    )
                  }
                },
                onShowMessage = showSnackbar,
              )
            }
          }
        }
      }
    }
  }
}
