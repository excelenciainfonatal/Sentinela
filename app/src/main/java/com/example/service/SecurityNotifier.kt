package com.example.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.MainActivity
import com.example.R

enum class ThreatAlertType(val badgeLabel: String) {
  INVALID_SIGNATURE("Assinatura Inválida"),
  SUSPICIOUS_BEHAVIOR("Comportamento Suspeito"),
  BLOCKED_INSTALL("Instalação Bloqueada"),
  MALWARE_DETECTED("Ameaça Catalogada"),
  ACCESSIBILITY_ABUSE("Abuso de Acessibilidade"),
  PERMISSION_ABUSE("Abuso de Permissões"),
  HIDDEN_COMMUNICATION("Comunicação Oculta"),
}

object SecurityNotifier {

  const val MONITOR_CHANNEL_ID = "sentinela_monitor_channel"
  const val ALERTS_CHANNEL_ID = "sentinela_alerts_channel"
  const val MONITOR_NOTIFICATION_ID = 1001

  const val EXTRA_AUDIT_ID = "extra_audit_id"
  const val EXTRA_PACKAGE_NAME = "extra_package_name"
  const val EXTRA_TARGET_TAB = "extra_target_tab"

  fun ensureChannels(context: Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

      val monitorChannel =
        NotificationChannel(
          MONITOR_CHANNEL_ID,
          context.getString(R.string.monitor_channel_name),
          NotificationManager.IMPORTANCE_LOW,
        ).apply {
          description = context.getString(R.string.monitor_channel_desc)
          setShowBadge(false)
        }

      val alertsChannel =
        NotificationChannel(
          ALERTS_CHANNEL_ID,
          context.getString(R.string.alerts_channel_name),
          NotificationManager.IMPORTANCE_HIGH,
        ).apply {
          description = context.getString(R.string.alerts_channel_desc)
          enableVibration(true)
          enableLights(true)
          vibrationPattern = longArrayOf(0L, 250L, 120L, 250L)
          lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }

      manager.createNotificationChannel(monitorChannel)
      manager.createNotificationChannel(alertsChannel)
    }
  }

  fun hasNotificationPermission(context: Context): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
        PackageManager.PERMISSION_GRANTED
    } else {
      true
    }
  }

  fun buildMonitorNotification(
    context: Context,
    bodyText: String = context.getString(R.string.monitor_notif_body),
  ): Notification {
    ensureChannels(context)
    val openIntent =
      PendingIntent.getActivity(
        context,
        0,
        Intent(context, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )

    return NotificationCompat.Builder(context, MONITOR_CHANNEL_ID)
      .setSmallIcon(android.R.drawable.ic_lock_lock)
      .setContentTitle(context.getString(R.string.monitor_notif_title))
      .setContentText(bodyText)
      .setStyle(NotificationCompat.BigTextStyle().bigText(bodyText))
      .setContentIntent(openIntent)
      .setOngoing(true)
      .setSilent(true)
      .build()
  }

  fun updateMonitorNotification(context: Context, bodyText: String) {
    if (!hasNotificationPermission(context)) return
    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    manager.notify(MONITOR_NOTIFICATION_ID, buildMonitorNotification(context, bodyText))
  }

  fun postSecurityThreatPushAlert(
    context: Context,
    alertType: ThreatAlertType,
    title: String,
    message: String,
    appName: String = "",
    packageName: String? = null,
    sha256Fingerprint: String? = null,
    auditId: Long = -1L,
    idOffset: Int = 2000,
  ): Int? {
    if (!hasNotificationPermission(context)) return null

    ensureChannels(context)
    val notificationId = idOffset + ((packageName?.hashCode() ?: title.hashCode()) and 0x3FF)

    val detailIntent =
      Intent(context, MainActivity::class.java).apply {
        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        if (auditId > 0L) {
          putExtra(EXTRA_AUDIT_ID, auditId)
        }
        if (!packageName.isNullOrBlank()) {
          putExtra(EXTRA_PACKAGE_NAME, packageName)
        }
        if (auditId <= 0L && packageName.isNullOrBlank()) {
          putExtra(EXTRA_TARGET_TAB, "behavior")
        }
      }

    val contentPendingIntent =
      PendingIntent.getActivity(
        context,
        notificationId,
        detailIntent,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )

    val builder =
      NotificationCompat.Builder(context, ALERTS_CHANNEL_ID)
        .setSmallIcon(android.R.drawable.stat_sys_warning)
        .setContentTitle(title)
        .setSubText(alertType.badgeLabel)
        .setContentText(message)
        .setStyle(NotificationCompat.BigTextStyle().bigText(message))
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .setCategory(NotificationCompat.CATEGORY_ALARM)
        .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
        .setDefaults(NotificationCompat.DEFAULT_ALL)
        .setAutoCancel(true)
        .setContentIntent(contentPendingIntent)

    val hasValidPackage = !packageName.isNullOrBlank() && packageName != context.packageName
    val hasValidSignature =
      !sha256Fingerprint.isNullOrBlank() && sha256Fingerprint != "SEM ASSINATURA"

    // 1. Quick Uninstall Action (system confirmation dialog via ACTION_DELETE)
    if (hasValidPackage && alertType != ThreatAlertType.BLOCKED_INSTALL) {
      val uninstallIntent =
        Intent(Intent.ACTION_DELETE).apply {
          data = Uri.fromParts("package", packageName, null)
          addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
      val uninstallPendingIntent =
        PendingIntent.getActivity(
          context,
          notificationId + 20_000,
          uninstallIntent,
          PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
      builder.addAction(
        android.R.drawable.ic_menu_delete,
        "Desinstalar",
        uninstallPendingIntent,
      )
    }

    // 2. Quick Block Action (blocks signature and/or package in Sentinela database)
    if (hasValidSignature || hasValidPackage) {
      val blockIntent =
        Intent(context, NotificationActionReceiver::class.java).apply {
          action = NotificationActionReceiver.ACTION_BLOCK_THREAT
          putExtra(NotificationActionReceiver.EXTRA_SHA256, sha256Fingerprint.orEmpty())
          putExtra(NotificationActionReceiver.EXTRA_APP_NAME, appName.ifBlank { title })
          putExtra(NotificationActionReceiver.EXTRA_PACKAGE_NAME, packageName.orEmpty())
          putExtra(NotificationActionReceiver.EXTRA_NOTIFICATION_ID, notificationId)
        }
      val blockPendingIntent =
        PendingIntent.getBroadcast(
          context,
          notificationId + 10_000,
          blockIntent,
          PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
      builder.addAction(
        android.R.drawable.ic_delete,
        "Bloquear",
        blockPendingIntent,
      )
    }

    // 3. Inspect Audit Action
    builder.addAction(
      android.R.drawable.ic_menu_info_details,
      "Inspecionar",
      contentPendingIntent,
    )

    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    manager.notify(notificationId, builder.build())
    return notificationId
  }

  fun cancelNotification(context: Context, notificationId: Int) {
    if (notificationId == -1) return
    val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    manager.cancel(notificationId)
  }

  fun postThreatAlert(context: Context, title: String, message: String, idOffset: Int = 2000) {
    postSecurityThreatPushAlert(
      context = context,
      alertType = ThreatAlertType.SUSPICIOUS_BEHAVIOR,
      title = title,
      message = message,
      idOffset = idOffset,
    )
  }
}
