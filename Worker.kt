package com.secscan

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.topjohnwu.superuser.Shell
import java.util.concurrent.TimeUnit

fun notifyFindings(ctx: Context, fresh: List<Finding>) {
    val nm = ctx.getSystemService(NotificationManager::class.java)
    nm.createNotificationChannel(
        NotificationChannel("secscan_alerts", "Предупреждения SecScan", NotificationManager.IMPORTANCE_HIGH)
    )
    val open = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, MainActivity::class.java),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val text = fresh.take(4).joinToString("\n") { "• " + it.title + ": " + it.path.cut(60) }
    val n = Notification.Builder(ctx, "secscan_alerts")
        .setSmallIcon(android.R.drawable.ic_dialog_alert)
        .setContentTitle("SecScan: новых находок ${fresh.size}")
        .setContentText(fresh.first().title)
        .setStyle(Notification.BigTextStyle().bigText(text))
        .setContentIntent(open)
        .setAutoCancel(true)
        .build()
    nm.notify(1001, n)
}

class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        try {
            val ctx = applicationContext
            val res = runFullScan(ctx, false) { } ?: return Result.success()
            AppCtx.c = ctx
            val prefs = SecPrefs.open(ctx)
            val trusted = prefs.getStringSet("trusted", emptySet<String>())!!.toSet()
            val baseline = prefs.getStringSet("baseline", emptySet<String>())!!.toSet()
            val notified = prefs.getStringSet("notified", emptySet<String>())!!.toSet()
            val minLevel = if (baseline.isEmpty()) 2 else 1
            val fresh = res.findings.filter {
                it.level >= minLevel && it.key !in trusted && it.key !in notified &&
                    (baseline.isEmpty() || it.key !in baseline)
            }
            if (fresh.isNotEmpty()) {
                notifyFindings(ctx, fresh)
                prefs.edit().putStringSet("notified", notified + fresh.map { it.key }).apply()
            }
        } catch (e: Exception) {
        }
        return Result.success()
    }
}

fun scheduleScan(ctx: Context, on: Boolean) {
    val wm = WorkManager.getInstance(ctx)
    if (on) {
        // Notification permission must be requested/granted by the user through Android UI.
        val req = PeriodicWorkRequestBuilder<ScanWorker>(1, TimeUnit.HOURS).build()
        wm.enqueueUniquePeriodicWork("secscan_bg", ExistingPeriodicWorkPolicy.UPDATE, req)
    } else {
        wm.cancelUniqueWork("secscan_bg")
    }
}

// END
