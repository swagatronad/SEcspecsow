package com.secscan

import android.content.Context
import android.util.Base64
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

const val QDIR = "/data/adb/secscan_q"
const val MAX_ENC = 8L * 1024L * 1024L

val QID = Regex("""\d+(\.enc)?""")
val QPERM = Regex("""\d+(:\d+:\d+)?""")

val BLOCKED_Q = listOf(
    "/system/", "/vendor/", "/apex/", "/product/", "/system_ext/", "/odm/",
    "/proc/", "/sys/", "/memfd:", "/data/adb/magisk", "/data/adb/modules",
    "/data/adb/ksu", "/data/adb/secscan_q", "/data/data/com.secscan",
    "/data/user/0/com.secscan"
)

val QItem.encrypted: Boolean get() = id.endsWith(".enc")

fun canQuarantine(p: String): Boolean {
    if (p.endsWith("(deleted)")) return false
    val sp = safePath(p) ?: return false
    if (sp.startsWith("/dev/") && !sp.startsWith("/dev/shm/")) return false
    return BLOCKED_Q.none { sp.startsWith(it) }
}

suspend fun quarantine(path: String): String = withContext(Dispatchers.IO) {
    val sp = safePath(path) ?: return@withContext "Путь не подходит (пробелы или спецсимволы)"
    if (!canQuarantine(sp)) return@withContext "Защищённый путь, перенос запрещён"
    val meta = Shell.cmd("stat -c '%a:%u:%g' '$sp'").exec().out.firstOrNull()?.trim() ?: ""
    val perms = if (QPERM.matches(meta)) meta else "755"
    val id = System.currentTimeMillis().toString()
    val size = Shell.cmd("stat -c %s '$sp'").exec().out.firstOrNull()?.trim()?.toLongOrNull() ?: -1L
    val ctx = AppCtx.c

    if (ctx != null && size in 0..MAX_ENC) {
        val tmp = File(ctx.cacheDir, "q_$id.tmp")
        try {
            val rd = Shell.cmd("base64 '$sp'").exec()
            if (rd.isSuccess) {
                val data = Base64.decode(rd.out.joinToString(""), Base64.DEFAULT)
                tmp.writeBytes(Vault.encryptBytes(data))
                val name = "$id.enc"
                val r = Shell.cmd(
                    "mkdir -p $QDIR && chmod 700 $QDIR && mv -f '${tmp.absolutePath}' $QDIR/$name && " +
                        "chmod 600 $QDIR/$name && rm -f '$sp' && echo '$name|$perms|$sp' >> $QDIR/index.txt"
                ).exec()
                if (r.isSuccess) return@withContext "Файл зашифрован и перенесён в карантин"
            }
        } catch (e: Exception) {
        } finally {
            tmp.delete()
        }
    }

    val r = Shell.cmd(
        "mkdir -p $QDIR && chmod 700 $QDIR && mv -f '$sp' $QDIR/$id && chmod 000 $QDIR/$id && " +
            "echo '$id|$perms|$sp' >> $QDIR/index.txt"
    ).exec()
    if (r.isSuccess) {
        "Файл перенесён в карантин БЕЗ шифрования (больше 8 МБ), права запуска сняты"
    } else {
        "Не удалось: " + r.err.joinToString(" ").cut(120)
    }
}

fun listQuarantine(): List<QItem> {
    val present = Shell.cmd("ls $QDIR 2>/dev/null").exec().out.map { it.trim() }.toSet()
    return Shell.cmd("cat $QDIR/index.txt 2>/dev/null").exec().out.mapNotNull { l ->
        val p = l.split("|", limit = 3)
        if (p.size == 3 && p[0] in present) QItem(p[0], p[1], p[2]) else null
    }
}

suspend fun restoreQ(q: QItem): String = withContext(Dispatchers.IO) {
    val sp = safePath(q.path) ?: return@withContext "Путь не подходит"
    if (!QID.matches(q.id) || !QPERM.matches(q.perms)) return@withContext "Повреждённая запись"
    val parent = sp.substringBeforeLast("/").ifEmpty { "/" }
    val parts = q.perms.split(":")
    val pm = parts[0]
    val ug = if (parts.size == 3) "${parts[1]}:${parts[2]}" else null

    if (q.encrypted) {
        val ctx = AppCtx.c ?: return@withContext "Приложение не готово, попробуйте ещё раз"
        val o = Shell.cmd("base64 $QDIR/${q.id}").exec()
        if (!o.isSuccess) return@withContext "Не удалось прочитать файл карантина"
        val plain: ByteArray? = try {
            Vault.decryptBytes(Base64.decode(o.out.joinToString(""), Base64.DEFAULT))
        } catch (e: Exception) {
            null
        }
        if (plain == null) {
            return@withContext "Ключ шифрования недоступен: файл расшифровать нельзя (приложение переустанавливали?)"
        }
        val tmp = File(ctx.cacheDir, "r_${q.id}")
        try {
            tmp.writeBytes(plain)
            val chown = if (ug != null) " && chown $ug '$sp'" else ""
            Shell.cmd(
                "mkdir -p '$parent' && mv -f '${tmp.absolutePath}' '$sp' && chmod $pm '$sp'$chown && " +
                    "rm -f $QDIR/${q.id} && sed -i '/^${q.id}|/d' $QDIR/index.txt; restorecon '$sp' 2>/dev/null"
            ).exec()
        } finally {
            tmp.delete()
        }
        val ok = Shell.cmd("[ -f '$sp' ] && echo ok").exec().out.firstOrNull()?.trim() == "ok"
        return@withContext if (ok) "Файл расшифрован и возвращён на место" else "Не удалось вернуть"
    }

    val r = Shell.cmd(
        "mkdir -p '$parent' && mv -f $QDIR/${q.id} '$sp' && chmod $pm '$sp' && " +
            "sed -i '/^${q.id}|/d' $QDIR/index.txt"
    ).exec()
    if (r.isSuccess) "Файл возвращён на место" else "Не удалось вернуть"
}

suspend fun deleteQ(q: QItem): String = withContext(Dispatchers.IO) {
    if (!QID.matches(q.id)) return@withContext "Повреждённая запись"
    val r = Shell.cmd("rm -f $QDIR/${q.id} && sed -i '/^${q.id}|/d' $QDIR/index.txt").exec()
    if (r.isSuccess) "Файл удалён навсегда" else "Не удалось удалить"
}

suspend fun killProc(pid: Int): String = withContext(Dispatchers.IO) {
    if (pid <= 1) return@withContext "Нельзя остановить этот процесс"
    val r = Shell.cmd("kill -9 $pid").exec()
    if (r.isSuccess) "Процесс $pid остановлен" else "Не удалось остановить"
}

suspend fun forceStop(pkg: String): String = withContext(Dispatchers.IO) {
    if (!PKG_OK.matches(pkg)) return@withContext "Неверное имя пакета"
    val r = Shell.cmd("am force-stop $pkg").exec()
    if (r.isSuccess) "Приложение остановлено" else "Не удалось остановить"
}

suspend fun disablePkg(pkg: String): String = withContext(Dispatchers.IO) {
    if (!PKG_OK.matches(pkg)) return@withContext "Неверное имя пакета"
    val r = Shell.cmd("am force-stop $pkg && pm disable-user --user 0 $pkg").exec()
    if (r.isSuccess) "Приложение отключено" else "Не удалось отключить"
}

suspend fun enablePkg(pkg: String): String = withContext(Dispatchers.IO) {
    if (!PKG_OK.matches(pkg)) return@withContext "Неверное имя пакета"
    val r = Shell.cmd("pm enable $pkg").exec()
    if (r.isSuccess) "Приложение включено" else "Не удалось включить"
}

suspend fun vtLookup(key: String, hash: String): String = withContext(Dispatchers.IO) {
    try {
        val c = URL("https://www.virustotal.com/api/v3/files/$hash").openConnection() as HttpURLConnection
        c.setRequestProperty("x-apikey", key.trim())
        c.connectTimeout = 10000
        c.readTimeout = 15000
        val code = c.responseCode
        if (code == 404) return@withContext "VirusTotal: такого файла в базе нет. Это не значит, что он безопасен."
        if (code == 401 || code == 403) return@withContext "VirusTotal: неверный API-ключ"
        if (code == 429) return@withContext "VirusTotal: лимит запросов, подождите минуту"
        if (code != 200) return@withContext "VirusTotal: ошибка $code"
        val body = c.inputStream.bufferedReader().use { it.readText() }
        val st = JSONObject(body).getJSONObject("data")
            .getJSONObject("attributes").getJSONObject("last_analysis_stats")
        val mal = st.optInt("malicious")
        val sus = st.optInt("suspicious")
        val total = mal + sus + st.optInt("harmless") + st.optInt("undetected")
        "VirusTotal: вредоносный — $mal, подозрительный — $sus из $total движков.\nSHA-256: $hash"
    } catch (e: Exception) {
        "Нет связи с VirusTotal: " + (e.message ?: "ошибка").cut(80)
    }
}

suspend fun saveReport(ctx: Context, text: String): String = withContext(Dispatchers.IO) {
    try {
        val f = File(ctx.cacheDir, "secscan_report.txt")
        f.writeText(text)
        val name = "secscan_report_" +
            SimpleDateFormat("yyyyMMdd_HHmm", Locale.US).format(Date()) + ".txt"
        val r = Shell.cmd("cp '${f.absolutePath}' '/sdcard/Download/$name'").exec()
        if (r.isSuccess) "Сохранено: Download/$name" else "Не удалось сохранить"
    } catch (e: Exception) {
        "Не удалось сохранить"
    }
}

// END
