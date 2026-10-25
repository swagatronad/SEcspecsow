@file:Suppress("DEPRECATION")

package com.secscan

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

val SAFE_PREFIX = listOf(
    "/system/", "/vendor/", "/apex/", "/product/", "/system_ext/", "/odm/",
    "/bin/", "/sbin/", "/debug_ramdisk/", "/data/adb/magisk", "/data/adb/ksu",
    "/linkerconfig/"
)
val BAD_PREFIX = listOf(
    "/data/local/tmp", "/sdcard", "/storage/", "/data/media", "/dev/shm", "/tmp"
)

fun isSystemPkg(pm: PackageManager, p: String): Boolean = try {
    (pm.getApplicationInfo(p, 0).flags and ApplicationInfo.FLAG_SYSTEM) != 0
} catch (e: Exception) {
    false
}

fun analyze(procs: List<Proc>, conns: List<Conn>): List<Finding> {
    val out = ArrayList<Finding>()
    val exeRe = Regex("""/proc/(\d+)/exe -> (.+)""")
    val exe = HashMap<Int, String>()
    for (l in Shell.cmd("ls -l /proc/[0-9]*/exe 2>/dev/null").exec().out) {
        exeRe.find(l)?.let { exe[it.groupValues[1].toInt()] = it.groupValues[2].trim() }
    }
    for (p in procs) {
        if (p.cmd.startsWith("[")) continue
        val path = exe[p.pid] ?: continue
        val deleted = path.endsWith("(deleted)") || path.startsWith("/memfd:")
        val bad = BAD_PREFIX.any { path.startsWith(it) }
        val rootOdd = p.user == "root" && SAFE_PREFIX.none { path.startsWith(it) }
        val termux = path.contains("/com.termux/")
        val appPriv = p.user != "root" && p.user != "system" && !termux &&
            (path.startsWith("/data/data/") || path.startsWith("/data/user/"))
        val hasExt = conns.any { it.pid == p.pid && it.external }
        val info = "PID ${p.pid}, пользователь ${p.user}" +
            (if (hasExt) ", ЕСТЬ внешнее соединение" else "") +
            ". Команда: ${p.cmd.cut(100)}"
        when {
            deleted -> out.add(Finding(2, "Процессы", "Запущен из удалённого файла или из памяти", path, info, p.pid))
            bad -> out.add(Finding(2, "Процессы", "Запущен из подозрительной папки", path, info, p.pid))
            rootOdd -> out.add(Finding(if (hasExt) 2 else 1, "Процессы", "Root-процесс вне системных папок", path, info, p.pid))
            appPriv -> out.add(Finding(if (hasExt) 2 else 1, "Процессы", "Программа запущена из личной папки приложения", path, info, p.pid))
        }
    }

    val psPids = procs.map { it.pid }.toSet()
    val procDirs = Shell.cmd("ls /proc").exec().out
        .flatMap { it.trim().split(Regex("\\s+")) }
        .mapNotNull { it.toIntOrNull() }
    val missing = procDirs.filter { it !in psPids }
    if (missing.isNotEmpty()) {
        val ps2 = Shell.cmd("ps -A -o PID").exec().out.mapNotNull { it.trim().toIntOrNull() }.toSet()
        val ghosts = missing.filter { it !in ps2 && it > 1 }.filter {
            Shell.cmd("[ -d /proc/$it ] && echo y").exec().out.firstOrNull()?.trim() == "y"
        }.take(10)
        for (g in ghosts) {
            val cl = Shell.cmd("cat /proc/$g/cmdline 2>/dev/null | tr '\\000' ' '").exec().out
                .joinToString("").trim().cut(100)
            out.add(Finding(2, "Процессы", "Процесс виден в /proc, но скрыт от ps",
                "PID $g", "Возможный признак руткита. Команда: ${if (cl.isEmpty()) "(пусто)" else cl}", g))
        }
    }

    for (c in conns) {
        if (c.external && c.pid == null && c.state == "ESTAB") {
            out.add(Finding(1, "Сеть", "Внешнее соединение без видимого процесса", c.remote,
                "${c.proto} ${c.local} → ${c.remote}. Может быть скрытый процесс или короткое системное соединение."))
        }
    }

    val seenL = HashSet<String>()
    for (c in conns) {
        if (c.state != "LISTEN") continue
        val any = c.local.startsWith("0.0.0.0:") ||
            c.local.startsWith("[0000:0000:0000:0000:0000:0000:0000:0000]:")
        if (!any) continue
        val port = c.local.substringAfterLast(":")
        if (!seenL.add("${c.pid}:$port")) continue
        out.add(Finding(1, "Сеть", "Порт открыт для всей сети", "${c.name}:$port",
            "Процесс ${c.name} (PID ${c.pid ?: "?"}) принимает входящие соединения на порту $port. Так работают серверы и бэкдоры.", c.pid))
    }
    return out
}

fun systemChecks(acc: List<String>): List<Finding> {
    val out = ArrayList<Finding>()
    for (a in acc) {
        out.add(Finding(1, "Система", "Включена служба специальных возможностей", a,
            "Через неё приложения могут читать экран и нажимать за вас. Если вы её не включали, проверьте."))
    }
    for (a in settingsList("enabled_notification_listeners")) {
        out.add(Finding(0, "Система", "Приложение читает ваши уведомления", a,
            "Справочно: так делают часы и мессенджеры, но и шпионы."))
    }
    if (Shell.cmd("getenforce").exec().out.firstOrNull()?.trim().equals("Permissive", true)) {
        out.add(Finding(2, "Система", "SELinux в режиме Permissive", "getenforce",
            "Защита SELinux отключена: процессы могут делать больше, чем положено."))
    }
    if (prop("ro.debuggable") == "1") {
        out.add(Finding(1, "Система", "Система в режиме отладки", "ro.debuggable=1",
            "Прошивка собрана с включённой отладкой."))
    }
    val adbPort = listOf(prop("service.adb.tcp.port"), prop("persist.adb.tcp.port"))
        .mapNotNull { it.toIntOrNull() }.firstOrNull { it > 0 }
    if (adbPort != null) {
        out.add(Finding(1, "Система", "Включена отладка ADB по сети", "порт $adbPort",
            "Через неё можно управлять телефоном по Wi-Fi. Если вы не включали, это тревожный знак."))
    }
    if (sget("global", "adb_enabled") == "1") {
        out.add(Finding(0, "Система", "Включена отладка по USB", "adb_enabled=1", "Справочно."))
    }
    val proxy = sget("global", "http_proxy")
    if (proxy.isNotEmpty() && proxy != ":0") {
        out.add(Finding(1, "Система", "Задан глобальный прокси", proxy,
            "Весь трафик может идти через чужой сервер."))
    }
    val cas = Shell.cmd("ls /data/misc/user/0/cacerts-added 2>/dev/null").exec().out.filter { it.isNotBlank() }
    if (cas.isNotEmpty()) {
        out.add(Finding(1, "Система", "Установлены пользовательские сертификаты", "${cas.size} шт.",
            "Позволяют перехватывать HTTPS. Нормально для Burp, AdGuard и корпоративных сетей, иначе проверьте."))
    }
    val preload = Shell.cmd("ls /system/etc/ld.so.preload /etc/ld.so.preload 2>/dev/null").exec().out
        .filter { it.isNotBlank() }
    for (p in preload) {
        out.add(Finding(2, "Система", "Найден ld.so.preload", p,
            "Принудительно подгружает библиотеки во все процессы. Классический приём руткитов."))
    }
    if (Shell.cmd("ls /sys/class/net").exec().out.joinToString(" ").contains("tun")) {
        out.add(Finding(0, "Система", "Активен VPN-интерфейс (tun)", "tun",
            "Справочно: работает VPN или прокси-приложение."))
    }
    val da = Shell.cmd(
        """dumpsys device_policy 2>/dev/null | grep -oE 'admin=ComponentInfo\{[^}]*\}' | sort -u"""
    ).exec().out
    for (l in da) {
        val comp = l.substringAfter("ComponentInfo{").removeSuffix("}")
        val pkg = comp.substringBefore("/")
        val lvl = if (pkg.startsWith("com.google.") || pkg.startsWith("com.android.")) 0 else 1
        out.add(Finding(lvl, "Система", "Администратор устройства", comp,
            "Такие приложения трудно удалить, и у них расширенные права."))
    }
    return out
}

val LINE_RE = Regex("^(.+?):(\\d+):(.*)")

fun parseGrep(
    lines: List<String>, level: Int, title: String,
    seen: MutableSet<String>, counts: MutableMap<String, Int>, out: MutableList<Finding>
) {
    for (l in lines) {
        val m = LINE_RE.find(l) ?: continue
        val file = m.groupValues[1]
        val no = m.groupValues[2]
        if (!seen.add("$file:$no")) continue
        val n = (counts[file] ?: 0) + 1
        counts[file] = n
        if (n > 3) continue
        out.add(Finding(level, "Скрипты", title, file, "строка $no: " + m.groupValues[3].trim().cut(120)))
    }
}

fun scanScripts(deep: Boolean): List<Finding> {
    val out = ArrayList<Finding>()
    var roots = "/data/local/tmp /data/adb /data/media/0 /dev/shm /tmp /system/etc /system/bin /system/xbin /vendor/bin /vendor/etc /product/etc"
    if (deep) roots += " /data/data /data/app /data/local /data/system /system /vendor /product /system_ext"
    val sel = """\( -name '*.sh' -o -name '*.bash' \) -size -1024k"""
    val high = """'/dev/tcp/|(^|[ ;|&(])nc +(-[a-z]*e|.* -e )|(curl|wget)[^|]*\| *(ba)?sh|base64 +(-d|--decode)[^|]*\| *(ba)?sh|mkfifo|socat|ncat|bash -i'"""
    val warn = """'wget |curl |nohup |chmod .*/(data/local/tmp|sdcard)|pm +install|pm +grant|settings +put secure'"""
    val seen = HashSet<String>()
    val counts = HashMap<String, Int>()

    val h = Shell.cmd("find $roots -type f $sel -exec grep -nHIE $high {} + 2>/dev/null").exec().out
    parseGrep(h, 2, "Опасная команда в скрипте", seen, counts, out)

    val anyRoots = if (deep) "/data/local/tmp /data/media/0 /dev/shm /tmp" else "/data/local/tmp /dev/shm /tmp"
    val h2 = Shell.cmd("find $anyRoots -type f -size -512k -exec grep -nHIE $high {} + 2>/dev/null").exec().out
    parseGrep(h2, 2, "Опасная команда в файле", seen, counts, out)

    val w = Shell.cmd("find $roots -type f $sel -exec grep -nHIE $warn {} + 2>/dev/null").exec().out
    parseGrep(w, 1, "Подозрительная команда в скрипте", seen, counts, out)
    return out
}

fun scanFiles(): List<Finding> {
    val out = ArrayList<Finding>()
    Shell.cmd("find /data/local/tmp /dev/shm /tmp -type f -perm -u+x 2>/dev/null | head -200").exec().out
        .filter { it.isNotBlank() }
        .forEach {
            out.add(Finding(1, "Файлы", "Исполняемый файл во временной папке", it,
                "Здесь обычно нет программ. Если это не ваши инструменты, проверьте файл."))
        }
    Shell.cmd("find /data/local/tmp /dev/shm /data/media/0 -type f \\( -name '*.so' -o -name '*.elf' \\) 2>/dev/null | head -200").exec().out
        .filter { it.isNotBlank() }
        .forEach {
            out.add(Finding(1, "Файлы", "Библиотека или ELF-файл вне системы", it,
                "Бинарные файлы на накопителе или во временных папках встречаются у вредоносных программ."))
        }
    Shell.cmd("find /data -xdev -type f -perm -4000 2>/dev/null | head -50").exec().out
        .filter { it.isNotBlank() }
        .forEach {
            out.add(Finding(2, "Файлы", "SUID-файл в /data", it,
                "Файл с правами запуска от root. Для обычных приложений это почти всегда плохой знак."))
        }
    Shell.cmd("find /data/adb/service.d /data/adb/post-fs-data.d /system/etc/init.d -type f 2>/dev/null").exec().out
        .filter { it.isNotBlank() }
        .forEach { out.add(Finding(0, "Автозапуск", "Скрипт автозапуска", it, "Выполняется при загрузке телефона.")) }
    Shell.cmd("ls /data/adb/modules 2>/dev/null").exec().out
        .filter { it.isNotBlank() }
        .forEach { out.add(Finding(0, "Автозапуск", "Magisk-модуль", "/data/adb/modules/$it", "Установленный модуль Magisk.")) }
    return out
}

fun scanApps(ctx: Context, accPkgs: Set<String>): List<Finding> {
    val pm = ctx.packageManager
    val out = ArrayList<Finding>()
    val sens = mapOf(
        "android.permission.RECORD_AUDIO" to "микрофон",
        "android.permission.CAMERA" to "камера",
        "android.permission.READ_SMS" to "чтение SMS",
        "android.permission.SEND_SMS" to "отправка SMS",
        "android.permission.RECEIVE_SMS" to "приём SMS",
        "android.permission.READ_CALL_LOG" to "журнал звонков",
        "android.permission.READ_CONTACTS" to "контакты",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "геолокация в фоне",
        "android.permission.SYSTEM_ALERT_WINDOW" to "окна поверх других",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "установка приложений"
    )
    val stores = setOf(
        "com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps",
        "com.heytap.market", "com.oppo.market", "com.oplus.appmarket", "com.xiaomi.mipicks",
        "com.huawei.appmarket", "org.fdroid.fdroid", "com.aurora.store"
    )
    val pkgs = try {
        pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
    } catch (e: Exception) {
        return out
    }
    for (p in pkgs) {
        if (p.packageName == ctx.packageName) continue
        val ai = p.applicationInfo ?: continue
        if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0) continue
        if (!ai.enabled) continue
        val inst = try { pm.getInstallerPackageName(p.packageName) } catch (e: Exception) { null }
        val side = inst == null || inst !in stores
        val perms = p.requestedPermissions
        val flags = p.requestedPermissionsFlags
        val granted = ArrayList<String>()
        if (perms != null && flags != null) {
            for (i in perms.indices) {
                if ((flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) {
                    sens[perms[i]]?.let { granted.add(it) }
                }
            }
        }
        val isAcc = p.packageName in accPkgs
        val noIcon = pm.getLaunchIntentForPackage(p.packageName) == null
        val label = pm.getApplicationLabel(ai).toString()
        val detail = "$label. Источник: ${inst ?: "неизвестен (вне магазина)"}. " +
            "Доступы: ${if (granted.isEmpty()) "нет чувствительных" else granted.joinToString(", ")}" +
            (if (isAcc) ". Включена служба спец. возможностей" else "") +
            (if (noIcon) ". Нет значка запуска" else "")
        val lvl = when {
            side && (isAcc || granted.size >= 4) -> 2
            side && noIcon && granted.size >= 2 -> 2
            side && noIcon -> 1
            side && granted.size >= 2 -> 1
            else -> -1
        }
        if (lvl >= 0) {
            val title = if (noIcon) "Скрытое приложение (без значка) вне магазина"
            else "Приложение вне магазина с широкими доступами"
            out.add(Finding(lvl, "Приложения", title, p.packageName, detail))
        }
        if ((ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            out.add(Finding(1, "Приложения", "Приложение в режиме отладки", p.packageName,
                "$label. Такие приложения можно изучать и подменять."))
        }
    }
    return out
}

fun parseAgo(s: String): Long {
    var total = 0L
    Regex("""(\d+)(d|h|ms|m|s)""").findAll(s).forEach {
        val n = it.groupValues[1].toLong()
        total += when (it.groupValues[2]) {
            "d" -> n * 86400L
            "h" -> n * 3600L
            "m" -> n * 60L
            "s" -> n
            else -> 0L
        }
    }
    return total
}

fun appOpsLog(ctx: Context): List<Finding> {
    val out = ArrayList<Finding>()
    val pm = ctx.packageManager
    val ops = listOf("RECORD_AUDIO" to "Микрофон", "CAMERA" to "Камера", "FINE_LOCATION" to "Геолокация")
    val pkgRe = Regex("""Package ([A-Za-z0-9_.]+)""")
    val tagRe = Regex("""\[([^\]]+)\]""")
    val agoRe = Regex("""\(([^)]*ago)\)""")
    for ((op, label) in ops) {
        val lines = Shell.cmd("dumpsys appops --op $op 2>/dev/null").exec().out
        var pkg: String? = null
        val best = HashMap<String, Pair<Long, Boolean>>()
        for (l in lines) {
            val t = l.trim()
            if (t.startsWith("Uid ")) { pkg = null; continue }
            if (t.startsWith("Package ")) { pkg = pkgRe.find(t)?.groupValues?.get(1); continue }
            if (!t.startsWith("Access:")) continue
            val p = pkg ?: continue
            val secs = agoRe.findAll(t).map { parseAgo(it.groupValues[1]) }.minOrNull() ?: continue
            val bg = tagRe.findAll(t).any {
                val g = it.groupValues[1]
                g.startsWith("bg") || g.startsWith("cch")
            }
            val old = best[p]
            if (old == null || secs < old.first) best[p] = Pair(secs, bg)
        }
        for ((p, v) in best) {
            if (v.first > 86400L || p == ctx.packageName || isSystemPkg(pm, p)) continue
            val lvl = if (v.second) 1 else 0
            out.add(Finding(lvl, "Доступ", "$label: использовался за последние сутки", p,
                "Последний доступ ${fmtAgo(v.first)} назад" +
                    (if (v.second) ", в фоновом режиме" else "") +
                    ". Проверьте, ожидаете ли вы этого от приложения."))
        }
    }
    return out
}

fun trafficStats(ctx: Context): List<Traffic> {
    // Do not grant protected AppOps permissions automatically; the user must enable access in Android Settings.
    val nsm = ctx.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
    val pm = ctx.packageManager
    val end = System.currentTimeMillis()
    val start = end - 24L * 3600L * 1000L
    val map = HashMap<Int, LongArray>()
    for (type in listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
        try {
            val st = nsm.querySummary(type, null, start, end)
            val b = NetworkStats.Bucket()
            while (st.hasNextBucket()) {
                st.getNextBucket(b)
                val a = map.getOrPut(b.uid) { LongArray(2) }
                a[0] += b.txBytes
                a[1] += b.rxBytes
            }
            st.close()
        } catch (e: Exception) {
        }
    }
    return map.map { (uid, a) ->
        val name = pm.getPackagesForUid(uid)?.firstOrNull() ?: "uid $uid"
        Traffic(name, a[0], a[1])
    }.filter { it.tx + it.rx > 0 }.sortedByDescending { it.tx }.take(40)
}

fun trafficFindings(ctx: Context, tr: List<Traffic>): List<Finding> {
    val pm = ctx.packageManager
    val out = ArrayList<Finding>()
    for (t in tr) {
        if (t.tx < 50L * 1024L * 1024L || t.tx < t.rx * 2) continue
        if (!PKG_OK.matches(t.pkg) || isSystemPkg(pm, t.pkg)) continue
        out.add(Finding(0, "Трафик", "Много исходящих данных за сутки", t.pkg,
            "Отправлено ${fmtBytes(t.tx)}, получено ${fmtBytes(t.rx)}. Для облака и мессенджеров это может быть нормой."))
    }
    return out
}

suspend fun runFullScan(ctx: Context, deep: Boolean, onStatus: (String) -> Unit): ScanResult? =
    withContext(Dispatchers.IO) {
        if (!Shell.getShell().isRoot) return@withContext null
        onStatus("Читаю процессы и сеть...")
        val (p, c) = safe(Pair(emptyList<Proc>(), emptyList<Conn>())) { loadAll() }
        onStatus("Анализ процессов и портов...")
        val f1 = safe(emptyList<Finding>()) { analyze(p, c) }
        onStatus("Проверка системы...")
        val acc = safe(emptyList<String>()) { settingsList("enabled_accessibility_services") }
        val f4 = safe(emptyList<Finding>()) { systemChecks(acc) }
        onStatus("Проверка приложений...")
        val f5 = safe(emptyList<Finding>()) { scanApps(ctx, acc.map { it.substringBefore("/") }.toSet()) }
        onStatus("Журнал микрофона, камеры и геолокации...")
        val f6 = safe(emptyList<Finding>()) { appOpsLog(ctx) }
        onStatus("Трафик приложений...")
        val tr = safe(emptyList<Traffic>()) { trafficStats(ctx) }
        val f7 = safe(emptyList<Finding>()) { trafficFindings(ctx, tr) }
        onStatus(if (deep) "Глубокий скан скриптов (несколько минут)..." else "Проверка скриптов...")
        val f2 = safe(emptyList<Finding>()) { scanScripts(deep) }
        onStatus("Проверка файлов и SUID...")
        val f3 = safe(emptyList<Finding>()) { scanFiles() }
        val all = (f1 + f2 + f3 + f4 + f5 + f6 + f7)
            .sortedWith(compareByDescending<Finding> { it.level }.thenBy { it.category })
        ScanResult(p, c, all, tr)
    }

// END
