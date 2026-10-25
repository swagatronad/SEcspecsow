package com.secscan

import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class Proc(val pid: Int, val user: String, val cmd: String)

data class Conn(
    val proto: String, val state: String,
    val local: String, val remote: String,
    val pid: Int?, val name: String, val external: Boolean
)

data class Finding(
    val level: Int, val category: String, val title: String,
    val path: String, val detail: String, val pid: Int? = null
) {
    val key: String get() = "$category|$title|$path"
}

data class Traffic(val pkg: String, val tx: Long, val rx: Long)

data class QItem(val id: String, val perms: String, val path: String)

data class ScanResult(
    val procs: List<Proc>, val conns: List<Conn>,
    val findings: List<Finding>, val traffic: List<Traffic>
)

fun String.cut(n: Int): String = if (length > n) take(n) + "…" else this

val PATH_OK = Regex("^[A-Za-z0-9_./@:+,=-]+$")
val PKG_OK = Regex("^[A-Za-z0-9_.]+$")

fun safePath(p: String): String? {
    val s = p.removeSuffix(" (deleted)").trim()
    return if (s.startsWith("/") && PATH_OK.matches(s)) s else null
}

fun prop(n: String): String =
    Shell.cmd("getprop $n").exec().out.firstOrNull()?.trim() ?: ""

fun sget(ns: String, k: String): String {
    val v = Shell.cmd("settings get $ns $k").exec().out.joinToString("").trim()
    return if (v == "null") "" else v
}

fun settingsList(k: String): List<String> =
    sget("secure", k).split(":").filter { it.isNotBlank() }

suspend fun sha256Of(path: String): String? = withContext(Dispatchers.IO) {
    val sp = safePath(path) ?: return@withContext null
    val o = Shell.cmd("sha256sum '$sp' 2>/dev/null").exec().out.firstOrNull()
        ?: return@withContext null
    o.trim().split(Regex("\\s+")).firstOrNull()?.takeIf { it.length == 64 }
}

fun levelName(l: Int) = when (l) { 2 -> "КРИТИЧНО"; 1 -> "ВНИМАНИЕ"; else -> "ИНФО" }

fun fmtBytes(b: Long): String = when {
    b >= 1_073_741_824L -> "%.2f ГБ".format(b / 1_073_741_824.0)
    b >= 1_048_576L -> "%.1f МБ".format(b / 1_048_576.0)
    b >= 1024L -> "%.0f КБ".format(b / 1024.0)
    else -> "$b Б"
}

fun fmtAgo(s: Long): String = when {
    s < 60 -> "$s с"
    s < 3600 -> "${s / 60} мин"
    else -> "${s / 3600} ч ${(s % 3600) / 60} мин"
}

inline fun <T> safe(def: T, f: () -> T): T =
    try { f() } catch (e: Exception) { def }

// END
