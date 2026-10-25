package com.secscan

import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPInputStream

const val F_RAT = "RAT / удалённый доступ"
const val F_SPY = "Шпионское ПО"
const val F_LOCK = "Локер / вымогатель"
const val F_DROP = "Загрузчик / дроппер"
const val F_MINE = "Майнер"
const val F_BOT = "Ботнет / сетевая атака"
const val F_EXF = "Кража данных"
const val F_WIPE = "Стиратель данных"
const val F_PRIV = "Захват прав и закрепление"
const val F_HIDE = "Сокрытие следов"
const val F_OBF = "Обфускация"

val FAM_DESC = mapOf(
    F_RAT to "даёт постороннему удалённое управление телефоном (обратная оболочка или канал управления)",
    F_SPY to "тайно собирает данные: экран, звук, камеру, SMS, контакты или геолокацию",
    F_LOCK to "блокирует телефон или шифрует ваши файлы ради выкупа",
    F_DROP to "скачивает и запускает чужой код из интернета",
    F_MINE to "майнит криптовалюту за счёт вашего телефона",
    F_BOT to "делает телефон участником ботнета или атакует и сканирует чужие сети",
    F_EXF to "отправляет ваши данные на внешний сервер",
    F_WIPE to "уничтожает данные или разделы памяти",
    F_PRIV to "получает опасные права, отключает защиту или закрепляется в системе",
    F_HIDE to "заметает следы и скрывает своё присутствие"
)

class Rule(val fam: String, val w: Int, pattern: String, val what: String, ci: Boolean = true) {
    val re: Regex? = try {
        if (ci) Regex(pattern, RegexOption.IGNORE_CASE) else Regex(pattern)
    } catch (e: Exception) {
        null
    }
}

data class Hit(val fam: String, val w: Int, val what: String, val line: String)

data class Analysis(
    val path: String, val level: Int, val title: String, val score: Int,
    val hits: List<Hit>, val iocs: List<String>, val layers: Int,
    val summary: String, val report: String
)

data class ScriptScan(val total: Int, val items: List<Analysis>)

val B64_RE = Regex("""[A-Za-z0-9+/]{32,}={0,2}""")
val HEXESC_RE = Regex("""(?:\\x[0-9a-fA-F]{2}){4,}""")
val OCTESC_RE = Regex("""(?:\\[0-7]{3}){4,}""")
val HEXBLOB_RE = Regex("""\b(?:[0-9a-fA-F]{2}){20,}\b""")
val ROT13_RE = Regex("""tr\s+['"]?A-Za-z['"]?\s+['"]?N-ZA-Mn-za-m""")
val REV_RE = Regex("""\|\s*rev\b""")
val URL_RE = Regex("""https?://[^\s'"<>)\\|;]+""", RegexOption.IGNORE_CASE)
val IP_RE = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b""")
val DEVTCP_RE = Regex("""/dev/(?:tcp|udp)/([^/\s]+)/(\d+)""")

val SKIP_PREFIX = listOf(
    "/data/adb/magisk/", "/data/adb/ksu/", "/data/data/com.termux/files/usr/",
    "/data/data/com.secscan/", "/data/user/0/com.secscan/", "/data/adb/secscan_q/"
)

fun printableRatio(b: ByteArray): Double {
    if (b.isEmpty()) return 0.0
    var ok = 0
    for (x in b) {
        val c = x.toInt() and 0xff
        if (c == 9 || c == 10 || c == 13 || c in 32..126 || c >= 0xC2) ok++
    }
    return ok.toDouble() / b.size
}

fun gunzipLimited(b: ByteArray): ByteArray? {
    if (b.size < 18 || (b[0].toInt() and 0xff) != 0x1f || (b[1].toInt() and 0xff) != 0x8b) return null
    return try {
        GZIPInputStream(ByteArrayInputStream(b)).use { gz ->
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            var total = 0
            while (true) {
                val n = gz.read(buf)
                if (n < 0) break
                total += n
                if (total > 2_000_000) break
                out.write(buf, 0, n)
            }
            out.toByteArray()
        }
    } catch (e: Exception) {
        null
    }
}

fun rot13(s: String): String = buildString {
    for (c in s) {
        append(
            when (c) {
                in 'a'..'z' -> 'a' + (c - 'a' + 13) % 26
                in 'A'..'Z' -> 'A' + (c - 'A' + 13) % 26
                else -> c
            }
        )
    }
}

fun decodeOnce(text: String, notes: MutableList<String>): List<String> {
    val parts = ArrayList<String>()
    val seen = HashSet<String>()

    fun addPart(s: String, how: String) {
        val t = s.trim()
        if (t.length >= 8 && seen.add(t)) {
            parts.add(t)
            val n = "Расшифровано: $how"
            if (n !in notes) notes.add(n)
        }
    }

    fun fromBytes(b: ByteArray, how: String) {
        var d = b
        var h = how
        val gz = gunzipLimited(d)
        if (gz != null) {
            d = gz
            h = "$how, затем gzip"
        }
        if (d.size >= 4 && d[0].toInt() == 0x7f && d[1].toInt() == 0x45 &&
            d[2].toInt() == 0x4c && d[3].toInt() == 0x46
        ) {
            val n = "Внутри закодированных данных спрятан исполняемый файл (ELF): типичный приём вредоносных программ."
            if (n !in notes) notes.add(n)
            return
        }
        if (d.size >= 8 && printableRatio(d) >= 0.92) {
            addPart(String(d, Charsets.UTF_8), h)
        }
    }

    val compact = text.filter { !it.isWhitespace() }
    val cands = ArrayList<String>()
    if (compact.length in 32..800000 &&
        compact.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '=' }
    ) {
        cands.add(compact)
    }
    for (m in B64_RE.findAll(text).take(80)) cands.add(m.value)
    val hasRev = REV_RE.containsMatchIn(text)
    for (c in cands) {
        try {
            fromBytes(Base64.getDecoder().decode(c), "base64")
        } catch (e: Exception) {
        }
        if (hasRev) {
            try {
                fromBytes(Base64.getDecoder().decode(c.reversed()), "base64 наоборот (rev)")
            } catch (e: Exception) {
            }
        }
    }
    for (m in HEXESC_RE.findAll(text).take(40)) {
        try {
            val bytes = m.value.split("\\x").filter { it.isNotEmpty() }
                .map { it.toInt(16).toByte() }.toByteArray()
            fromBytes(bytes, "hex-коды (\\x..)")
        } catch (e: Exception) {
        }
    }
    for (m in OCTESC_RE.findAll(text).take(40)) {
        try {
            val bytes = m.value.split("\\").filter { it.isNotEmpty() }
                .map { it.toInt(8).toByte() }.toByteArray()
            fromBytes(bytes, "восьмеричные коды (\\NNN)")
        } catch (e: Exception) {
        }
    }
    for (m in HEXBLOB_RE.findAll(text).take(40)) {
        try {
            val h = m.value
            val bytes = ByteArray(h.length / 2) { i -> h.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
            fromBytes(bytes, "hex-строка (xxd -r -p)")
        } catch (e: Exception) {
        }
    }
    if (ROT13_RE.containsMatchIn(text)) addPart(rot13(text), "ROT13")
    return parts
}

fun extractIocs(text: String): List<String> {
    val s = LinkedHashSet<String>()
    for (m in DEVTCP_RE.findAll(text)) s.add(m.groupValues[1] + ":" + m.groupValues[2])
    for (m in URL_RE.findAll(text)) s.add(m.value.trimEnd('.', ',', '"', '\''))
    for (m in IP_RE.findAll(text)) {
        val ip = m.value.substringBefore(":")
        val b = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (b.size == 4 && b.all { it in 0..255 } && isExtV4(b)) s.add(m.value)
    }
    return s.take(15)
}

fun analyzeFileSync(path: String): Analysis? {
    val sp = safePath(path) ?: return null
    val ext = sp.substringAfterLast('.', "").lowercase()
    val isElf = if (ext in setOf("sh", "bash", "py", "pl")) {
        false
    } else {
        Shell.cmd("head -c 4 '$sp' 2>/dev/null | od -An -tx1").exec().out
            .joinToString(" ").trim().startsWith("7f 45 4c 46")
    }
    val notes = ArrayList<String>()
    var obf = 0
    val text: String
    if (isElf) {
        notes.add("Это исполняемый бинарный файл (ELF). Проверены только строки внутри него. Названия команд внутри системных программ (toybox, busybox) вирусом не считаются.")
        text = Shell.cmd("grep -aoE '[[:print:]]{6,}' '$sp' 2>/dev/null | head -4000").exec().out
            .joinToString("\n")
        val upx = Shell.cmd("grep -ac 'UPX!' '$sp' 2>/dev/null").exec().out
            .firstOrNull()?.trim()?.toIntOrNull() ?: 0
        if (upx > 0) {
            notes.add("Файл упакован UPX: упаковщики часто используют, чтобы скрыть код от антивирусов.")
            obf += 4
        }
    } else {
        text = Shell.cmd("head -c 600000 '$sp' 2>/dev/null").exec().out.joinToString("\n")
    }
    if (text.isBlank()) return null
    return analyzeTextV2(sp, text, notes, obf, isElf)
}

suspend fun analyzeFile(path: String): Analysis? = withContext(Dispatchers.IO) {
    try {
        analyzeFileSync(path)
    } catch (e: Exception) {
        null
    }
}

fun findScriptFiles(deep: Boolean): List<String> {
    var roots = "/data/local/tmp /data/adb /data/media/0 /dev/shm /tmp /system/etc /system/bin /system/xbin /vendor/bin /vendor/etc /product/etc /data/data/com.termux/files/home"
    if (deep) roots += " /data/local /data/app /data/system /system /vendor /product /system_ext /data/data"
    val a = Shell.cmd(
        "find $roots -type f \\( -name '*.sh' -o -name '*.bash' -o -name '*.py' -o -name '*.pl' \\) -size -2048k 2>/dev/null | head -3000"
    ).exec().out
    val b = Shell.cmd(
        "find /data/local/tmp /dev/shm /tmp /data/adb /data/media/0 -type f -size -1024k -exec grep -lIE '^#!' {} + 2>/dev/null | head -500"
    ).exec().out
    val found = LinkedHashSet<String>()
    for (p in a + b) {
        val s = p.trim()
        if (s.isEmpty() || SKIP_PREFIX.any { s.startsWith(it) } || safePath(s) == null) continue
        found.add(s)
    }
    return found.toList()
}

suspend fun fullScriptScan(deep: Boolean, onStatus: (String) -> Unit): ScriptScan =
    withContext(Dispatchers.IO) {
        onStatus("Ищу скрипты...")
        val files = try {
            findScriptFiles(deep)
        } catch (e: Exception) {
            emptyList<String>()
        }
        val out = ArrayList<Analysis>()
        var n = 0
        for (f in files) {
            n++
            if (n % 15 == 0) onStatus("Разбираю скрипты: $n из ${files.size}")
            val a = try {
                analyzeFileSync(f)
            } catch (e: Exception) {
                null
            }
            if (a != null && a.level >= 0) out.add(a)
        }
        out.sortWith(compareByDescending<Analysis> { it.level }.thenByDescending { it.score })
        ScriptScan(files.size, out)
    }

// END
