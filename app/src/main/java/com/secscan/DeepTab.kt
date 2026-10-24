package com.secscan

import android.widget.Toast
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DeepState {
    var results by mutableStateOf(listOf<Analysis>())
    var total by mutableStateOf(0)
    var status by mutableStateOf("")
    var running by mutableStateOf(false)
    var path by mutableStateOf("")
    var deep by mutableStateOf(false)
    var weak by mutableStateOf(false)
}

suspend fun loadLayers(path: String): List<String> = withContext(Dispatchers.IO) {
    try {
        val sp = safePath(path) ?: return@withContext emptyList<String>()
        val magic = Shell.cmd("head -c 4 '$sp' 2>/dev/null | od -An -tx1").exec().out
            .joinToString(" ").trim()
        val raw = if (magic.startsWith("7f 45 4c 46")) {
            Shell.cmd("grep -aoE '[[:print:]]{6,}' '$sp' 2>/dev/null | head -4000").exec().out
                .joinToString("\n")
        } else {
            Shell.cmd("head -c 600000 '$sp' 2>/dev/null").exec().out.joinToString("\n")
        }
        if (raw.isBlank()) return@withContext emptyList<String>()
        val out = ArrayList<String>()
        out.add(raw.take(300000))
        var cur = raw
        val notes = ArrayList<String>()
        for (i in 1..6) {
            val parts = try {
                decodeOnce(cur, notes)
            } catch (e: Exception) {
                emptyList<String>()
            }
            if (parts.isEmpty()) break
            cur = parts.joinToString("\n")
            out.add(cur.take(300000))
        }
        out
    } catch (e: Exception) {
        emptyList<String>()
    }
}

fun prettify(t: String): String =
    t.replace("; ", ";\n").replace(" && ", " &&\n").replace(" | ", " |\n")

fun highlighted(text: String, limit: Int): AnnotatedString {
    val shown = if (text.length > limit) text.take(limit) else text
    return buildAnnotatedString {
        var n = 0
        for (line in shown.split("\n")) {
            n++
            val check = if (line.length > 600) line.take(600) else line
            val bad = n <= 600 && line.isNotBlank() && !line.trimStart().startsWith("#") &&
                RULES2.any { it.fam != F_OBF && it.re?.containsMatchIn(check) == true }
            if (bad) {
                withStyle(SpanStyle(color = Color(0xFFE53935), fontWeight = FontWeight.Bold)) { append(line) }
            } else {
                append(line)
            }
            append("\n")
        }
        if (text.length > limit) {
            append("\n… показано $limit из ${text.length} символов. Полный текст: кнопка «Сохранить в файл».")
        }
    }
}

@Composable
fun ReportDialog(a: Analysis, onCopy: (String) -> Unit, onClose: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var layers by remember(a.path) { mutableStateOf<List<String>?>(null) }
    var sel by remember(a.path) { mutableStateOf(0) }
    var fmt by remember(a.path) { mutableStateOf(false) }

    LaunchedEffect(a.path) { layers = loadLayers(a.path) }

    val raw: String = if (sel == 0) a.report else (layers?.getOrNull(sel - 1) ?: "")
    val full: String = if (fmt && sel > 0) prettify(raw) else raw
    val display: AnnotatedString = remember(full, sel) {
        if (sel == 0) AnnotatedString(full) else highlighted(full, 60000)
    }

    AlertDialog(
        onDismissRequest = onClose,
        confirmButton = { TextButton(onClick = onClose) { Text("Закрыть") } },
        title = { Text(a.title, fontSize = 15.sp) },
        text = {
            Column {
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    FilterChip(selected = sel == 0, onClick = { sel = 0 }, label = { Text("Отчёт") })
                    val ls = layers
                    if (ls == null) {
                        Spacer(Modifier.width(6.dp))
                        Text("  загрузка…", fontSize = 12.sp, color = Color.Gray)
                    } else {
                        ls.forEachIndexed { i, _ ->
                            Spacer(Modifier.width(6.dp))
                            FilterChip(
                                selected = sel == i + 1,
                                onClick = { sel = i + 1 },
                                label = { Text(if (i == 0) "Исходник" else "Слой $i") }
                            )
                        }
                    }
                }
                if (sel > 0) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(checked = fmt, onCheckedChange = { fmt = it })
                        Text("  Разбить по командам", fontSize = 12.sp)
                    }
                    Text(
                        "Красным выделены опасные строки. Последний слой это то, что скрипт реально выполнял бы.",
                        fontSize = 11.sp, color = Color.Gray
                    )
                }
                Column(
                    Modifier.heightIn(max = 340.dp).fillMaxWidth()
                        .verticalScroll(rememberScrollState()).padding(top = 6.dp)
                ) {
                    SelectionContainer {
                        Text(display, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                    }
                }
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    TextButton(onClick = { onCopy(full) }) { Text("Копировать", fontSize = 12.sp) }
                    TextButton(onClick = {
                        scope.launch {
                            val m = saveReport(ctx, full)
                            Toast.makeText(ctx, m, Toast.LENGTH_LONG).show()
                        }
                    }) { Text("Сохранить в файл", fontSize = 12.sp) }
                }
            }
        }
    )
}

@Composable
fun DeepTab(
    st: DeepState,
    trusted: Set<String>,
    onTrust: (String) -> Unit,
    onQuarantine: (String) -> Unit,
    onVt: (String) -> Unit,
    onCopy: (String) -> Unit,
    toast: (String) -> Unit
) {
    val scope = rememberCoroutineScope()
    var report by remember { mutableStateOf<Analysis?>(null) }
    val shown = st.results
        .filter { ("Разбор|" + it.title + "|" + it.path) !in trusted }
        .filter { st.weak || it.level >= 1 }
    val c2 = shown.count { it.level == 2 }
    val c1 = shown.count { it.level == 1 }
    val c0 = shown.count { it.level == 0 }

    LazyColumn {
        item {
            Column {
                Text(
                    "Полная проверка читает скрипты, расшифровывает спрятанное (base64, gzip, hex, ROT13) " +
                        "и называет тип угрозы. Файлы не запускаются.",
                    fontSize = 12.sp, color = Color.Gray, modifier = Modifier.padding(vertical = 6.dp)
                )
                Button(
                    onClick = {
                        if (!st.running) {
                            scope.launch {
                                st.running = true
                                st.status = "Запуск..."
                                val res = fullScriptScan(st.deep) { s -> st.status = s }
                                st.results = res.items
                                st.total = res.total
                                st.status = "Готово"
                                st.running = false
                            }
                        }
                    },
                    enabled = !st.running
                ) { Text(if (st.running) "Идёт разбор..." else "Полная проверка скриптов") }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = st.deep, onCheckedChange = { st.deep = it })
                    Text("  Искать по всей системе (долго)", fontSize = 12.sp)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = st.weak, onCheckedChange = { st.weak = it })
                    Text("  Показывать слабые признаки", fontSize = 12.sp)
                }
                if (st.status.isNotEmpty()) {
                    Text(st.status, fontSize = 12.sp, color = Color.Gray)
                }
                Text(
                    "Проверено файлов: ${st.total} | Критично: $c2 | Внимание: $c1 | Слабых: $c0",
                    fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp)
                )
                TextButton(onClick = {
                    val all = st.results.filter { it.level >= 1 }.flatMap { it.iocs }.distinct()
                    if (all.isEmpty()) {
                        toast("Адресов не найдено")
                    } else {
                        onCopy(all.joinToString("\n"))
                        toast("Скопировано адресов: ${all.size}")
                    }
                }) { Text("Копировать все адреса (IOC)", fontSize = 12.sp) }
                HorizontalDivider()
                OutlinedTextField(
                    value = st.path, onValueChange = { st.path = it },
                    label = { Text("Путь к файлу для разбора") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                )
                Button(onClick = {
                    val p = st.path.trim()
                    scope.launch {
                        val a = analyzeFile(p)
                        if (a == null) {
                            toast("Файл не прочитан. Проверьте путь (без пробелов)")
                        } else {
                            report = a
                        }
                    }
                }) { Text("Разобрать файл") }
                HorizontalDivider()
            }
        }
        items(shown) { a ->
            val color = when (a.level) {
                2 -> Color(0xFFE53935)
                1 -> Color(0xFFEF6C00)
                else -> Color.Gray
            }
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Text(a.title, color = color, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                Text(a.path, fontSize = 12.sp)
                Text(a.summary, fontSize = 11.sp, color = Color.Gray)
                Row(Modifier.horizontalScroll(rememberScrollState())) {
                    TextButton(onClick = { report = a }) { Text("Разобрать", fontSize = 12.sp) }
                    TextButton(onClick = {
                        onTrust("Разбор|" + a.title + "|" + a.path)
                    }) { Text("Доверять", fontSize = 12.sp) }
                    TextButton(onClick = { onVt(a.path) }) { Text("VirusTotal", fontSize = 12.sp) }
                    if (canQuarantine(a.path)) {
                        TextButton(onClick = { onQuarantine(a.path) }) { Text("В карантин", fontSize = 12.sp) }
                    }
                }
            }
            HorizontalDivider()
        }
    }

    report?.let { a ->
        ReportDialog(
            a,
            onCopy = { t ->
                onCopy(t)
                toast("Скопировано")
            },
            onClose = { report = null }
        )
    }
}

// END
