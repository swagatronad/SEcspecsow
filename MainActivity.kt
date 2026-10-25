package com.secscan

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        ThemeState.load(this)
        AppCtx.c = applicationContext
        setContent { SecTheme { App() } }
    }
}

@Composable
fun FindingCard(
    f: Finding, isNew: Boolean, onCopy: () -> Unit,
    actions: List<Pair<String, () -> Unit>>
) {
    val color = when (f.level) {
        2 -> Color(0xFFE53935)
        1 -> Color(0xFFEF6C00)
        else -> Color.Gray
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Column(Modifier.clickable { onCopy() }) {
            Text(
                (if (isNew) "НОВОЕ · " else "") + "[${f.category}] ${f.title}",
                color = color, fontSize = 13.sp, fontWeight = FontWeight.Bold
            )
            Text(f.path, fontSize = 12.sp)
            Text(f.detail, fontSize = 11.sp, color = Color.Gray)
        }
        Row(Modifier.horizontalScroll(rememberScrollState())) {
            for ((label, act) in actions) {
                TextButton(onClick = act) { Text(label, fontSize = 12.sp) }
            }
        }
    }
    HorizontalDivider()
}

@Composable
fun App() {
    val ctx = LocalContext.current
    val clip = LocalClipboardManager.current
    val prefs = remember { SecPrefs.open(ctx) }
    val scope = rememberCoroutineScope()
    val deepState = remember { DeepState() }

    var trusted by remember { mutableStateOf(prefs.getStringSet("trusted", emptySet<String>())!!.toSet()) }
    var baseline by remember { mutableStateOf(prefs.getStringSet("baseline", emptySet<String>())!!.toSet()) }
    var disabled by remember { mutableStateOf(prefs.getStringSet("disabled", emptySet<String>())!!.toSet()) }
    var vtKey by remember { mutableStateOf(prefs.getString("vtkey", "") ?: "") }
    var bg by remember { mutableStateOf(prefs.getBoolean("bg", false)) }

    var root by remember { mutableStateOf<Boolean?>(null) }
    var procs by remember { mutableStateOf(listOf<Proc>()) }
    var conns by remember { mutableStateOf(listOf<Conn>()) }
    var findings by remember { mutableStateOf(listOf<Finding>()) }
    var traffic by remember { mutableStateOf(listOf<Traffic>()) }
    var qItems by remember { mutableStateOf(listOf<QItem>()) }
    var status by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var tab by remember { mutableStateOf(0) }
    var hideKernel by remember { mutableStateOf(true) }
    var deep by remember { mutableStateOf(false) }
    var onlyNew by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var catFilter by remember { mutableStateOf<String?>(null) }
    var confirm by remember { mutableStateOf<Pair<String, () -> Unit>?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    var report by remember { mutableStateOf<Analysis?>(null) }

    val visible = findings
        .filter { it.key !in trusted }
        .filter { !onlyNew || baseline.isEmpty() || it.key !in baseline }
        .filter { catFilter == null || it.category == catFilter }
        .filter { query.isBlank() || (it.title + " " + it.path + " " + it.detail).contains(query, true) }
    val flagged = findings.filter { it.level >= 1 && it.key !in trusted }.mapNotNull { it.pid }.toSet()
    val c2 = visible.count { it.level == 2 }
    val c1 = visible.count { it.level == 1 }
    val c0 = visible.count { it.level == 0 }
    val extCount = conns.count { it.external }
    val categories = findings.map { it.category }.distinct()

    fun toast(s: String) {
        Toast.makeText(ctx, s, Toast.LENGTH_LONG).show()
    }

    fun loadQ() {
        scope.launch { qItems = withContext(Dispatchers.IO) { listQuarantine() } }
    }

    fun scan() {
        if (scanning) return
        scope.launch {
            scanning = true
            status = "Запуск проверки..."
            val res = runFullScan(ctx, deep) { s -> status = s }
            if (res == null) {
                root = false
                status = ""
            } else {
                root = true
                procs = res.procs
                conns = res.conns
                findings = res.findings
                traffic = res.traffic
                status = "Готово"
            }
            scanning = false
        }
    }

    fun trust(k: String) {
        trusted = trusted + k
        prefs.edit().putStringSet("trusted", trusted).apply()
    }

    fun ask(msg: String, f: () -> Unit) {
        confirm = Pair(msg, f)
    }

    fun act(block: suspend () -> String) {
        scope.launch {
            toast(block())
            loadQ()
            scan()
        }
    }

    fun doVt(target: String) {
        scope.launch {
            val h = sha256Of(target)
            if (h == null) {
                toast("Не удалось посчитать хеш")
                return@launch
            }
            clip.setText(AnnotatedString(h))
            if (vtKey.isBlank()) {
                toast("SHA-256 скопирован. Открываю VirusTotal")
                val i = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.virustotal.com/gui/file/$h"))
                i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(i)
            } else {
                toast("Проверяю в VirusTotal...")
                info = vtLookup(vtKey, h)
            }
        }
    }

    fun reportText(): String = visible.joinToString("\n\n") {
        "[" + levelName(it.level) + "][" + it.category + "] " + it.title + "\n" + it.path + "\n" + it.detail
    }

    LaunchedEffect(Unit) {
        scan()
        loadQ()
    }

    val tabs = listOf("Проверка", "Разбор", "Процессы", "Сеть", "Трафик", "Карантин", "Настройки")

    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.statusBarsPadding().navigationBarsPadding().padding(horizontal = 12.dp)) {
            Text(
                when (root) {
                    null -> "Проверяю root..."
                    true -> "Root: ЕСТЬ | процессов ${procs.size} | внешних соединений $extCount"
                    false -> "Root: НЕТ"
                },
                modifier = Modifier.padding(top = 8.dp), fontSize = 13.sp
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { scan() }, enabled = !scanning) {
                    Text(if (scanning) "Идёт проверка..." else "Проверить")
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = {
                    clip.setText(AnnotatedString(reportText()))
                    toast("Отчёт скопирован")
                }) { Text("Копировать отчёт") }
            }
            if (status.isNotEmpty()) Text(status, fontSize = 12.sp, color = Color.Gray)
            ScrollableTabRow(selectedTabIndex = tab, edgePadding = 0.dp) {
                tabs.forEachIndexed { i, t ->
                    Tab(selected = tab == i, onClick = { tab = i }, text = { Text(t, fontSize = 13.sp) })
                }
            }
            when (tab) {
                0 -> LazyColumn {
                    item {
                        Column {
                            OutlinedTextField(
                                value = query, onValueChange = { query = it },
                                label = { Text("Поиск по находкам") }, singleLine = true,
                                modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
                            )
                            Row(Modifier.horizontalScroll(rememberScrollState()).padding(vertical = 4.dp)) {
                                FilterChip(
                                    selected = catFilter == null, onClick = { catFilter = null },
                                    label = { Text("Все") }
                                )
                                for (cat in categories) {
                                    Spacer(Modifier.width(6.dp))
                                    FilterChip(
                                        selected = catFilter == cat, onClick = { catFilter = cat },
                                        label = { Text(cat) }
                                    )
                                }
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Switch(checked = deep, onCheckedChange = { deep = it })
                                Text("  Глубокий скан (медленно)", fontSize = 12.sp)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Switch(checked = onlyNew, onCheckedChange = { onlyNew = it })
                                Text("  Только новое", fontSize = 12.sp)
                            }
                            Row(Modifier.horizontalScroll(rememberScrollState())) {
                                TextButton(onClick = {
                                    baseline = findings.map { it.key }.toSet()
                                    prefs.edit().putStringSet("baseline", baseline).apply()
                                    toast("Текущее состояние запомнено как чистое")
                                }) { Text("Запомнить как чистое", fontSize = 12.sp) }
                                TextButton(onClick = {
                                    trusted = emptySet()
                                    baseline = emptySet()
                                    prefs.edit().remove("trusted").remove("baseline").remove("notified").apply()
                                }) { Text("Сбросить всё", fontSize = 12.sp) }
                            }
                            Text(
                                "Критично: $c2 | Внимание: $c1 | Инфо: $c0",
                                fontSize = 13.sp, modifier = Modifier.padding(vertical = 4.dp)
                            )
                            if (visible.isEmpty() && !scanning && status == "Готово") {
                                Text("Ничего подозрительного не найдено.")
                            }
                        }
                    }
                    items(visible) { f ->
                        val acts = ArrayList<Pair<String, () -> Unit>>()
                        fun add(label: String, run: () -> Unit) {
                            acts.add(Pair(label, run))
                        }
                        add("Доверять") { trust(f.key) }
                        val pid = f.pid
                        val vtTarget = if (pid != null && f.category == "Процессы") "/proc/$pid/exe" else f.path
                        val canVt = (f.category == "Процессы" || f.category == "Скрипты" || f.category == "Файлы") &&
                            safePath(vtTarget) != null
                        if (canVt) {
                            add("Разобрать") {
                                scope.launch {
                                    val a = analyzeFile(vtTarget)
                                    if (a == null) toast("Не удалось прочитать файл") else report = a
                                }
                            }
                            add("VirusTotal") { doVt(vtTarget) }
                        }
                        if ((f.category == "Файлы" || f.category == "Скрипты" || f.category == "Процессы") &&
                            canQuarantine(f.path)
                        ) {
                            add("В карантин") {
                                ask("Перенести файл в карантин?\n${f.path}\n\nОн не удаляется, его можно вернуть во вкладке «Карантин».") {
                                    act { quarantine(f.path) }
                                }
                            }
                        }
                        if (pid != null && pid > 1 && f.category == "Процессы") {
                            add("Остановить процесс") {
                                ask("Остановить процесс $pid?\n${f.path}") { act { killProc(pid) } }
                            }
                        }
                        if (f.category == "Приложения" && PKG_OK.matches(f.path)) {
                            add("Остановить") {
                                ask("Остановить приложение ${f.path}?") { act { forceStop(f.path) } }
                            }
                            add("Отключить") {
                                ask("Отключить ${f.path}? Оно перестанет работать. Включить можно во вкладке «Карантин».") {
                                    act {
                                        val m = disablePkg(f.path)
                                        disabled = disabled + f.path
                                        prefs.edit().putStringSet("disabled", disabled).apply()
                                        m
                                    }
                                }
                            }
                        }
                        FindingCard(
                            f,
                            isNew = baseline.isNotEmpty() && f.key !in baseline,
                            onCopy = { clip.setText(AnnotatedString(f.path)) },
                            actions = acts
                        )
                    }
                }
                1 -> DeepTab(
                    st = deepState,
                    trusted = trusted,
                    onTrust = { k -> trust(k) },
                    onQuarantine = { p ->
                        ask("Перенести файл в карантин?\n$p\n\nОн не удаляется, его можно вернуть во вкладке «Карантин».") {
                            scope.launch {
                                toast(quarantine(p))
                                loadQ()
                                deepState.results = deepState.results.filter { it.path != p }
                            }
                        }
                    },
                    onVt = { p -> doVt(p) },
                    onCopy = { t -> clip.setText(AnnotatedString(t)) },
                    toast = { m -> toast(m) }
                )
                2 -> Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(checked = hideKernel, onCheckedChange = { hideKernel = it })
                        Text("  Скрыть потоки ядра", fontSize = 13.sp)
                    }
                    val shown = if (hideKernel) procs.filter { !it.cmd.startsWith("[") } else procs
                    LazyColumn {
                        items(shown) { p ->
                            Text(
                                "${p.pid}  ${p.user}\n${p.cmd}",
                                fontSize = 11.sp,
                                color = if (p.pid in flagged) Color(0xFFE53935) else Color.Unspecified,
                                modifier = Modifier.padding(vertical = 3.dp)
                            )
                        }
                    }
                }
                3 -> LazyColumn {
                    items(conns) { c ->
                        Text(
                            "${c.proto} ${c.state}  ${c.name} (${c.pid ?: "?"})\n${c.local} → ${c.remote}",
                            fontSize = 11.sp,
                            color = if (c.external) Color(0xFFEF6C00) else Color.Unspecified,
                            modifier = Modifier.padding(vertical = 3.dp)
                        )
                    }
                }
                4 -> LazyColumn {
                    item {
                        Text(
                            if (traffic.isEmpty()) "Нет данных. Нажмите «Проверить» ещё раз."
                            else "Данные за последние 24 часа (Wi-Fi и мобильная сеть).",
                            fontSize = 12.sp, color = Color.Gray,
                            modifier = Modifier.padding(vertical = 6.dp)
                        )
                    }
                    items(traffic) { t ->
                        Text(
                            "${t.pkg}\n↑ отправлено ${fmtBytes(t.tx)}   ↓ получено ${fmtBytes(t.rx)}",
                            fontSize = 12.sp, modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                }
                5 -> LazyColumn {
                    item {
                        Text(
                            "Файлов в карантине: ${qItems.size}. Отключённых приложений: ${disabled.size}.",
                            fontSize = 13.sp, modifier = Modifier.padding(vertical = 6.dp)
                        )
                    }
                    items(qItems) { q ->
                        Column(Modifier.padding(vertical = 4.dp)) {
                            Text(q.path, fontSize = 12.sp)
                            Row {
                                TextButton(onClick = { act { restoreQ(q) } }) { Text("Вернуть", fontSize = 12.sp) }
                                TextButton(onClick = {
                                    ask("Удалить файл навсегда?\n${q.path}") { act { deleteQ(q) } }
                                }) { Text("Удалить навсегда", fontSize = 12.sp) }
                            }
                        }
                        HorizontalDivider()
                    }
                    items(disabled.toList()) { pkg ->
                        Column(Modifier.padding(vertical = 4.dp)) {
                            Text("Отключено: $pkg", fontSize = 12.sp)
                            TextButton(onClick = {
                                act {
                                    val m = enablePkg(pkg)
                                    disabled = disabled - pkg
                                    prefs.edit().putStringSet("disabled", disabled).apply()
                                    m
                                }
                            }) { Text("Включить", fontSize = 12.sp) }
                        }
                        HorizontalDivider()
                    }
                }
                else -> Column(Modifier.verticalScroll(rememberScrollState()).padding(top = 8.dp)) {
                    ThemeSettings()
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Switch(checked = bg, onCheckedChange = {
                            bg = it
                            prefs.edit().putBoolean("bg", it).apply()
                            scheduleScan(ctx, it)
                            if (it && baseline.isEmpty()) {
                                toast("Совет: нажмите «Запомнить как чистое» на вкладке «Проверка»")
                            }
                        })
                        Text("  Проверка раз в час с уведомлением", fontSize = 13.sp)
                    }
                    Text(
                        "Без «чистого» состояния уведомления приходят только о критичных находках. " +
                            "Если уведомления не приходят, отключите оптимизацию батареи для SecScan.",
                        fontSize = 11.sp, color = Color.Gray, modifier = Modifier.padding(vertical = 6.dp)
                    )
                    OutlinedTextField(
                        value = vtKey,
                        onValueChange = {
                            vtKey = it
                            prefs.edit().putString("vtkey", it.trim()).apply()
                        },
                        label = { Text("API-ключ VirusTotal (необязательно)") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        "Ключ бесплатный: virustotal.com → профиль → API key. " +
                            "В VirusTotal уходит только хеш файла, сам файл не загружается.",
                        fontSize = 11.sp, color = Color.Gray, modifier = Modifier.padding(vertical = 6.dp)
                    )
                    Button(onClick = {
                        scope.launch { toast(saveReport(ctx, reportText())) }
                    }) { Text("Сохранить отчёт в Download") }
                }
            }
        }
    }

    confirm?.let { (msg, run) ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            confirmButton = {
                TextButton(onClick = {
                    run()
                    confirm = null
                }) { Text("Да") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Отмена") } },
            title = { Text("Подтвердите") },
            text = { Text(msg) }
        )
    }

    info?.let { msg ->
        AlertDialog(
            onDismissRequest = { info = null },
            confirmButton = { TextButton(onClick = { info = null }) { Text("OK") } },
            title = { Text("Результат") },
            text = { Text(msg) }
        )
    }

    report?.let { a ->
        ReportDialog(
            a,
            onCopy = { t ->
                clip.setText(AnnotatedString(t))
                toast("Отчёт скопирован")
            },
            onClose = { report = null }
        )
    }
}

// END
