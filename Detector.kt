package com.secscan

const val F_TEST = "Тестовый файл EICAR"

val FAM_DESC2: Map<String, String> =
    FAM_DESC + (F_TEST to "безвредная стандартная строка, по которой проверяют антивирусы; сама опасности не несёт")

class Combo(val fam: String, val w: Int, pats: List<String>, val what: String) {
    val res: List<Regex> = pats.mapNotNull {
        try {
            Regex(it, RegexOption.IGNORE_CASE)
        } catch (e: Exception) {
            null
        }
    }
    val ok: Boolean = res.size == pats.size
}

private class HitE(val fam: String, val w: Int, val e: Double, val what: String, val line: String)

private fun rl(fam: String, w: Int, p: String, what: String, ci: Boolean = true) = Rule(fam, w, p, what, ci)

val SYS_PREFIX = listOf("/system/", "/vendor/", "/product/", "/system_ext/", "/odm/", "/apex/")

val RULES2: List<Rule> = listOf(
    rl(F_TEST, 12, """EICAR-STANDARD-ANTIVIRUS-TEST-FILE""", "Стандартная тестовая строка EICAR"),

    rl(F_RAT, 6, """/dev/tcp/""", "Подключение через /dev/tcp: так делают обратные оболочки"),
    rl(F_RAT, 3, """/dev/udp/""", "Передача данных через /dev/udp"),
    rl(F_RAT, 9, """(^|[\s;&|(])(nc|ncat|netcat)\s+.*\s-[a-z]*e\b""", "netcat запускает оболочку для удалённого входа (-e)"),
    rl(F_RAT, 9, """ncat\s+.*--(sh-exec|exec)""", "ncat запускает оболочку для удалённого входа"),
    rl(F_RAT, 3, """\bmkfifo\s""", "Именованный канал (mkfifo): часть обратной оболочки"),
    rl(F_RAT, 9, """(^|[\s;&|(])(ba|z|da)?sh\s+-i\s*>&""", "Интерактивная оболочка выведена в сокет: классическая обратная оболочка"),
    rl(F_RAT, 3, """(^|[\s;&|(])(ba|z|da)?sh\s+-i\b""", "Запуск интерактивной оболочки"),
    rl(F_RAT, 8, """socat\s+.*(exec|system|pty)""", "socat связывает сеть с оболочкой"),
    rl(F_RAT, 6, """pty\.spawn""", "Python запускает оболочку через pty"),
    rl(F_RAT, 4, """os\.dup2\(""", "Python перенаправляет ввод и вывод (часто в сокет)"),
    rl(F_RAT, 4, """ssh\s+.*\s-R\s""", "Обратный SSH-туннель"),
    rl(F_RAT, 2, """ngrok|cloudflared|serveo\.net|localtunnel""", "Туннель во внешнюю сеть"),
    rl(F_RAT, 4, """api\.telegram\.org/bot""", "Связь с Telegram-ботом"),
    rl(F_RAT, 6, """(^|[\s;&|(])(busybox\s+)?telnetd\b""", "Запуск telnet-сервера: удалённый вход в телефон"),
    rl(F_RAT, 7, """setprop\s+(service|persist)\.adb\.tcp\.port|\btcpip\s+\d{3,5}""", "Включение отладки ADB по сети"),
    rl(F_RAT, 2, """adb\s+connect\s""", "Подключение к устройству по ADB"),
    rl(F_RAT, 3, """(dropbear|sshd)\b.*(\s-p\s|start)""", "Запуск SSH-сервера на телефоне"),

    rl(F_SPY, 3, """\bscreenrecord\b""", "Запись видео с экрана"),
    rl(F_SPY, 3, """\bscreencap\b""", "Снимки экрана"),
    rl(F_SPY, 5, """\b(arecord|tinycap|termux-microphone-record)\b""", "Запись звука с микрофона"),
    rl(F_SPY, 5, """termux-camera-photo|am\s+start.*(IMAGE_CAPTURE|VIDEO_CAPTURE|STILL_IMAGE_CAMERA)""", "Съёмка на камеру"),
    rl(F_SPY, 3, """termux-location|dumpsys\s+location""", "Определение местоположения"),
    rl(F_SPY, 6, """termux-(sms-list|sms-send|call-log|contact-list|clipboard-get)""", "Доступ к SMS, звонкам, контактам или буферу обмена"),
    rl(F_SPY, 7, """content\s+query\s+.*content://(sms|mms|call_log|com\.android\.contacts)""", "Чтение SMS, звонков или контактов из базы"),
    rl(F_SPY, 3, """\bgetevent\b|/dev/input/event""", "Чтение нажатий и касаний"),
    rl(F_SPY, 4, """logcat\s+.*(password|passwd|otp|token)""", "Поиск паролей и кодов в системном журнале"),
    rl(F_SPY, 3, """uiautomator\s+dump""", "Чтение содержимого экрана"),
    rl(F_SPY, 1, """\binput\s+(text|tap|swipe|keyevent)\b""", "Эмуляция нажатий и ввода"),

    rl(F_LOCK, 8, """lock_?settings\s+(set-pin|set-password|set-pattern|clear)""", "Смена или сброс блокировки экрана"),
    rl(F_LOCK, 5, """openssl\s+(enc|aes)\b.*(-aes|-des|-chacha|-camellia|-e\b)""", "Шифрование файлов через openssl"),
    rl(F_LOCK, 4, """gpg\s+.*(--symmetric|--encrypt|\s-c\s|\s-e\s)""", "Шифрование файлов через gpg"),
    rl(F_LOCK, 8, """find\s+.*(/sdcard|/storage|/data/media).*-exec\s+.*(openssl|gpg|mv|rm|shred)""", "Массовая обработка файлов накопителя (шифрование, удаление)"),
    rl(F_LOCK, 2, """\.(locked|encrypted|crypted|crypt|enc|ransom|wncry|lockbit)\b""", "Расширения зашифрованных вымогателем файлов"),
    rl(F_LOCK, 4, """ransom|bitcoin|decrypt\s+your|your\s+files\s+(have|are)|выкуп|ваши\s+файлы|зашифрован|биткоин|биткойн""", "Текст с требованием выкупа"),
    rl(F_LOCK, 8, """pm\s+(disable|disable-user|hide)\s+.*(systemui|launcher|com\.android\.settings)""", "Отключение интерфейса или настроек: так блокируют телефон"),
    rl(F_LOCK, 3, """\bshred\s""", "Безвозвратное затирание файлов"),
    rl(F_LOCK, 2, """settings\s+put\s+global\s+(adb_enabled|development_settings_enabled)\s+0""", "Отключение отладки"),

    rl(F_WIPE, 7, """rm\s+-[a-z]+\s+(/sdcard|/storage/emulated|/data/media|/system|/vendor|/data)(\s|/\*|/?$)""", "Массовое удаление данных (rm -rf)"),
    rl(F_WIPE, 6, """\bdd\s+.*if=/dev/(zero|urandom|random).*of=""", "Затирание данных через dd"),
    rl(F_WIPE, 9, """\bdd\s+.*of=/dev/(block|mmcblk|sd)""", "Запись прямо в раздел памяти телефона"),
    rl(F_WIPE, 6, """\bmkfs(\.|\s)""", "Форматирование раздела"),
    rl(F_WIPE, 7, """blkdiscard|fastboot\s+erase|flash_erase""", "Стирание разделов памяти"),

    rl(F_DROP, 7, """(curl|wget)\s[^|;&]*\|\s*(ba|z|da)?sh\b""", "Скачивание кода и немедленный запуск (curl | sh)"),
    rl(F_DROP, 7, """(sh|bash|source|\.)\s+<\(\s*(curl|wget)""", "Запуск кода, скачанного из интернета"),
    rl(F_DROP, 5, """(curl|wget)\s.*(-o|-O|--output|>)\s*(/data/local/tmp|/dev/shm|/tmp|/sdcard|/data/data)""", "Скачивание файла в папку, откуда его можно запустить"),
    rl(F_DROP, 3, """chmod\s+(\+x|[0-7]{3,4})\s+.*(/data/local/tmp|/dev/shm|/tmp/|/sdcard)""", "Право запуска файлу во временной папке"),
    rl(F_DROP, 4, """\bpm\s+install\b""", "Тихая установка приложения"),
    rl(F_DROP, 3, """\b(tftp|ftpget)\s""", "Загрузка файла по tftp или ftp"),
    rl(F_DROP, 6, """(base64\s+(-d|--decode)|xxd\s+-r(\s+-p)?|openssl\s+enc\s+-d)[^|]*\|\s*(ba|z|da)?sh\b""", "Раскодирование данных и немедленный запуск"),

    rl(F_MINE, 9, """xmrig|minerd|cpuminer|ccminer|cgminer|nanominer|ethminer|lolminer|nbminer""", "Программа-майнер криптовалюты"),
    rl(F_MINE, 9, """stratum\+(tcp|ssl|tls)://""", "Подключение к майнинг-пулу (stratum)"),
    rl(F_MINE, 8, """(nanopool|supportxmr|minexmr|2miners|hashvault|moneroocean|f2pool|ethermine|nicehash|unmineable)\.""", "Адрес известного майнинг-пула"),
    rl(F_MINE, 6, """--donate-level|--coin\s|randomx|cryptonight""", "Параметры майнера"),
    rl(F_MINE, 6, """\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b""", "Адрес кошелька Monero", false),

    rl(F_BOT, 5, """\bhping3?\b|\bping\s+.*\s-f\b|\bping\s+.*-s\s*[0-9]{5}""", "Флуд-атака на чужой адрес"),
    rl(F_BOT, 7, """slowloris|goldeneye|ufonet""", "Инструмент DDoS-атак"),
    rl(F_BOT, 3, """\b(masscan|zmap|zgrab|nmap)\s""", "Сканирование чужих сетей"),
    rl(F_BOT, 3, """while\s+(true|:|\[\s*1\s*\]).*(curl|wget|\bnc\b|ping)""", "Бесконечный цикл сетевых запросов"),

    rl(F_EXF, 5, """(curl|wget)\s.*(\s-F\s|--form|--upload-file|\s-T\s|--data-binary\s+@|-d\s+@)""", "Отправка файла на внешний сервер"),
    rl(F_EXF, 6, """api\.telegram\.org/bot[^/\s]*/send(Document|Photo|Video|Audio|Message)""", "Отправка данных через Telegram-бота"),
    rl(F_EXF, 6, """discord(app)?\.com/api/webhooks""", "Отправка данных через Discord-вебхук"),
    rl(F_EXF, 3, """pastebin\.com|transfer\.sh|file\.io|anonfiles|gofile\.io|0x0\.st|webhook\.site|requestbin""", "Файлообменник или приёмник данных"),
    rl(F_EXF, 3, """\b(scp|rsync)\s+.*@""", "Копирование файлов на удалённый сервер"),
    rl(F_EXF, 4, """\btar\s+.*(/data/data|DCIM|WhatsApp|Telegram)""", "Архивация личных данных"),
    rl(F_EXF, 8, """(cat|cp|tar)\s+.*(/data/system/(users|gatekeeper|locksettings|gesture|password)|wpa_supplicant\.conf|WifiConfigStore\.xml)""", "Кража паролей Wi-Fi или данных блокировки экрана"),
    rl(F_EXF, 8, """sqlite3\s+.*(mmssms|contacts2|calllog|Cookies|Login\s*Data|msgstore)""", "Чтение баз SMS, контактов, паролей или мессенджеров"),

    rl(F_PRIV, 4, """setenforce\s+0""", "Отключение защиты SELinux"),
    rl(F_PRIV, 7, """settings\s+put\s+secure\s+enabled_accessibility_services""", "Тихое включение службы спецвозможностей"),
    rl(F_PRIV, 4, """settings\s+put\s+secure\s+enabled_notification_listeners""", "Тихая выдача доступа к уведомлениям"),
    rl(F_PRIV, 7, """dpm\s+(set-device-owner|set-active-admin)""", "Назначение администратора устройства"),
    rl(F_PRIV, 5, """pm\s+grant\s+\S+\s+android\.permission\.(RECORD_AUDIO|CAMERA|READ_SMS|SEND_SMS|READ_CONTACTS|READ_CALL_LOG|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|SYSTEM_ALERT_WINDOW|WRITE_SECURE_SETTINGS|READ_LOGS)""", "Скрытая выдача опасных разрешений"),
    rl(F_PRIV, 2, """appops\s+set\s+\S+\s+\S+\s+allow""", "Выдача разрешений через appops"),
    rl(F_PRIV, 8, """magisk\s+--sqlite|INSERT\s+(OR\s+REPLACE\s+)?INTO\s+policies""", "Выдача root-прав приложению через базу Magisk"),
    rl(F_PRIV, 1, """\bsu\s+(-c|-|0|root)\b""", "Запуск команд от root"),
    rl(F_PRIV, 3, """mount\s+.*remount.*\s/(system|vendor|product)|mount\s+-o\s+rw,?remount""", "Перемонтирование системного раздела на запись"),
    rl(F_PRIV, 2, """/data/adb/(service|post-fs-data)\.d|/system/etc/init\.d|\bcrontab\b|\bcrond\b""", "Закрепление: запуск при загрузке или по расписанию"),
    rl(F_PRIV, 3, """>>\s*\S*(\.bashrc|\.profile|\.zshrc|\.bash_profile)""", "Автозапуск через профиль оболочки"),
    rl(F_PRIV, 2, """BOOT_COMPLETED""", "Запуск после загрузки телефона"),
    rl(F_PRIV, 9, """pm\s+(hide|disable-user|disable)\s+.*(kaspersky|avast|drweb|eset|mcafee|malwarebytes|bitdefender|lookout|norton|sophos|avira|antivirus)""", "Отключение антивируса"),
    rl(F_PRIV, 2, """pm\s+(hide|disable-user)\b""", "Скрытие или отключение приложений"),
    rl(F_PRIV, 1, """\bresetprop\s""", "Изменение системных свойств"),
    rl(F_PRIV, 3, """chmod\s+(-R\s+)?[0-7]*777\s+/(data|system)""", "Права 777 на системные папки"),

    rl(F_HIDE, 4, """history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0""", "Очистка истории команд"),
    rl(F_HIDE, 2, """logcat\s+-c""", "Очистка системного журнала"),
    rl(F_HIDE, 5, """rm\s+(-[a-z]+\s+)?("?\$0"?|"?\$\{0\}"?|"?\$\{?BASH_SOURCE)""", "Самоудаление скрипта"),
    rl(F_HIDE, 2, """\btouch\s+-(r|d|t)\s""", "Подмена времени изменения файлов"),
    rl(F_HIDE, 5, """\bexec\s+-a\s""", "Подмена имени процесса"),
    rl(F_HIDE, 8, """mount\s+(--bind|-o\s+bind)\s+\S+\s+/proc/""", "Скрытие процесса через mount --bind"),
    rl(F_HIDE, 3, """chattr\s+\+i""", "Защита файла от удаления"),
    rl(F_HIDE, 1, """\b(nohup|setsid)\s.*&""", "Фоновый запуск, отвязанный от сессии"),
    rl(F_HIDE, 2, """iptables\s+-[IAD]\s.*(DROP|REJECT)""", "Блокировка трафика правилами iptables"),

    rl(F_OBF, 3, """base64\s+(-d|--decode)\b""", "Декодирование спрятанных данных (base64)"),
    rl(F_OBF, 2, """\beval\b""", "Выполнение собранного на лету кода (eval)"),
    rl(F_OBF, 3, """xxd\s+-r""", "Декодирование hex-данных"),
    rl(F_OBF, 3, """\|\s*rev\b""", "Разворот строки наоборот"),
    rl(F_OBF, 4, """tr\s+['"]?A-Za-z['"]?\s+['"]?N-ZA-Mn-za-m""", "Шифр ROT13"),
    rl(F_OBF, 4, """openssl\s+enc\s+-d""", "Расшифровка данных через openssl"),
    rl(F_OBF, 2, """\b(gunzip|zcat|unxz)\b|gzip\s+-d""", "Распаковка спрятанных данных"),
    rl(F_OBF, 3, """printf\s+['"]?(\\x|\\[0-7]{3})""", "Сборка команд из кодов символов"),
    rl(F_OBF, 3, """\$'\\x""", "Строки из hex-кодов")
)

val COMBOS: List<Combo> = listOf(
    Combo(F_RAT, 10, listOf("""/dev/tcp/""", """0>&1|0<&\d+|exec\s+\d+<>|>&\s*/dev/tcp|\|\s*(ba|z|da)?sh\b"""),
        "Обратная оболочка bash: телефон подключается к серверу и отдаёт ему управление"),
    Combo(F_RAT, 10, listOf("""socket""", """\.connect\s*\(""", """dup2|pty\.spawn"""),
        "Скрипт подключается к серверу и отдаёт ему оболочку (обратная оболочка)"),
    Combo(F_RAT, 9, listOf("""socket""", """\.connect\s*\(""", """subprocess|Popen|os\.system|os\.popen""", """/bin/(ba|z|da)?sh|["']sh["']|["']cmd(\.exe)?["']"""),
        "Скрипт подключается к серверу и запускает оболочку"),
    Combo(F_RAT, 7, listOf("""socket""", """\.recv(from)?\s*\(""", """os\.system|subprocess|os\.popen|Popen|\bexec\s*\(|\beval\s*\("""),
        "Скрипт принимает команды по сети и выполняет их"),
    Combo(F_RAT, 9, listOf("""fsockopen|stream_socket_client""", """(shell_exec|system|passthru|proc_open|popen|exec)\s*\("""),
        "PHP открывает сокет и запускает команды (обратная оболочка)"),
    Combo(F_RAT, 9, listOf("""require\(['"]net['"]\)|net\.Socket""", """child_process|spawn\(""", """\.connect\("""),
        "Node.js подключается к серверу и запускает оболочку"),
    Combo(F_RAT, 9, listOf("""TCPSocket""", """exec|spawn|system|popen"""),
        "Ruby открывает сокет и запускает команды"),
    Combo(F_RAT, 9, listOf("""use\s+Socket|IO::Socket""", """exec\s*\(?\s*['"]?/bin/(ba)?sh|system\s*\(?\s*['"]?/bin/(ba)?sh|open\s*\(\s*STDIN"""),
        "Perl открывает сокет и запускает оболочку"),
    Combo(F_RAT, 9, listOf("""java\.net\.Socket""", """Runtime\.getRuntime\(\)\.exec|ProcessBuilder"""),
        "Java открывает сокет и запускает команды"),
    Combo(F_RAT, 9, listOf("""mkfifo""", """\b(nc|ncat|netcat|telnet)\b""", """\b(ba|z|da)?sh\b"""),
        "Обратная оболочка через именованный канал и netcat"),

    Combo(F_DROP, 7, listOf("""(curl|wget)\s""", """chmod\s+(\+x|[0-7]{3,4})\s""", """/data/local/tmp|/dev/shm|/tmp/|/sdcard"""),
        "Скачивает файл и выдаёт ему право запуска во временной папке"),

    Combo(F_LOCK, 9, listOf("""openssl\s+enc|\bgpg\b|\baes\b|7z\s+a\s.*-p|zip\s+.*-P""", """/sdcard|/storage/emulated|/data/media|DCIM""",
        """\brm\s|\bshred\b|\bmv\s|\.locked|\.enc\b|\.crypt""", """find\s|for\s+\w+\s+in|while\s+read|xargs"""),
        "Массово шифрует файлы накопителя и удаляет или переименовывает оригиналы: поведение вымогателя"),
    Combo(F_LOCK, 8, listOf("""ransom|bitcoin|btc\b|биткоин|биткойн|выкуп|monero|usdt""", """encrypt|decrypt|зашифр|расшифр|your files|ваши файлы|ваш телефон|your phone"""),
        "Требование выкупа за файлы или телефон"),
    Combo(F_LOCK, 10, listOf("""lock_?settings\s+(set-pin|set-password|set-pattern)""", """ransom|bitcoin|btc\b|выкуп|биткоин|оплат"""),
        "Блокировка экрана с требованием оплаты: вымогатель-локер"),

    Combo(F_SPY, 8, listOf("""arecord|tinycap|screenrecord|screencap|camera-photo|microphone-record|content\s+query\s+.*(sms|call_log|contacts)|sqlite3\s+.*(mmssms|contacts2|calllog)""",
        """curl|wget|\bnc\b|\bscp\b|api\.telegram\.org|discord(app)?\.com/api/webhooks|\bftp"""),
        "Собирает данные (звук, экран, SMS, контакты) и отправляет наружу"),

    Combo(F_PRIV, 8, listOf("""/data/adb/service\.d|/system/etc/init\.d|crontab|BOOT_COMPLETED|post-fs-data\.d""",
        """/dev/tcp/|\bnc\b.*\s-[a-z]*e\b|(curl|wget)[^|]*\|\s*(ba|z|da)?sh|stratum\+"""),
        "Закрепляется в автозапуске и открывает сетевой канал"),
    Combo(F_PRIV, 8, listOf("""enabled_accessibility_services""", """settings\s+put|pm\s+grant""", """input\s+(tap|text|swipe)|uiautomator|screencap|am\s+start"""),
        "Тихо включает спецвозможности и управляет экраном: приём банковских троянов")
)

fun analyzeTextV2(path: String, raw: String, notes0: List<String>, obf0: Int, isElf: Boolean): Analysis {
    val notes = ArrayList<String>(notes0)
    val all = StringBuilder(raw)
    var cur = raw
    var layers = 0
    for (i in 1..6) {
        val parts = try {
            decodeOnce(cur, notes)
        } catch (e: Exception) {
            emptyList<String>()
        }
        if (parts.isEmpty()) break
        cur = parts.joinToString("\n")
        all.append("\n\n# ===== слой ").append(i).append(" =====\n").append(cur)
        layers++
        if (all.length > 3_000_000) break
    }

    val sys = SYS_PREFIX.any { path.startsWith(it) }
    val magisk = path.startsWith("/data/adb/modules") || path.startsWith("/data/adb/service.d") ||
        path.startsWith("/data/adb/post-fs-data.d")
    val termux = path.startsWith("/data/data/com.termux/") || path.startsWith("/data/user/0/com.termux/")
    val risky = BAD_PREFIX.any { path.startsWith(it) }
    val locF = when {
        sys -> 0.3
        magisk -> 0.6
        termux -> 0.7
        risky -> 1.1
        else -> 1.0
    }
    val locName = when {
        sys -> "системная папка (слабые признаки ×0.3)"
        magisk -> "модуль или автозапуск Magisk (слабые признаки ×0.6)"
        termux -> "Termux (слабые признаки ×0.7)"
        risky -> "папка, откуда обычно запускают вредоносное (×1.1)"
        else -> "обычная папка"
    }

    fun eff(w: Int): Double {
        var f = locF
        if (isElf && w < 9) f *= 0.6
        return if (f < 1.0 && w >= 9) w.toDouble() else minOf(12.0, w * f)
    }

    val hs = ArrayList<HitE>()
    val used = BooleanArray(RULES2.size)
    var usedCount = 0
    var lineNo = 0
    for (line0 in all.lineSequence()) {
        lineNo++
        if (lineNo > 30000) break
        val t = line0.trim()
        if (t.isEmpty() || t.startsWith("#")) continue
        val line = if (t.length > 3000) t.substring(0, 3000) else t
        for (idx in RULES2.indices) {
            if (used[idx]) continue
            val rule = RULES2[idx]
            val re = rule.re ?: continue
            if (re.containsMatchIn(line)) {
                used[idx] = true
                usedCount++
                hs.add(HitE(rule.fam, rule.w, eff(rule.w), rule.what, line.cut(140)))
            }
        }
        if (usedCount == RULES2.size) break
    }

    if (!isElf) {
        val txt = if (all.length > 1_000_000) all.substring(0, 1_000_000) else all.toString()
        for (c in COMBOS) {
            if (!c.ok) continue
            if (c.res.all { it.containsMatchIn(txt) }) {
                hs.add(HitE(c.fam, c.w, eff(c.w), c.what, "(сочетание признаков в файле)"))
            }
        }
    }

    val core = hs.filter { it.fam != F_OBF }
    var obfPts = obf0 + hs.filter { it.fam == F_OBF }.sumOf { it.w }
    if (raw.lineSequence().any { it.length > 2000 }) {
        obfPts += 2
        notes.add("Есть очень длинные строки (больше 2000 символов): так обычно прячут закодированные данные.")
    }
    if (layers > 0) {
        notes.add(0, "Содержимое спрятано в несколько слоёв кодирования (слоёв: $layers) и расшифровано автоматически. Прятать код характерно для вредоносных программ.")
    }

    val famScore = HashMap<String, Double>()
    for ((fam, list) in core.groupBy { it.fam }) {
        val ws = list.map { it.e }.sortedDescending()
        var s = ws[0]
        if (ws.size > 1) s += 0.3 * ws[1]
        if (ws.size > 2) s += 0.1 * ws.drop(2).sum()
        famScore[fam] = minOf(12.0, s)
    }
    val ranked = famScore.entries.sortedByDescending { it.value }
    val topFam: String? = ranked.firstOrNull()?.key
    val topScore = ranked.firstOrNull()?.value ?: 0.0
    val second = ranked.getOrNull(1)?.takeIf { it.value >= 5.0 }
    val iocs = extractIocs(all.toString())

    var risk = topScore + (if (second != null) 0.25 * second.value else 0.0)
    if (topScore >= 4.0) {
        risk += minOf(obfPts * 0.5, 2.0) + minOf(layers * 1.0, 2.0)
        if (iocs.isNotEmpty() && topScore >= 5.0) risk += 0.5
    }
    risk = minOf(10.0, risk)

    val strong = core.any { it.e >= 6.5 } || famScore.values.count { it >= 5.0 } >= 2
    val medium = core.any { it.w >= 5 }
    val kind = if (topFam == null) "" else if (second != null) "$topFam + ${second.key}" else topFam
    val hiddenOnly = (obfPts >= 4 && layers > 0) || layers >= 2

    val level: Int
    val title: String
    when {
        topFam == F_TEST -> {
            level = 2
            title = "ТЕСТОВЫЙ ВИРУС — EICAR (безвредный образец для проверки антивирусов)"
        }
          risk >= 8.0 && strong -> {
            level = 2
            title = "ВРЕДОНОСНЫЙ — $kind"
        }
        risk >= 5.0 && medium -> {
            level = 1
            title = "ПОДОЗРИТЕЛЬНЫЙ — $kind"
        }
        risk >= 1.0 -> {
            level = 0
            title = "Слабые признаки — $kind"
        }
        hiddenOnly -> {
            level = 1
            title = "ПОДОЗРИТЕЛЬНЫЙ — содержимое спрятано (обфускация)"
        }
        else -> {
            level = -1
            title = "Явных признаков не найдено"
        }
    }

    val shownRisk = when (level) {
        2 -> maxOf(risk, 8.0)
        1 -> risk.coerceIn(5.0, 7.9)
        0 -> minOf(risk, 4.9)
        else -> 0.0
    }
    val score = shownRisk.toInt()

    val explain = StringBuilder()
    if (topFam == F_TEST) {
        explain.append("Это стандартный тестовый файл EICAR. Он безвреден: его придумали, чтобы проверять антивирусы. Раз вы это видите, детектор работает.")
    } else if (topFam != null && level >= 0) {
        explain.append("Больше всего похоже на: ").append(topFam)
            .append(". Это программа, которая ").append(FAM_DESC2[topFam] ?: "").append(".")
        if (second != null) {
            explain.append("\nТакже есть признаки: ").append(second.key)
                .append(" — программа, которая ").append(FAM_DESC2[second.key] ?: "").append(".")
        }
        if (level == 2) {
            explain.append("\nРекомендация: не запускайте файл, выясните, откуда он взялся, и перенесите в карантин.")
        } else {
            explain.append("\nЭто эвристика, возможны ложные срабатывания. Если файл ваш или из знакомого модуля, нажмите «Доверять».")
        }
    } else if (level >= 1) {
        explain.append("Содержимое специально спрятано, но известных вредных действий после расшифровки не найдено. Если вы файл не создавали, проверьте вручную.")
    }

    val ev = core.sortedByDescending { it.e }.take(3).joinToString("; ") { it.what }
    val summary = "Оценка $score/10." +
        (if (ev.isNotEmpty()) " $ev." else "") +
        (if (iocs.isNotEmpty()) " Адреса: " + iocs.take(3).joinToString(", ") + "." else "") +
        (if (layers > 0) " Расшифровано слоёв: $layers." else "")

    val sb = StringBuilder()
    sb.append("ФАЙЛ: ").append(path).append('\n')
    sb.append("ВЕРДИКТ: ").append(title).append('\n')
    sb.append("ОЦЕНКА: ").append(score).append("/10  (8–10 вредоносный, 5–7 подозрительный, ниже 5 слабые признаки)\n\n")
    if (explain.isNotEmpty()) sb.append("ЧТО ЭТО:\n").append(explain).append("\n\n")
    if (core.isNotEmpty()) {
        sb.append("ЧТО НАЙДЕНО:\n")
        for (h in core.sortedByDescending { it.e }) {
            sb.append("• [").append(h.fam).append("] ").append(h.what)
                .append(" (вес ").append("%.1f".format(h.e)).append(")\n   ").append(h.line).append('\n')
        }
        sb.append('\n')
    }
    sb.append("КАК СЧИТАЛОСЬ:\nРасположение: ").append(locName).append('\n')
    for ((f, v) in ranked) sb.append("• ").append(f).append(": ").append("%.1f".format(v)).append('\n')
    sb.append("Итог по формуле: ").append("%.1f".format(risk)).append("\n\n")
    if (iocs.isNotEmpty()) {
        sb.append("АДРЕСА И ССЫЛКИ (куда обращается скрипт):\n")
        for (i in iocs) sb.append("• ").append(i).append('\n')
        sb.append('\n')
    }
    if (notes.isNotEmpty()) {
        sb.append("ЗАМЕТКИ:\n")
        for (n in notes) sb.append("• ").append(n).append('\n')
        sb.append('\n')
    }
    sb.append("ИСХОДНЫЙ ТЕКСТ (начало):\n").append(raw.take(1200)).append("\n\n")
    if (layers > 0) {
        sb.append("ПОСЛЕ РАСШИФРОВКИ (слои):\n").append(all.substring(raw.length).take(3500))
    }

    val hitsOut = core.map { Hit(it.fam, Math.round(it.e).toInt(), it.what, it.line) }
    return Analysis(path, level, title, score, hitsOut, iocs, layers, summary, sb.toString())
}

// END
