package com.secscan

import com.topjohnwu.superuser.Shell

fun isExtV4(b: List<Int>): Boolean =
    !(b[0] == 0 || b[0] == 10 || b[0] == 127 ||
        (b[0] == 192 && b[1] == 168) ||
        (b[0] == 169 && b[1] == 254) ||
        (b[0] == 172 && b[1] in 16..31))

fun hexAddr(s: String): Pair<String, Boolean> {
    try {
        val parts = s.split(":")
        val port = parts[1].toInt(16)
        val h = parts[0]
        val bytes: List<Int> = if (h.length == 8) {
            h.chunked(2).map { it.toInt(16) }.reversed()
        } else {
            h.chunked(8).flatMap { w -> w.chunked(2).map { it.toInt(16) }.reversed() }
        }
        if (bytes.size == 4) {
            return "${bytes.joinToString(".")}:$port" to isExtV4(bytes)
        }
        val mapped = bytes.take(10).all { it == 0 } && bytes[10] == 255 && bytes[11] == 255
        if (mapped) {
            val v4 = bytes.drop(12)
            return "${v4.joinToString(".")}:$port" to isExtV4(v4)
        }
        val allZero = bytes.all { it == 0 }
        val loop = bytes.take(15).all { it == 0 } && bytes[15] == 1
        val linkLocal = bytes[0] == 0xfe && (bytes[1] and 0xc0) == 0x80
        val ula = (bytes[0] and 0xfe) == 0xfc
        val ip = bytes.chunked(2).joinToString(":") { "%02x%02x".format(it[0], it[1]) }
        return "[$ip]:$port" to !(allZero || loop || linkLocal || ula)
    } catch (e: Exception) {
        return s to false
    }
}

fun loadAll(): Pair<List<Proc>, List<Conn>> {
    val psRe = Regex("""^\s*(\d+)\s+(\S+)\s+(.*)""")
    val ps = Shell.cmd("ps -A -o PID,USER,ARGS").exec().out
    val procs = ps.drop(1).mapNotNull { l ->
        psRe.find(l)?.let { Proc(it.groupValues[1].toInt(), it.groupValues[2], it.groupValues[3]) }
    }
    val names = procs.associate { it.pid to it.cmd }

    val inodeToPid = HashMap<String, Int>()
    var cur: Int? = null
    val fdLines = Shell.cmd("ls -l /proc/[0-9]*/fd 2>/dev/null | grep -E '^/proc|socket:'").exec().out
    for (l in fdLines) {
        if (l.startsWith("/proc/")) {
            cur = l.substringAfter("/proc/").substringBefore("/").toIntOrNull()
        } else if (l.contains("socket:[") && cur != null) {
            inodeToPid[l.substringAfter("socket:[").substringBefore("]")] = cur
        }
    }

    val conns = ArrayList<Conn>()
    val tcpStates = mapOf("01" to "ESTAB", "0A" to "LISTEN")
    for ((file, proto) in listOf("tcp" to "TCP", "tcp6" to "TCP6", "udp" to "UDP", "udp6" to "UDP6")) {
        val lines = Shell.cmd("cat /proc/net/$file").exec().out
        for (l in lines.drop(1)) {
            val t = l.trim().split(Regex("\\s+"))
            if (t.size < 10) continue
            val isTcp = file.startsWith("tcp")
            val state: String
            if (isTcp) {
                state = tcpStates[t[3]] ?: continue
            } else {
                if (t[2].endsWith(":0000")) continue
                state = "UDP"
            }
            val (local, _) = hexAddr(t[1])
            val (remote, ext) = hexAddr(t[2])
            val pid = inodeToPid[t[9]]
            val name = pid?.let { names[it]?.substringBefore(" ") } ?: "?"
            conns.add(Conn(proto, state, local, remote, pid, name, ext && state != "LISTEN"))
        }
    }
    conns.sortWith(compareByDescending<Conn> { it.external }.thenBy { it.name })
    return procs to conns
}

// END
