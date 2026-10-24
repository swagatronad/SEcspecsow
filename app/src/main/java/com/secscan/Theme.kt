package com.secscan

import android.app.Activity
import android.content.Context
import android.os.Build
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat

object ThemeState {
    var dyn by mutableStateOf(true)
    var mode by mutableStateOf(0)
    var amoled by mutableStateOf(false)
    private var loaded = false

    fun load(ctx: Context) {
        if (loaded) return
        loaded = true
        val p = ctx.getSharedPreferences("secscan", Context.MODE_PRIVATE)
        dyn = p.getBoolean("dyn", true)
        mode = p.getInt("mode", 0)
        amoled = p.getBoolean("amoled", false)
    }

    fun save(ctx: Context) {
        ctx.getSharedPreferences("secscan", Context.MODE_PRIVATE).edit()
            .putBoolean("dyn", dyn)
            .putInt("mode", mode)
            .putBoolean("amoled", amoled)
            .apply()
    }
}

@Composable
fun SecTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val sysDark = isSystemInDarkTheme()
    val dark = when (ThemeState.mode) {
        1 -> false
        2 -> true
        else -> sysDark
    }
    val canDyn = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    var scheme = when {
        ThemeState.dyn && canDyn ->
            if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme(
            primary = Color(0xFF3FD0BF),
            secondary = Color(0xFF6EF7D3),
            background = Color(0xFF121821),
            surface = Color(0xFF121821)
        )
        else -> lightColorScheme(
            primary = Color(0xFF1E8E80),
            secondary = Color(0xFF2A9D8F)
        )
    }
    if (dark && ThemeState.amoled) {
        scheme = scheme.copy(background = Color.Black, surface = Color.Black)
    }
    val view = LocalView.current
    SideEffect {
        val act = view.context as? Activity
        if (act != null) {
            val w = act.window
            w.decorView.setBackgroundColor(scheme.background.toArgb())
            val c = WindowCompat.getInsetsController(w, view)
            c.isAppearanceLightStatusBars = !dark
            c.isAppearanceLightNavigationBars = !dark
        }
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

@Composable
fun ThemeSettings() {
    val ctx = LocalContext.current
    val canDyn = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    val modes = listOf("Как в системе", "Светлая", "Тёмная")
    Column(Modifier.padding(bottom = 8.dp)) {
        Text("Оформление", fontSize = 14.sp, fontWeight = FontWeight.Bold)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(
                checked = ThemeState.dyn && canDyn,
                enabled = canDyn,
                onCheckedChange = {
                    ThemeState.dyn = it
                    ThemeState.save(ctx)
                }
            )
            Text("  Material You (цвета из обоев)", fontSize = 13.sp)
        }
        if (!canDyn) {
            Text("Material You работает на Android 12 и новее.", fontSize = 11.sp, color = Color.Gray)
        }
        Row(Modifier.horizontalScroll(rememberScrollState()).padding(vertical = 4.dp)) {
            modes.forEachIndexed { i, t ->
                FilterChip(
                    selected = ThemeState.mode == i,
                    onClick = {
                        ThemeState.mode = i
                        ThemeState.save(ctx)
                    },
                    label = { Text(t) }
                )
                Spacer(Modifier.width(6.dp))
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(
                checked = ThemeState.amoled,
                onCheckedChange = {
                    ThemeState.amoled = it
                    ThemeState.save(ctx)
                }
            )
            Text("  Чёрный фон (AMOLED) в тёмной теме", fontSize = 13.sp)
        }
        HorizontalDivider(Modifier.padding(top = 8.dp))
    }
}

// END
