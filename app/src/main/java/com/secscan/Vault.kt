package com.secscan

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONArray
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object AppCtx {
    @Volatile
    var c: Context? = null
}

object Vault {
    private const val ALIAS = "secscan_vault_v1"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val ex = ks.getKey(ALIAS, null)
        if (ex is SecretKey) return ex
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(
            KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return g.generateKey()
    }

    fun encryptBytes(b: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val iv = c.iv
        return iv + c.doFinal(b)
    }

    fun decryptBytes(b: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, 12))
        return c.doFinal(b, 12, b.size - 12)
    }

    fun enc(s: String): String =
        Base64.encodeToString(encryptBytes(s.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

    fun dec(s: String): String? = try {
        String(decryptBytes(Base64.decode(s, Base64.NO_WRAP)), Charsets.UTF_8)
    } catch (e: Exception) {
        null
    }
}

class SecPrefs private constructor(private val sp: SharedPreferences) {

    class Editor(private val ed: SharedPreferences.Editor) {
        private fun put(k: String, v: String) {
            try {
                ed.putString(k, Vault.enc(v))
            } catch (e: Exception) {
            }
        }

        fun putString(k: String, v: String): Editor {
            put(k, v)
            return this
        }

        fun putBoolean(k: String, v: Boolean): Editor {
            put(k, v.toString())
            return this
        }

        fun putStringSet(k: String, v: Set<String>): Editor {
            put(k, JSONArray(v.toList()).toString())
            return this
        }

        fun remove(k: String): Editor {
            ed.remove(k)
            return this
        }

        fun apply() {
            ed.apply()
        }
    }

    fun edit(): Editor = Editor(sp.edit())

    fun getString(k: String, d: String?): String? {
        val raw = sp.getString(k, null) ?: return d
        return Vault.dec(raw) ?: d
    }

    fun getBoolean(k: String, d: Boolean): Boolean =
        getString(k, null)?.toBooleanStrictOrNull() ?: d

    fun getStringSet(k: String, d: Set<String>?): Set<String>? {
        val s = getString(k, null) ?: return d
        return try {
            val a = JSONArray(s)
            val out = LinkedHashSet<String>()
            for (i in 0 until a.length()) out.add(a.getString(i))
            out
        } catch (e: Exception) {
            d
        }
    }

    companion object {
        fun open(ctx: Context): SecPrefs {
            val app = ctx.applicationContext
            val p = SecPrefs(app.getSharedPreferences("secscan_enc", Context.MODE_PRIVATE))
            try {
                val old = app.getSharedPreferences("secscan", Context.MODE_PRIVATE)
                val e = p.edit()
                var changed = false
                for (k in listOf("trusted", "baseline", "disabled", "notified")) {
                    val s = old.getStringSet(k, null)
                    if (s != null) {
                        if (p.getStringSet(k, null) == null) e.putStringSet(k, s)
                        changed = true
                    }
                }
                val vt = old.getString("vtkey", null)
                if (vt != null) {
                    if (p.getString("vtkey", null) == null) e.putString("vtkey", vt)
                    changed = true
                }
                if (old.contains("bg")) {
                    if (p.getString("bg", null) == null) e.putBoolean("bg", old.getBoolean("bg", false))
                    changed = true
                }
                if (changed) {
                    e.apply()
                    old.edit().remove("trusted").remove("baseline").remove("disabled")
                        .remove("notified").remove("vtkey").remove("bg").apply()
                }
            } catch (e: Exception) {
            }
            return p
        }
    }
}

// END
