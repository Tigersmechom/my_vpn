package app.myvpn

import org.json.JSONObject

data class Protocol(
    val name: String,
    val title: String,
    val subtitle: String,
    val customOutbound: String? = null,
) {
    val usesXray get() = name != AWG.name

    companion object {
        val VLESS_TCP = Protocol("VLESS_TCP", "VLESS Reality · TCP", "Vision, маскировка под HTTPS")
        val HY2 = Protocol("HY2", "Hysteria2", "QUIC, UDP")
        val HY2_OBFS = Protocol("HY2_OBFS", "Hysteria2 + Salamander", "QUIC с обфускацией, UDP")
        val AWG = Protocol("AWG", "AmneziaWG", "WireGuard с обфускацией, UDP")
        val entries = listOf(VLESS_TCP, HY2, HY2_OBFS, AWG)

        /** Старый или удалённый выбор безопасно заменяем на TCP. */
        fun restored(name: String?, profile: Profile? = null): Protocol =
            (profile?.protocols ?: entries).firstOrNull { it.name == name } ?: VLESS_TCP

        fun history(name: String, title: String): Protocol? = entries.firstOrNull { it.name == name }
            ?: name.takeIf { it.matches(Regex("^custom-[A-Za-z0-9_-]{1,48}$")) }
                ?.let { Protocol(it, title.take(80).ifBlank { it }, "") }
    }
}

/**
 * Профиль сервера. Формат совпадает с выводом `vpnctl profile <имя>` на сервере,
 * поэтому храним JSON как есть и читаем поля по пути вида "vless.uuid".
 */
class Profile(val json: JSONObject) {

    fun str(path: String): String {
        val (obj, key) = locate(path) ?: return ""
        return if (obj.has(key) && !obj.isNull(key)) obj.get(key).toString() else ""
    }

    fun int(path: String): Int = str(path).trim().toIntOrNull() ?: 0

    val host get() = str("host")
    val protocols: List<Protocol> get() = Protocol.entries + ExtraXray.parse(json.optJSONArray("extraXray"))
    val dnsServers get() = str("dns").split(',', ' ').map { it.trim() }.filter { it.isNotEmpty() }

    /** Копия профиля с изменёнными полями. Числовые поля сохраняются числами. */
    fun with(values: Map<String, String>): Profile {
        val copy = JSONObject(json.toString())
        for ((path, raw) in values) {
            val field = Fields.byPath[path] ?: continue
            val parts = path.split('.')
            var obj = copy
            for (p in parts.dropLast(1)) {
                obj = obj.optJSONObject(p) ?: JSONObject().also { obj.put(p, it) }
            }
            val v = raw.trim()
            obj.put(parts.last(), if (field.numeric) v.toIntOrNull() ?: 0 else v)
        }
        return Profile(copy)
    }

    private fun locate(path: String): Pair<JSONObject, String>? {
        val parts = path.split('.')
        var obj = json
        for (p in parts.dropLast(1)) obj = obj.optJSONObject(p) ?: return null
        return obj to parts.last()
    }

    override fun toString(): String = json.toString()

    companion object {
        fun parse(text: String): Profile {
            val obj = JsonBounds.objectFrom(text.trim())
            require(obj.has("host") && obj.has("vless")) { "Это не профиль My VPN (нет полей host/vless)" }
            // Миграция старых сохранённых и импортированных профилей без замены ключей.
            obj.remove("wg")
            obj.remove("relay")
            obj.optJSONObject("vless")?.apply {
                remove("xhttpPort")
                remove("xhttpPath")
            }
            obj.put("version", 2)
            require(!obj.has("extraXray") || obj.opt("extraXray") is org.json.JSONArray) { "Дополнительные режимы должны быть списком" }
            ExtraXray.parse(obj.optJSONArray("extraXray"))
            return Profile(obj)
        }
    }
}

data class Field(val path: String, val label: String, val numeric: Boolean = false)

data class FieldGroup(val title: String, val fields: List<Field>)

/** Описание редактируемых полей для экрана настроек. */
object Fields {
    val groups = listOf(
        FieldGroup(
            "Сервер", listOf(
                Field("host", "Адрес сервера (IP или домен)"),
                Field("dns", "DNS внутри туннеля"),
            )
        ),
        FieldGroup(
            "VLESS + Reality", listOf(
                Field("vless.uuid", "UUID"),
                Field("vless.sni", "SNI (маскировочный сайт)"),
                Field("vless.publicKey", "Public key"),
                Field("vless.shortId", "Short ID"),
                Field("vless.fingerprint", "Fingerprint"),
                Field("vless.tcpPort", "Порт TCP", numeric = true),
            )
        ),
        FieldGroup(
            "Hysteria2", listOf(
                Field("hy2.port", "Порт (UDP)", numeric = true),
                Field("hy2.obfsPort", "Порт с Salamander (UDP)", numeric = true),
                Field("hy2.auth", "Пароль (auth)"),
                Field("hy2.sni", "SNI"),
                Field("hy2.pinSha256", "SHA-256 сертификата"),
                Field("hy2.obfsPassword", "Пароль Salamander"),
            )
        ),
        FieldGroup(
            "AmneziaWG", listOf(
                Field("awg.port", "Порт (UDP)", numeric = true),
                Field("awg.privateKey", "Private key клиента"),
                Field("awg.address", "Адрес клиента"),
                Field("awg.mtu", "MTU", numeric = true),
                Field("awg.serverPublicKey", "Public key сервера"),
                Field("awg.presharedKey", "Preshared key"),
                Field("awg.jc", "Jc", numeric = true),
                Field("awg.jmin", "Jmin", numeric = true),
                Field("awg.jmax", "Jmax", numeric = true),
                Field("awg.s1", "S1", numeric = true),
                Field("awg.s2", "S2", numeric = true),
                Field("awg.s3", "S3", numeric = true),
                Field("awg.s4", "S4", numeric = true),
                Field("awg.h1", "H1"),
                Field("awg.h2", "H2"),
                Field("awg.h3", "H3"),
                Field("awg.h4", "H4"),
                Field("awg.i1", "I1"),
            )
        ),

    )

    val byPath: Map<String, Field> = groups.flatMap { it.fields }.associateBy { it.path }
}
