package app.myvpn

import org.json.JSONObject

data class Protocol(
    val name: String,
    val title: String,
    val subtitle: String,
    val customOutbound: String? = null,
    val baseName: String = name,
    val routeId: String? = null,
) {
    val usesXray get() = baseName != AWG.name

    companion object {
        val VLESS_TCP = Protocol("VLESS_TCP", "VLESS Reality · TCP", "Vision, маскировка под HTTPS")
        val HY2 = Protocol("HY2", "Hysteria 2", "QUIC, UDP")
        val HY2_OBFS = Protocol("HY2_OBFS", "Hysteria 2 + Salamander", "QUIC с обфускацией, UDP")
        val AWG = Protocol("AWG", "AmneziaWG", "WireGuard с обфускацией, UDP")
        val entries = listOf(VLESS_TCP, HY2, HY2_OBFS, AWG)

        val supported = listOf(HY2, HY2_OBFS, AWG)

        /** Старый выбор заменяется первым доступным режимом текущего профиля. */
        fun restored(name: String?, profile: Profile? = null): Protocol =
            (profile?.protocols ?: supported).let { modes -> modes.firstOrNull { it.name == name } ?: modes.first() }

        fun history(name: String, title: String): Protocol? = entries.firstOrNull { it.name == name }
            ?: name.takeIf { it.matches(Regex("custom-[A-Za-z0-9_-]{1,48}")) }?.let { Protocol(it, title.take(80).ifBlank { it }, "Дополнительный режим Xray") }
            ?: Regex("^route-([A-Za-z0-9_-]{1,32})-(HY2_OBFS|HY2|AWG)$").matchEntire(name)
                ?.let { Protocol(name, title.take(80).ifBlank { name }, "", baseName = it.groupValues[2], routeId = it.groupValues[1]) }
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
    val directProtocols: List<Protocol> get() {
        val enabled = json.optJSONArray("enabledProtocols") ?: return Protocol.supported
        val ids = (0 until enabled.length()).map { enabled.getString(it) }.toSet()
        return Protocol.supported.filter { it.name in ids }
    }
    val protocols: List<Protocol> get() {
        val directTitle = str("serverTitle").ifBlank { "Напрямую" }
        val direct = directProtocols.map { if (json.has("routes")) it.copy(title = "${it.title} · $directTitle") else it }
        val routes = json.optJSONArray("routes") ?: org.json.JSONArray()
        return direct + (0 until routes.length()).flatMap { i ->
            val route = routes.getJSONObject(i)
            val id = route.getString("id")
            Profile(route.getJSONObject("profile")).directProtocols.map {
                it.copy(name = "route-$id-${it.name}", title = "${it.title} · ${route.getString("title")}", routeId = id)
            }
        } + ExtraXray.parse(json.optJSONArray("extraXray"))
    }

    fun connectionProfile(protocol: Protocol): Profile {
        if (protocol.customOutbound != null) {
            val settings = JSONObject(protocol.customOutbound).getJSONObject("settings")
            val endpoint = settings.optString("address").ifBlank {
                (settings.optJSONArray("vnext") ?: settings.optJSONArray("servers"))?.optJSONObject(0)?.optString("address").orEmpty()
            }
            return Profile(JSONObject(json.toString()).put("host", endpoint.ifBlank { host }))
        }
        val id = protocol.routeId ?: return this
        val routes = json.getJSONArray("routes")
        return (0 until routes.length()).map { routes.getJSONObject(it) }
            .first { it.getString("id") == id }.let { Profile(it.getJSONObject("profile")) }
    }
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
            RouteValidation.validate(obj)
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
