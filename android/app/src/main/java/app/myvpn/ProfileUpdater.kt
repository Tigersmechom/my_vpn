package app.myvpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import java.net.URI
import java.io.IOException
import java.net.SocketTimeoutException
import java.security.GeneralSecurityException
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import kotlin.io.encoding.Base64

private const val UPDATE_FORMAT = "myvpn-update-v1"
private const val MAX_UPDATE_BYTES = 1024 * 1024

/** AES-GCM key stays in the installed app; only encrypted envelopes are published. */
data class UpdateBootstrap(val client: String, val url: String, val key: ByteArray, val minRevision: Int) {
    companion object {
        fun parse(text: String): UpdateBootstrap {
            val obj = JSONObject(text)
            require(obj.getString("format") == "myvpn-bootstrap-v1") { "Неверный формат настроек обновления" }
            val client = obj.getString("client")
            require(client == "android") { "Настройки обновления предназначены для другого устройства" }
            val url = obj.getString("url")
            val parsed = URL(url)
            require(parsed.protocol == "https" && parsed.userInfo == null && parsed.ref == null && parsed.host.isNotBlank()) {
                "Для обновлений требуется HTTPS"
            }
            val key = Base64.decode(obj.getString("key"))
            require(key.size == 32) { "Неверный ключ обновления" }
            val revision = exactRevision(obj, "minRevision")
            return UpdateBootstrap(client, url, key, revision)
        }
    }
}

data class ProfileUpdate(val revision: Int, val profile: Profile)

object UpdateEnvelope {
    /** Pure validation: never mutates settings or touches the active tunnel. */
    fun decode(bytes: ByteArray, bootstrap: UpdateBootstrap, appliedRevision: Int): ProfileUpdate {
        require(bytes.size <= MAX_UPDATE_BYTES) { "Обновление слишком большое" }
        try {
            val envelope = JsonBounds.objectFrom(bytes.toString(Charsets.UTF_8))
            require(envelope.getString("format") == UPDATE_FORMAT) { "Неверный формат обновления" }
            require(envelope.getString("client") == bootstrap.client) { "Обновление предназначено для другого устройства" }
            val revision = exactRevision(envelope, "revision")
            require(revision >= bootstrap.minRevision && revision >= appliedRevision) { "Получено устаревшее обновление" }
            val nonce = Base64.decode(envelope.getString("nonce"))
            require(nonce.size == 12 && bootstrap.key.size == 32) { "Неверный формат защиты обновления" }
            val ciphertext = Base64.decode(envelope.getString("ciphertext"))
            require(ciphertext.size >= 16 && ciphertext.size <= MAX_UPDATE_BYTES) { "Неверный размер обновления" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(bootstrap.key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD("$UPDATE_FORMAT\n${bootstrap.client}\n$revision".toByteArray(Charsets.UTF_8))
            val payload = JsonBounds.objectFrom(cipher.doFinal(ciphertext).toString(Charsets.UTF_8))
            require(payload.get("schema") is Int && payload.getInt("schema") == 1) { "Для этого обновления нужно обновить приложение" }
            require(payload.getString("client") == bootstrap.client && exactRevision(payload, "revision") == revision) {
                "Не совпадают данные обновления"
            }
            val rawProfile = payload.getJSONObject("profile")
            require(rawProfile.get("version") is Int && rawProfile.getInt("version") == 2) {
                "Для этого формата профиля нужно обновить приложение"
            }
            require(rawProfile.getString("client") == bootstrap.client) { "Профиль предназначен для другого устройства" }
            val profile = Profile.parse(rawProfile.toString())
            ProfileValidation.requireComplete(profile)
            return ProfileUpdate(revision, profile)
        } catch (e: GeneralSecurityException) {
            throw IllegalArgumentException("Не удалось проверить подлинность обновления")
        } catch (e: org.json.JSONException) {
            throw IllegalArgumentException("Неверный формат обновления")
        }
    }
}

private fun exactRevision(obj: JSONObject, key: String): Int {
    val value = obj.get(key)
    require((value is Int || value is Long) && (value as Number).toLong() in 1..Int.MAX_VALUE.toLong()) {
        "Неверный номер обновления"
    }
    return (value as Number).toInt()
}

/** Reduce intermediary caching; the authenticated revision floor still rejects stale responses. */
internal fun cacheBustedUpdateUrl(url: String): String {
    val parsed = URI(url)
    require(parsed.scheme == "https" && parsed.host?.isNotBlank() == true &&
        parsed.rawUserInfo == null && parsed.rawFragment == null) { "Для обновлений требуется HTTPS без данных пользователя и фрагмента" }
    val separator = if (parsed.rawQuery == null) "?" else "&"
    return parsed.toASCIIString() + separator + "_myvpn_nonce=" + UUID.randomUUID()
}

object ProfileUpdater {
    private val deadlines = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "vpn-update-deadline").apply { isDaemon = true }
    }

    suspend fun refresh(store: Store): Boolean = withContext(Dispatchers.IO) {
        val bootstrap = store.bootstrap ?: error("Обновления не настроены в этой сборке")
        // Приложение исключено из Xray VPN, поэтому используем его локальный SOCKS.
        val status = VpnController.status.value
        val socksPort = status.socksPort.takeIf { status.state == VpnState.UP && status.protocol?.usesXray == true } ?: 0
        val update = download(bootstrap, store.appliedRevision, socksPort)
        store.applyUpdate(update)
    }

    /** При недоступном старом сервере пробуем HTTPS напрямую, не останавливая туннель. */
    internal fun download(bootstrap: UpdateBootstrap, appliedRevision: Int, socksPort: Int,
        fetcher: (String, Int) -> ByteArray = ::fetch): ProfileUpdate {
        val bytes = try {
            try {
                fetcher(bootstrap.url, socksPort)
            } catch (e: IOException) {
                if (socksPort <= 0) throw e
                fetcher(bootstrap.url, 0)
            }
        } catch (_: IOException) {
            throw IllegalStateException("Не удалось загрузить обновление. Проверьте интернет и повторите.")
        }
        // Ошибки подписи, формата и откат ревизии не вызывают сетевых повторов.
        return UpdateEnvelope.decode(bytes, bootstrap, appliedRevision)
    }

    private fun fetch(url: String, socksPort: Int): ByteArray {
        val proxy = if (socksPort > 0) java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", socksPort))
            else java.net.Proxy.NO_PROXY
        val connection = URL(cacheBustedUpdateUrl(url)).openConnection(proxy) as HttpsURLConnection
        val expired = AtomicBoolean(false)
        val deadline = deadlines.schedule({
            expired.set(true)
            connection.disconnect()
        }, 20, TimeUnit.SECONDS)
        try {
            connection.connectTimeout = 6_000
            connection.readTimeout = 8_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Cache-Control", "no-cache")
            require(connection.responseCode == 200) { "Сервер обновлений временно недоступен" }
            require(connection.contentLengthLong <= MAX_UPDATE_BYTES) { "Обновление слишком большое" }
            return connection.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    if (expired.get()) throw SocketTimeoutException()
                    val count = input.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= MAX_UPDATE_BYTES) { "Обновление слишком большое" }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } finally {
            deadline.cancel(false)
            connection.disconnect()
        }
    }
}

object ProfileValidation {
    fun requireComplete(p: Profile) {
        fun required(path: String) {
            require(p.str(path).isNotBlank() && !p.str(path).any { it.code < 32 }) { "В обновлении неполные данные профиля" }
        }
        fun port(path: String) { require(p.int(path) in 1..65535) { "В обновлении неверный порт" } }
        for (path in listOf("host", "dns", "vless.uuid", "vless.sni", "vless.publicKey", "vless.shortId",
            "hy2.auth", "hy2.sni", "hy2.pinSha256", "hy2.obfsPassword", "awg.privateKey",
            "awg.serverPublicKey", "awg.address", "awg.h1", "awg.h2", "awg.h3", "awg.h4")) required(path)
        require(runCatching { UUID.fromString(p.str("vless.uuid")) }.isSuccess) { "В обновлении неверный UUID" }
        for (path in listOf("vless.tcpPort", "hy2.port", "hy2.obfsPort", "awg.port")) port(path)
        require(p.str("vless.publicKey").matches(Regex("[A-Za-z0-9_-]{43}"))) { "В обновлении неверный ключ REALITY" }
        require(p.str("vless.shortId").matches(Regex("(?:[A-Fa-f0-9]{2}){1,8}"))) { "В обновлении неверный Short ID" }
        require(p.str("hy2.pinSha256").matches(Regex("[A-Fa-f0-9]{64}"))) { "В обновлении неверный отпечаток сертификата" }
        for (path in listOf("awg.privateKey", "awg.serverPublicKey", "awg.presharedKey")) {
            require(runCatching { Base64.decode(p.str(path)).size == 32 }.getOrDefault(false)) { "В обновлении неверный ключ AmneziaWG" }
        }
        require(p.int("awg.mtu") in 576..9000) { "В обновлении неверный MTU" }
        require(p.int("awg.jmin") >= 0 && p.int("awg.jmax") >= p.int("awg.jmin")) { "В обновлении неверные параметры AmneziaWG" }
        require(p.dnsServers.isNotEmpty()) { "В обновлении не задан DNS" }
        require(runCatching { AwgConfig.build(p) }.isSuccess) { "В обновлении неверная конфигурация AmneziaWG" }
        require(p.protocols.size >= 4)
    }
}

object ExtraXray {
    private val supported = setOf("vless", "hysteria", "trojan", "vmess", "shadowsocks")
    private val denied = setOf("certificatefile", "keyfile", "masterkeylog", "sslkeylogfile", "sockopt",
        "proxysettings", "sendthrough", "dialerproxy", "log", "inbounds", "outbounds", "routing", "dns",
        "api", "stats", "policy", "includes", "exec", "command", "script")
    private val topLevel = setOf("protocol", "settings", "streamSettings", "mux")

    fun parse(extras: JSONArray?): List<Protocol> {
        if (extras == null) return emptyList()
        require(extras.length() <= 8) { "В профиле слишком много дополнительных режимов" }
        val used = mutableSetOf<String>()
        return (0 until extras.length()).map { index ->
            val item = extras.getJSONObject(index)
            val id = item.getString("id")
            val title = item.getString("title")
            require(id.matches(Regex("^custom-[A-Za-z0-9_-]{1,48}$")) && used.add(id)) { "Неверный или повторяющийся ID режима" }
            require(title.isNotBlank() && title.length <= 80 && title.none { it.isISOControl() }) { "Неверное название режима" }
            val outbound = item.getJSONObject("outbound")
            require(outbound.keys().asSequence().all { it in topLevel }) { "В режиме есть недопустимые параметры" }
            val protocol = outbound.getString("protocol")
            require(protocol in supported) { "Для нового протокола нужно обновить приложение" }
            require(outbound.optJSONObject("settings") != null) { "В режиме отсутствуют настройки" }
            if (protocol == "hysteria") require(outbound.getJSONObject("settings").optInt("version", 2) == 2) {
                "Поддерживается только Hysteria 2"
            }
            validateNode(outbound, 0)
            validateSettings(protocol, outbound.getJSONObject("settings"))
            Protocol(id, title, "Дополнительный режим Xray · $protocol", outbound.toString())
        }
    }

    private fun validateSettings(protocol: String, settings: JSONObject) {
        fun endpoint(server: JSONObject) {
            require(server.optString("address").isNotBlank() && server.optInt("port") in 1..65535) {
                "В дополнительном режиме не задан сервер или порт"
            }
        }
        if (protocol == "hysteria") { endpoint(settings); return }
        val servers = settings.optJSONArray(if (protocol == "vless" || protocol == "vmess") "vnext" else "servers")
            ?: JSONArray().put(settings)
        require(servers.length() in 1..16) { "В дополнительном режиме не задан сервер" }
        for (index in 0 until servers.length()) {
            val server = servers.getJSONObject(index)
            endpoint(server)
            if (protocol == "vless" || protocol == "vmess") {
                val users = server.optJSONArray("users") ?: JSONArray().put(server)
                require(users.length() in 1..16) { "В дополнительном режиме не задан пользователь" }
                for (userIndex in 0 until users.length()) {
                    require(users.getJSONObject(userIndex).optString("id").isNotBlank()) { "В дополнительном режиме не задан ID пользователя" }
                }
            } else {
                require(server.optString("password").isNotBlank()) { "В дополнительном режиме не задан пароль" }
                if (protocol == "shadowsocks") require(server.optString("method").isNotBlank()) {
                    "В дополнительном режиме не задан метод шифрования"
                }
            }
        }
    }

    private fun validateNode(value: Any?, depth: Int) {
        require(depth <= 16) { "Настройки режима слишком сложные" }
        when (value) {
            is JSONObject -> value.keys().forEach { key ->
                val lower = key.lowercase()
                require(lower !in denied && !lower.endsWith("file") && !lower.endsWith("filename") && !lower.endsWith("filepath")) {
                    "В режиме есть недопустимые параметры"
                }
                if (lower == "allowinsecure") require(value.get(key) == false) {
                    "Проверка TLS-сертификата должна быть включена"
                }
                validateNode(value.get(key), depth + 1)
            }
            is JSONArray -> (0 until value.length()).forEach { validateNode(value.get(it), depth + 1) }
        }
    }
}


object JsonBounds {
    fun objectFrom(text: String): JSONObject {
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_UPDATE_BYTES) { "Профиль слишком большой" }
        var depth = 0
        var quoted = false
        var escaped = false
        for (char in text) {
            if (quoted) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{', '[' -> { depth++; require(depth <= 24) { "Настройки слишком сложные" } }
                '}', ']' -> depth--
            }
        }
        return JSONObject(text)
    }
}
