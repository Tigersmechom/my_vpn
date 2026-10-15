package app.myvpn

import org.amnezia.awg.config.Config
import org.json.JSONArray
import org.json.JSONObject

/** Сети, которые Xray отправляет напрямую, мимо сервера (локалка, loopback и т.п.). */
private val PRIVATE_NETS = listOf(
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "fc00::/7", "fe80::/10",
)

object XrayConfig {
    /**
     * Клиентский конфиг Xray: TUN-inbound (fd передаётся отдельно в startLoop),
     * локальный SOCKS для встроенного теста скорости и outbound VLESS+Reality или Hysteria2.
     */
    fun build(p: Profile, protocol: Protocol, socksPort: Int): String {
        val proxy = when (protocol) {
            Protocol.HY2, Protocol.HY2_OBFS -> hysteria(p, obfs = protocol == Protocol.HY2_OBFS)
            Protocol.VLESS_TCP -> vless(p)
            Protocol.AWG -> error("Для AmneziaWG используется отдельное ядро")
            else -> protocol.customOutbound?.let { JSONObject(it) }
                ?: error("Для этого протокола нужно обновить приложение")
        }
        return JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put(
                "inbounds", JSONArray()
                    .put(
                        JSONObject()
                            .put("tag", "tun")
                            .put("port", 0)
                            .put("protocol", "tun")
                            .put("settings", JSONObject().put("name", "xray0").put("mtu", XrayVpnService.MTU))
                    )
                    .put(
                        JSONObject()
                            .put("tag", "socks")
                            .put("listen", "127.0.0.1")
                            .put("port", socksPort)
                            .put("protocol", "socks")
                            .put("settings", JSONObject().put("auth", "noauth").put("udp", true))
                    )
            )
            .put(
                "outbounds", JSONArray()
                    .put(proxy.put("tag", "proxy"))
                    .put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
                    .put(JSONObject().put("tag", "block").put("protocol", "blackhole"))
            )
            .put(
                "routing", JSONObject()
                    .put("domainStrategy", "AsIs")
                    .put(
                        "rules", JSONArray().put(
                            JSONObject().put("type", "field")
                                .put("ip", JSONArray(PRIVATE_NETS))
                                .put("outboundTag", "direct")
                        )
                    )
            )
            .toString()
    }

    /** Hysteria2: QUIC с самоподписанным сертификатом, проверяется по отпечатку SHA-256. */
    private fun hysteria(p: Profile, obfs: Boolean): JSONObject {
        val stream = JSONObject()
            .put("network", "hysteria")
            .put("hysteriaSettings", JSONObject().put("version", 2).put("auth", p.str("hy2.auth")))
            .put("security", "tls")
            .put(
                "tlsSettings", JSONObject()
                    .put("serverName", p.str("hy2.sni"))
                    .put("alpn", JSONArray().put("h3"))
                    .put("pinnedPeerCertSha256", p.str("hy2.pinSha256"))
            )
        if (obfs) {
            val salamander = JSONObject().put("type", "salamander")
                .put("settings", JSONObject().put("password", p.str("hy2.obfsPassword")))
            stream.put("finalmask", JSONObject().put("udp", JSONArray().put(salamander)))
        }
        return JSONObject()
            .put("protocol", "hysteria")
            .put(
                "settings", JSONObject().put("version", 2).put("address", p.host)
                    .put("port", p.int(if (obfs) "hy2.obfsPort" else "hy2.port"))
            )
            .put("streamSettings", stream)
    }

    private fun vless(p: Profile): JSONObject {
        val port = p.int("vless.tcpPort")

        val user = JSONObject()
            .put("address", p.host)
            .put("port", port)
            .put("id", p.str("vless.uuid"))
            .put("encryption", "none")
        user.put("flow", "xtls-rprx-vision")

        val stream = JSONObject()
            .put("network", "raw")
            .put("security", "reality")
            .put(
                "realitySettings", JSONObject()
                    .put("serverName", p.str("vless.sni"))
                    .put("fingerprint", p.str("vless.fingerprint").ifEmpty { "chrome" })
                    .put("publicKey", p.str("vless.publicKey"))
                    .put("shortId", p.str("vless.shortId"))
                    .put("spiderX", "/")
            )
        return JSONObject().put("protocol", "vless").put("settings", user).put("streamSettings", stream)
    }
}

object AwgConfig {
    /** Конфиг для AmneziaWG-бэкенда, включая параметры обфускации AWG 2.0. */
    fun build(p: Profile): Config {
        val s = "awg"
        val text = buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = ${p.str("$s.privateKey")}")
            appendLine("Address = ${p.str("$s.address")}")
            if (p.dnsServers.isNotEmpty()) appendLine("DNS = ${p.dnsServers.joinToString(", ")}")
            p.int("$s.mtu").takeIf { it > 0 }?.let { appendLine("MTU = $it") }
            run {
                for (k in listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")) {
                    p.int("awg.$k").takeIf { it > 0 }?.let { appendLine("${k.replaceFirstChar(Char::uppercase)} = $it") }
                }
                for (k in listOf("h1", "h2", "h3", "h4", "i1")) {
                    p.str("awg.$k").takeIf { it.isNotBlank() }?.let { appendLine("${k.uppercase()} = $it") }
                }
            }
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = ${p.str("$s.serverPublicKey")}")
            p.str("$s.presharedKey").takeIf { it.isNotBlank() }?.let { appendLine("PresharedKey = $it") }
            appendLine("Endpoint = ${p.host}:${p.int("$s.port")}")
            // Только IPv4: адреса IPv6 на интерфейсе нет, поэтому Android блокирует IPv6 целиком — без утечек.
            appendLine("AllowedIPs = 0.0.0.0/0")
            appendLine("PersistentKeepalive = 25")
        }
        return Config.parse(text.byteInputStream())
    }
}
