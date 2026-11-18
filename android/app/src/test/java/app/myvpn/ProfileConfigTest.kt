package app.myvpn

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ProfileConfigTest {
    private fun sample() = Profile.parse(
        """{
            "version": 1, "host": "192.0.2.1", "dns": "1.1.1.1",
            "vless": {"uuid": "00000000-0000-4000-8000-000000000001", "sni": "example.org",
                "publicKey": "example-public-key", "shortId": "abcd", "fingerprint": "chrome",
                "tcpPort": 443, "xhttpPort": 8443, "xhttpPath": "/old"},
            "hy2": {"port": 443, "obfsPort": 8443, "auth": "example-auth", "sni": "example.org",
                "pinSha256": "0123456789abcdef", "obfsPassword": "example-obfs"},
            "awg": {"port": 51821, "privateKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "serverPublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "address": "10.0.0.2/32", "mtu": 1280, "jc": 4, "jmin": 40, "jmax": 70,
                "s1": 10, "s2": 20, "s3": 30, "s4": 40, "h1": "100-200", "h2": "300-400",
                "h3": "500-600", "h4": "700-800", "i1": "<b 0x1234>"},
            "wg": {"privateKey": "obsolete"}, "relay": {"host": "192.0.2.2"}
        }""".trimIndent()
    )

    private fun outbound(protocol: Protocol): JSONObject =
        JSONObject(XrayConfig.build(sample(), protocol, 10808)).getJSONArray("outbounds").getJSONObject(0)

    @Test fun migrationRemovesOldTransportsAndPreservesRetainedCredentials() {
        val p = sample()
        assertEquals(2, p.int("version"))
        assertFalse(p.json.has("wg"))
        assertFalse(p.json.has("relay"))
        assertFalse(p.json.getJSONObject("vless").has("xhttpPort"))
        assertFalse(p.json.getJSONObject("vless").has("xhttpPath"))
        assertEquals("00000000-0000-4000-8000-000000000001", p.str("vless.uuid"))
        assertEquals("example-auth", p.str("hy2.auth"))
        assertEquals("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", p.str("awg.privateKey"))
        assertEquals(p.toString(), Profile.parse(p.toString()).toString())
    }

    @Test fun removedAndUnknownSavedProtocolsFallBackToHysteria() {
        for (name in listOf("WG", "VLESS_XHTTP", "future", null)) {
            assertEquals(Protocol.HY2, Protocol.restored(name))
        }
        for (p in Protocol.supported) assertEquals(p, Protocol.restored(p.name))
    }

    @Test fun vlessUsesTcpRealityVision() {
        val config = outbound(Protocol.VLESS_TCP)
        val settings = config.getJSONObject("settings")
        val stream = config.getJSONObject("streamSettings")
        assertEquals("vless", config.getString("protocol"))
        // Внешний транспорт остаётся TCP/REALITY, UDP/443 внутри туннеля разрешён.
        assertEquals("xtls-rprx-vision-udp443", settings.getString("flow"))
        assertEquals(443, settings.getInt("port"))
        assertEquals("raw", stream.getString("network"))
        assertEquals("reality", stream.getString("security"))
        assertEquals("example-public-key", stream.getJSONObject("realitySettings").getString("publicKey"))
        assertFalse(stream.has("xhttpSettings"))
        val inbounds = JSONObject(XrayConfig.build(sample(), Protocol.VLESS_TCP, 10808)).getJSONArray("inbounds")
        assertTrue(inbounds.getJSONObject(1).getJSONObject("settings").getBoolean("udp"))
    }

    @Test fun plainHysteriaKeepsCertificatePinWithoutSalamander() {
        val config = outbound(Protocol.HY2)
        val stream = config.getJSONObject("streamSettings")
        assertEquals("hysteria", config.getString("protocol"))
        assertEquals(2, config.getJSONObject("settings").getInt("version"))
        assertEquals(443, config.getJSONObject("settings").getInt("port"))
        assertEquals("example-auth", stream.getJSONObject("hysteriaSettings").getString("auth"))
        assertEquals("0123456789abcdef", stream.getJSONObject("tlsSettings").getString("pinnedPeerCertSha256"))
        assertFalse(stream.has("finalmask"))
    }

    @Test fun obfuscatedHysteriaUsesOwnPortAndSalamanderPassword() {
        val config = outbound(Protocol.HY2_OBFS)
        assertEquals(8443, config.getJSONObject("settings").getInt("port"))
        val mask = config.getJSONObject("streamSettings").getJSONObject("finalmask")
            .getJSONArray("udp").getJSONObject(0)
        assertEquals("salamander", mask.getString("type"))
        assertEquals("example-obfs", mask.getJSONObject("settings").getString("password"))
    }

    @Test(expected = IllegalStateException::class)
    fun amneziaCannotAccidentallyUseVlessConfiguration() {
        XrayConfig.build(sample(), Protocol.AWG, 10808)
    }

    @Test fun tunDnsUsesHttpsThroughProxyAndPrecedesLocalBypassRules() {
        for (mode in listOf(Protocol.HY2, Protocol.HY2_OBFS, Protocol.VLESS_TCP)) {
            val config = JSONObject(XrayConfig.build(sample(), mode, 10808))
            val dns = config.getJSONObject("dns")
            assertTrue(dns.getBoolean("disableFallback"))
            assertEquals("UseIPv4", dns.getString("queryStrategy"))
            assertTrue(dns.getJSONArray("servers").getString(0).startsWith("https://"))
            val rules = config.getJSONObject("routing").getJSONArray("rules")
            assertEquals("53", rules.getJSONObject(0).getString("port"))
            assertEquals("dns-out", rules.getJSONObject(0).getString("outboundTag"))
            assertEquals(dns.getString("tag"), rules.getJSONObject(1).getJSONArray("inboundTag").getString(0))
            assertEquals("proxy", rules.getJSONObject(1).getString("outboundTag"))
            val outbounds = config.getJSONArray("outbounds")
            val dnsOut = (0 until outbounds.length()).map { outbounds.getJSONObject(it) }.first { it.getString("tag") == "dns-out" }
            assertEquals("dns", dnsOut.getString("protocol"))
            assertFalse(dnsOut.has("proxySettings"))
            assertEquals("proxy", dnsOut.getJSONObject("streamSettings").getJSONObject("sockopt").getString("dialerProxy"))
            val policy = dnsOut.getJSONObject("settings").getJSONArray("rules")
            val ipv6 = (0 until policy.length()).map { policy.getJSONObject(it) }.first { it.optInt("qType") == 28 }
            assertEquals("return", ipv6.getString("action"))
            assertEquals(0, ipv6.getInt("rCode"))
        }
    }

    @Test fun amneziaParserRetainsAwg2ObfuscationAndIpv4Route() {
        val config = AwgConfig.build(sample())
        val iface = config.`interface`
        assertEquals(4, iface.junkPacketCount.get())
        assertEquals(30, iface.cookieReplyPacketJunkSize.get())
        assertEquals(40, iface.transportPacketJunkSize.get())
        assertEquals("100-200", iface.initPacketMagicHeader.get())
        assertEquals("<b 0x1234>", iface.specialJunkI1.get())
        val serialized = config.toAwgQuickString(true, true)
        assertTrue(serialized.contains("AllowedIPs = 0.0.0.0/0"))
        assertTrue(serialized.contains("Endpoint = 192.0.2.1:51821"))
    }

    @Test fun settingsCannotReintroduceDeletedTransports() {
        val p = sample().with(mapOf("wg.port" to "1234", "relay.host" to "192.0.2.2",
            "vless.xhttpPort" to "8888", "vless.tcpPort" to "444", "hy2.auth" to "changed"))
        assertFalse(p.json.has("wg"))
        assertFalse(p.json.has("relay"))
        assertFalse(p.json.getJSONObject("vless").has("xhttpPort"))
        assertEquals(443, p.int("vless.tcpPort"))
        assertEquals("changed", p.str("hy2.auth"))
    }
}
