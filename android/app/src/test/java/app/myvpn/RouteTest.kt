package app.myvpn

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RouteTest {
    private fun base(): JSONObject = JSONObject("""{
        "version":2,"client":"android","host":"192.0.2.1","dns":"1.1.1.1",
        "vless":{"uuid":"00000000-0000-4000-8000-000000000001","sni":"example.org","publicKey":"${"A".repeat(43)}","shortId":"abcd","tcpPort":443},
        "hy2":{"port":443,"obfsPort":8443,"auth":"finland-auth","sni":"example.org","pinSha256":"${"a".repeat(64)}","obfsPassword":"finland-obfs"},
        "awg":{"port":51821,"privateKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","serverPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "presharedKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","address":"10.77.77.2/32","mtu":1280,"jc":3,"jmin":20,"jmax":40,
        "s1":10,"s2":20,"s3":30,"s4":40,"h1":"100-200","h2":"300-400","h3":"500-600","h4":"700-800"}}
    """)

    private fun catalog(): JSONObject {
        val pl = base().put("host", "192.0.2.2")
        val relay = base().put("host", "192.0.2.2").put("exitHost", "192.0.2.1")
        relay.getJSONObject("hy2").put("port", 10443).put("obfsPort", 10444)
        relay.getJSONObject("awg").put("port", 10445)
        return base().put("routes", JSONArray()
            .put(JSONObject().put("id", "pl").put("title", "Польша").put("profile", pl))
            .put(JSONObject().put("id", "pl-fi").put("title", "Польша → Финляндия").put("profile", relay)))
    }

    @Test fun nineChoicesUseCorrectEndpointCoreAndFinlandPin() {
        val p = Profile.parse(catalog().toString())
        assertEquals(9, p.protocols.size)
        assertEquals(9, p.protocols.map { it.name }.toSet().size)
        assertEquals(3, p.protocols.count { !it.usesXray })
        assertFalse(p.protocols.any { it.baseName == "VLESS_TCP" })
        for (mode in p.protocols) {
            val endpoint = p.connectionProfile(mode)
            assertEquals(mode, Protocol.restored(mode.name, Profile.parse(p.toString())))
            assertEquals(mode.usesXray, Protocol.history(mode.name, mode.title)!!.usesXray)
            if (mode.routeId != null) assertEquals("192.0.2.2", endpoint.host)
            if (mode.usesXray) {
                val config = JSONObject(XrayConfig.build(p, mode, 10808))
                val out = config.getJSONArray("outbounds").getJSONObject(0)
                assertEquals(endpoint.host, out.getJSONObject("settings").getString("address"))
                assertEquals(endpoint.str("hy2.pinSha256"), out.getJSONObject("streamSettings").getJSONObject("tlsSettings").getString("pinnedPeerCertSha256"))
                if (mode.routeId == "pl-fi") assertEquals("finland-auth", endpoint.str("hy2.auth"))
            } else {
                val config = AwgConfig.build(endpoint).toAwgQuickString(true, true)
                assertTrue(config.contains("Endpoint = ${endpoint.host}:${endpoint.int("awg.port")}"))
                if (mode.routeId == "pl-fi") assertEquals(10445, endpoint.int("awg.port"))
            }
        }
    }

    @Test fun newAndRemovedRoutesAppearFromDataInTheSameApplication() {
        val initial = Profile.parse(base().toString())
        val store = Store(MemoryPreferences(), { initial }, { null })
        store.applyUpdate(ProfileUpdate(1, initial))
        val activeSnapshot = store.profile
        val updated = Profile.parse(catalog().toString())
        assertTrue(store.applyUpdate(ProfileUpdate(2, updated)))
        assertEquals(9, store.profile.protocols.size)
        assertEquals(3, activeSnapshot.protocols.size)
        store.protocol = store.profile.protocols.last()
        val changed = catalog()
        changed.getJSONArray("routes").remove(1)
        changed.getJSONArray("routes").getJSONObject(0).put("title", "Новое название")
        store.applyUpdate(ProfileUpdate(3, Profile.parse(changed.toString())))
        assertEquals(6, store.profile.protocols.size)
        assertTrue(store.profile.protocols.last().title.contains("Новое название"))
        assertEquals("HY2", store.protocol.name)
        assertEquals(9, updated.protocols.size)
    }

    @Test fun healthPeersCannotReuseTheMainClientIdentity() {
        val probe = JSONObject().put("privateKey", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
            .put("presharedKey", "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=").put("address", "10.77.77.99/32")
        val valid = base().put("probeAwg", probe)
        Profile.parse(valid.toString())
        probe.put("address", "10.77.77.2/32")
        assertThrows(Exception::class.java) { Profile.parse(valid.toString()) }
        probe.put("address", "10.77.77.99/32").put("privateKey", valid.getJSONObject("awg").getString("privateKey"))
        assertThrows(Exception::class.java) { Profile.parse(valid.toString()) }
    }

    @Test fun malformedNestedAndCrossDeviceRoutesAreRejected() {
        val duplicate = catalog().also { it.getJSONArray("routes").put(it.getJSONArray("routes").getJSONObject(0)) }
        val nested = catalog().also { it.getJSONArray("routes").getJSONObject(0).put("profile", catalog()) }
        val wrong = catalog().also { it.getJSONArray("routes").getJSONObject(0).getJSONObject("profile").put("client", "mac") }
        val incomplete = catalog().also { it.getJSONArray("routes").getJSONObject(0).getJSONObject("profile").remove("hy2") }
        val fractional = catalog().also { it.getJSONArray("routes").getJSONObject(0).getJSONObject("profile").put("version", 2.5) }
        for (bad in listOf(duplicate, nested, wrong, incomplete, fractional, catalog().put("routes", JSONArray()),
            catalog().put("enabledProtocols", JSONArray().put("VLESS_TCP")), catalog().put("additionalServers", JSONArray()))) {
            assertThrows(Exception::class.java) { Profile.parse(bad.toString()) }
        }
    }
}
