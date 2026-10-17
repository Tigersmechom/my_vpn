package app.myvpn

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.io.IOException
import java.net.SocketTimeoutException
import kotlin.io.encoding.Base64

class ProfileUpdateTest {
    private val key = ByteArray(32) { it.toByte() }
    private val bootstrap = UpdateBootstrap("android", "https://example.org/update.json", key, 1)

    private fun profile(): JSONObject = JSONObject()
        .put("version", 2).put("client", "android").put("host", "192.0.2.1").put("dns", "1.1.1.1")
        .put("vless", JSONObject().put("uuid", "00000000-0000-4000-8000-000000000001")
            .put("sni", "example.org").put("publicKey", "A".repeat(43)).put("shortId", "0123456789abcdef").put("tcpPort", 443))
        .put("hy2", JSONObject().put("auth", "test-auth").put("sni", "example.org")
            .put("pinSha256", "a".repeat(64)).put("obfsPassword", "test-obfs").put("port", 443).put("obfsPort", 8443))
        .put("awg", JSONObject().put("privateKey", Base64.encode(key)).put("serverPublicKey", Base64.encode(key))
            .put("presharedKey", Base64.encode(key)).put("address", "10.0.0.2/32").put("port", 51821)
            .put("mtu", 1280).put("h1", "100-200").put("h2", "300-400").put("h3", "500-600").put("h4", "700-800")
            .put("jmin", 20).put("jmax", 40))

    private fun envelope(p: JSONObject = profile(), revision: Int = 3, client: String = "android",
        payloadClient: String = client, payloadRevision: Int = revision): JSONObject {
        val nonce = ByteArray(12) { (it + 50).toByte() } // Test fixture only; production publisher uses random nonces.
        val payload = JSONObject().put("schema", 1).put("client", payloadClient).put("revision", payloadRevision).put("profile", p)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD("myvpn-update-v1\n$client\n$revision".toByteArray())
        val encrypted = cipher.doFinal(payload.toString().toByteArray())
        return JSONObject().put("format", "myvpn-update-v1").put("client", client).put("revision", revision)
            .put("nonce", Base64.encode(nonce)).put("ciphertext", Base64.encode(encrypted))
    }

    private fun decode(e: JSONObject, highest: Int = 0, b: UpdateBootstrap = bootstrap) =
        UpdateEnvelope.decode(e.toString().toByteArray(), b, highest)

    private fun extra(id: String = "custom-trojan", title: String = "New server") = JSONObject()
        .put("id", id).put("title", title).put("outbound", JSONObject().put("protocol", "trojan")
            .put("settings", JSONObject().put("servers", JSONArray().put(JSONObject().put("address", "192.0.2.2")
                .put("port", 443).put("password", "test-password"))))
            .put("streamSettings", JSONObject().put("network", "raw").put("security", "tls")
                .put("tlsSettings", JSONObject().put("serverName", "example.org")))).also { }

    @Test fun authenticUpdatePreservesProfileAndRevision() {
        val p = profile()
        val update = decode(envelope(p))
        assertEquals(3, update.revision)
        assertEquals(p.toString(), update.profile.toString())
        assertEquals(4, update.profile.protocols.size)
    }

    @Test fun sameRevisionIsAcceptedForIdempotentStorageAndFirstBootstrapApply() {
        assertEquals(3, decode(envelope(), 3).revision)
        assertEquals(1, decode(envelope(revision = 1), 0).revision)
    }

    @Test fun rejectsRollbackAndRevisionBelowBundledFloor() {
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(revision = 2), 3) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(revision = 1), 0, bootstrap.copy(minRevision = 2)) }
    }

    @Test fun rejectsTamperedCiphertextRevisionAndWrongKey() {
        val changed = envelope()
        val encrypted = Base64.decode(changed.getString("ciphertext"))
        encrypted[0] = (encrypted[0].toInt() xor 1).toByte()
        changed.put("ciphertext", Base64.encode(encrypted))
        assertThrows(IllegalArgumentException::class.java) { decode(changed) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope().put("revision", 4)) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(), b = bootstrap.copy(key = ByteArray(32))) }
    }

    @Test fun rejectsClientAndPayloadMismatch() {
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(client = "mac")) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(payloadClient = "mac")) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(payloadRevision = 2)) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("client", "mac"))) }
    }

    @Test fun rejectsInvalidEnvelopeSizeNonceAndNonintegerRevision() {
        assertThrows(IllegalArgumentException::class.java) { UpdateEnvelope.decode(ByteArray(1024 * 1024 + 1), bootstrap, 0) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope().put("nonce", Base64.encode(ByteArray(8)))) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope().put("revision", 3.5)) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope().put("revision", 2147483648L)) }
    }

    @Test fun invalidProfileDoesNotReturnApplicableUpdate() {
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().also { it.remove("awg") })) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("version", 3))) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().also {
            it.getJSONObject("vless").put("tcpPort", 0)
        })) }
    }

    @Test fun extraProtocolKeepsIdentityHistoryAndFixedLocalTunnelConfig() {
        val update = decode(envelope(profile().put("extraXray", JSONArray().put(extra()))))
        val custom = update.profile.protocols.last()
        assertEquals("custom-trojan", custom.name)
        assertEquals(custom, Protocol.restored("custom-trojan", update.profile))
        assertEquals(custom.name, Protocol.history(custom.name, custom.title)?.name)
        val config = JSONObject(XrayConfig.build(update.profile, custom, 10808))
        assertEquals(2, config.getJSONArray("inbounds").length())
        assertEquals("127.0.0.1", config.getJSONArray("inbounds").getJSONObject(1).getString("listen"))
        val outbound = config.getJSONArray("outbounds").getJSONObject(0)
        assertEquals("trojan", outbound.getString("protocol"))
        assertEquals("proxy", outbound.getString("tag"))
    }

    @Test fun rejectsUnknownProtocolsDuplicateIdsAndDangerousFields() {
        val unknown = extra().also { it.getJSONObject("outbound").put("protocol", "future-protocol") }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONArray().put(unknown)))) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONArray().put(extra()).put(extra())))) }
        for (field in listOf("certificateFile", "keyFile", "masterKeyLog", "sslKeyLogFile", "sockopt", "proxySettings", "sendThrough", "script")) {
            val e = extra().also { it.getJSONObject("outbound").getJSONObject("streamSettings").put(field, "forbidden") }
            assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONArray().put(e)))) }
        }
    }

    @Test fun rejectsDisabledTlsVerificationAndExcessiveNesting() {
        val e = extra().also { it.getJSONObject("outbound").getJSONObject("streamSettings")
            .getJSONObject("tlsSettings").put("allowInsecure", true) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONArray().put(e)))) }
        assertThrows(IllegalArgumentException::class.java) { JsonBounds.objectFrom("{\"x\":".repeat(30) + "0" + "}".repeat(30)) }
    }

    @Test fun bootstrapRequiresHttpsCorrectDeviceKeyAndIntegerFloor() {
        val b = JSONObject().put("format", "myvpn-bootstrap-v1").put("client", "android")
            .put("url", "https://example.org/update.json").put("key", Base64.encode(key)).put("minRevision", 1)
        assertEquals(32, UpdateBootstrap.parse(b.toString()).key.size)
        assertThrows(IllegalArgumentException::class.java) { UpdateBootstrap.parse(b.put("url", "http://example.org").toString()) }
    }
    @Test fun rejectsMalformedExtraListAndMissingNativeServer() {
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONObject()))) }
        val broken = extra().also { it.getJSONObject("outbound").put("settings", JSONObject()) }
        assertThrows(IllegalArgumentException::class.java) { decode(envelope(profile().put("extraXray", JSONArray().put(broken)))) }
    }

    @Test fun unavailableXrayFallsBackToSameHttpsFeedWithoutChangingAuthentication() {
        val ports = mutableListOf<Int>()
        val bytes = envelope(revision = 4).toString().toByteArray()
        val update = ProfileUpdater.download(bootstrap, 3, 10808) { url, port ->
            assertEquals(bootstrap.url, url)
            ports += port
            if (port != 0) throw SocketTimeoutException()
            bytes
        }
        assertEquals(listOf(10808, 0), ports)
        assertEquals(4, update.revision)
    }

    @Test fun workingVpnFeedIsPreferredAndDirectFailureIsNotRetried() {
        val ports = mutableListOf<Int>()
        ProfileUpdater.download(bootstrap, 0, 10808) { _, port ->
            ports += port
            envelope().toString().toByteArray()
        }
        assertEquals(listOf(10808), ports)
        ports.clear()
        val error = assertThrows(IllegalStateException::class.java) {
            ProfileUpdater.download(bootstrap, 0, 0) { _, port ->
                ports += port
                throw IOException("private-network-details")
            }
        }
        assertEquals(listOf(0), ports)
        assertFalse(error.message.orEmpty().contains("private-network-details"))
    }

    @Test fun authenticationRollbackAndHttpFailuresNeverTriggerDirectFallback() {
        val invalid = listOf(
            "{}".toByteArray(),
            envelope(revision = 2).toString().toByteArray(),
            envelope().put("revision", 4).toString().toByteArray(),
        )
        for (bytes in invalid) {
            var requests = 0
            assertThrows(IllegalArgumentException::class.java) {
                ProfileUpdater.download(bootstrap, 3, 10808) { _, _ -> requests++; bytes }
            }
            assertEquals(1, requests)
        }
        var requests = 0
        assertThrows(IllegalArgumentException::class.java) {
            ProfileUpdater.download(bootstrap, 3, 10808) { _, _ ->
                requests++
                throw IllegalArgumentException("HTTP error")
            }
        }
        assertEquals(1, requests)
    }

    @Test fun localPublisherEnvelopeWhenExplicitlyRequested() {
        org.junit.Assume.assumeTrue(System.getenv("MYVPN_VERIFY_LOCAL_FEED") == "1")
        val root = java.io.File("../..").canonicalFile
        val localBootstrap = UpdateBootstrap.parse(java.io.File(root, "config/android-update.json").readText())
        val update = UpdateEnvelope.decode(java.io.File(root, "updates/android.json").readBytes(), localBootstrap, 0)
        val expected = Profile.parse(java.io.File(root, "config/android.json").readText())
        fun plain(value: Any?): Any? = when (value) {
            is JSONObject -> value.keys().asSequence().associateWith { plain(value.get(it)) }
            is JSONArray -> (0 until value.length()).map { plain(value.get(it)) }
            else -> value
        }
        assertTrue("Publisher and Android profile differ", plain(expected.json) == plain(update.profile.json))
        assertTrue(update.revision >= localBootstrap.minRevision)
    }

}
