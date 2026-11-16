package app.myvpn

import android.content.Context
import kotlinx.coroutines.suspendCancellableCoroutine
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Result is an end-to-end HTTPS observation, never a guessed bandwidth rating. */
data class AvailabilityResult(val grade: String, val code: String, val rtt: Int, val jitter: Int,
    val successes: Int, val samples: Int, val checkedAt: Long) {
    val label: String get() = if (code == "ok") {
        if (grade == "green") "Хорошее соединение" else "Соединение с задержкой"
    } else if (grade == "red") "Соединение недоступно" else "Требует проверки"
    val detail: String get() {
        val reason = when (code) {
            "ok" -> "$rtt мс · разброс $jitter мс"
            "timeout" -> "Нет ответа за время проверки"
            "certificate" -> "Не прошла проверка сертификата"
            "auth" -> "Сервер отклонил авторизацию"
            "requires_probe_key" -> "Нет отдельного ключа проверки — обновите конфигурацию"
            "http_status" -> "VPN ответил, контрольный сайт недоступен"
            "cancelled" -> "Проверка приостановлена"
            else -> "Не удалось открыть сайт через VPN"
        }
        return "$reason · успешно $successes/$samples"
    }
}

/** Separate, unprivileged process avoids two Go runtimes in the Android VPN process. */
class AvailabilityProcess(private val context: Context) {
    companion object {
        private val active = java.util.concurrent.ConcurrentHashMap.newKeySet<AvailabilityProcess>()
        fun stopAll() { active.toList().forEach { it.stop() } }
    }
    init { active.add(this) }
    private val lock = Any()
    private var child: Process? = null
    private var stopped = false
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "vpn-availability").apply { isDaemon = true } }

    fun stop() {
        synchronized(lock) {
            stopped = true
            child?.destroy()
            child = null
        }
        active.remove(this)
        executor.shutdownNow()
    }

    suspend fun check(profile: Profile): Map<String, AvailabilityResult> = suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { stop() }
        executor.execute {
            try {
                val process = synchronized(lock) {
                    check(!stopped) { "Проверка остановлена" }
                    child ?: run {
                        val ca = exportRoots()
                        ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libmyvpnhealth.so").path,
                            "--ca-file", ca.path).apply {
                            environment()["GOMAXPROCS"] = "2"
                            redirectError(File("/dev/null"))
                        }.start().also { child = it }
                    }
                }
                val routes = JSONArray()
                profile.protocols.filter { it.baseName in setOf("HY2", "HY2_OBFS", "AWG") }.forEach { proto ->
                    routes.put(JSONObject().put("id", proto.name).put("protocol", proto.baseName)
                        .put("profile", JSONObject(profile.connectionProfile(proto).toString())))
                }
                process.outputStream.write((JSONObject().put("routes", routes).toString() + "\n").toByteArray())
                process.outputStream.flush()
                val output = java.io.ByteArrayOutputStream()
                while (output.size() <= 1_048_576) {
                    val value = process.inputStream.read()
                    check(value >= 0) { "Проверка остановлена" }
                    if (value == 10) break
                    output.write(value)
                }
                val reply = JSONObject(output.toString("UTF-8"))
                check(!reply.has("error")) { "Не удалось проверить конфигурацию" }
                val results = reply.getJSONArray("results")
                val parsed = (0 until results.length()).associate { i ->
                    val r = results.getJSONObject(i)
                    r.getString("id") to AvailabilityResult(r.getString("grade"), r.getString("code"), r.getInt("rttMs"),
                        r.getInt("jitterMs"), r.getInt("successes"), r.getInt("samples"), r.getLong("checkedAt"))
                }
                if (continuation.isActive) continuation.resume(parsed)
            } catch (e: Exception) {
                synchronized(lock) { child?.destroy(); child = null }
                if (continuation.isActive) continuation.resumeWithException(IllegalStateException("Проверка временно недоступна"))
            }
        }
    }

    private fun exportRoots(): File {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val certificates = factory.trustManagers.filterIsInstance<X509TrustManager>().flatMap { it.acceptedIssuers.toList() }
        check(certificates.isNotEmpty())
        val pem = certificates.distinctBy { it.serialNumber.toString() + it.issuerX500Principal.name }.joinToString("") {
            "-----BEGIN CERTIFICATE-----\n" + android.util.Base64.encodeToString(it.encoded, android.util.Base64.NO_WRAP)
                .chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----\n"
        }
        return File(context.noBackupFilesDir, "availability-roots.pem").apply { writeText(pem); setReadable(false, false); setReadable(true, true) }
    }
}
