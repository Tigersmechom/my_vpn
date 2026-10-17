package app.myvpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

internal data class ProbeTarget(val title: String, val url: String, val expectedStatus: Int, val expectedBytes: Int)
internal data class ProbeResponse(val status: Int, val bytes: Int)
internal fun interface ProbeTransport { fun request(target: ProbeTarget, proxy: Proxy): ProbeResponse }
internal class ProbeTransferException(val transferred: Int, cause: IOException) : IOException(cause)

internal enum class ProbeFailure { TIMEOUT, DNS, TLS, NETWORK, HTTP_STATUS, INCOMPLETE, OVERSIZED }

internal data class ProbeResult(
    val title: String,
    val bytes: Int,
    val failure: ProbeFailure? = null,
    val status: Int? = null,
) {
    val passed get() = failure == null
    val message: String get() = when (failure) {
        null -> if (bytes == 0) "$title: HTTPS отвечает" else "$title: получены все 64 КиБ"
        ProbeFailure.TIMEOUT -> if (bytes > 0) "$title: тайм-аут после $bytes байт" else "$title: нет ответа за отведённое время"
        ProbeFailure.DNS -> "$title: не удалось определить адрес"
        ProbeFailure.TLS -> "$title: не удалось проверить HTTPS-соединение"
        ProbeFailure.NETWORK -> if (bytes > 0) "$title: соединение прервалось после $bytes байт" else "$title: соединение не удалось"
        ProbeFailure.HTTP_STATUS -> "$title: неожиданный HTTP-ответ ($status)"
        ProbeFailure.INCOMPLETE -> "$title: получен неполный ответ ($bytes байт)"
        ProbeFailure.OVERSIZED -> "$title: ответ больше ожидаемого"
    }
}

internal data class DiagnosticReport(val results: List<ProbeResult>) {
    val summary: String get() = when (results.count { it.passed }) {
        results.size -> "HTTPS работает, загрузка 64 КиБ прошла. Это проверка доступности, а не скорости."
        0 -> "Проверки не прошли. Запущенный туннель ещё не означает, что сайты доступны."
        else -> "Часть проверок не прошла. Ниже видно, на каком запросе возникла проблема."
    }
}

/** Проверяет текущий путь, не меняя профиль, маршруты или состояние VPN. */
internal object ConnectionDiagnostics {
    private val targets = listOf(
        ProbeTarget("Google", "https://www.google.com/generate_204", 204, 0),
        ProbeTarget("Cloudflare", "https://speed.cloudflare.com/__down?bytes=65536", 200, 65536),
    )

    suspend fun check(status: VpnStatus): DiagnosticReport = withContext(Dispatchers.IO) {
        run(status, HttpsProbeTransport)
    }

    internal fun run(status: VpnStatus, transport: ProbeTransport): DiagnosticReport {
        require(status.state == VpnState.UP && status.protocol != null) { "Сначала включите VPN" }
        val proxy = if (status.protocol.usesXray) {
            require(status.socksPort in 1..65535) { "Локальный порт VPN пока недоступен" }
            Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", status.socksPort))
        } else Proxy.NO_PROXY // AmneziaWG включает приложение в системный VPN.
        return DiagnosticReport(targets.map { target ->
            try {
                val response = transport.request(target, proxy)
                val failure = when {
                    response.status != target.expectedStatus -> ProbeFailure.HTTP_STATUS
                    response.bytes < target.expectedBytes -> ProbeFailure.INCOMPLETE
                    response.bytes > target.expectedBytes -> ProbeFailure.OVERSIZED
                    else -> null
                }
                ProbeResult(target.title, response.bytes, failure, response.status)
            } catch (e: IOException) {
                val cause = if (e is ProbeTransferException) e.cause else e
                val failure = when (cause) {
                    is SocketTimeoutException -> ProbeFailure.TIMEOUT
                    is UnknownHostException -> ProbeFailure.DNS
                    is SSLException -> ProbeFailure.TLS
                    else -> ProbeFailure.NETWORK
                }
                ProbeResult(target.title, (e as? ProbeTransferException)?.transferred ?: 0, failure)
            }
        })
    }

    fun sameConnection(before: VpnStatus, after: VpnStatus): Boolean =
        before.state == VpnState.UP && after.state == VpnState.UP &&
            before.since == after.since && before.socksPort == after.socksPort &&
            before.protocol?.name == after.protocol?.name && before.host == after.host
}

private object HttpsProbeTransport : ProbeTransport {
    private const val DEADLINE_SECONDS = 12L
    private val deadlines = Executors.newSingleThreadScheduledExecutor { task ->
        Thread(task, "vpn-probe-deadline").apply { isDaemon = true }
    }

    override fun request(target: ProbeTarget, proxy: Proxy): ProbeResponse {
        val connection = URL(target.url).openConnection(proxy) as HttpsURLConnection
        val expired = AtomicBoolean(false)
        val deadline = deadlines.schedule({
            expired.set(true)
            connection.disconnect()
        }, DEADLINE_SECONDS, TimeUnit.SECONDS)
        var transferred = 0
        try {
            connection.connectTimeout = 5_000
            connection.readTimeout = 5_000
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept-Encoding", "identity")
            connection.setRequestProperty("User-Agent", "MyVPN-connectivity-check")
            val code = connection.responseCode
            if (code != target.expectedStatus || code == HttpURLConnection.HTTP_NO_CONTENT) {
                return ProbeResponse(code, 0)
            }
            connection.inputStream.use { input ->
                val buffer = ByteArray(4096)
                // At most the requested size + one byte: enough to reject an unexpected body.
                while (transferred <= target.expectedBytes) {
                    if (expired.get()) throw SocketTimeoutException()
                    val count = input.read(buffer, 0, minOf(buffer.size, target.expectedBytes + 1 - transferred))
                    if (count < 0) break
                    transferred += count
                }
            }
            return ProbeResponse(code, transferred)
        } catch (e: IOException) {
            throw ProbeTransferException(transferred, if (expired.get()) SocketTimeoutException() else e)
        } finally {
            deadline.cancel(false)
            connection.disconnect()
        }
    }
}
