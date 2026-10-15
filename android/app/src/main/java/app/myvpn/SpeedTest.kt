package app.myvpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import kotlin.random.Random

/**
 * Простой тест скорости через speed.cloudflare.com: пинг (время HTTP-запроса по уже открытому
 * соединению), скачивание и отдача по ~10 секунд.
 *
 * В режимах на Xray (VLESS, Hysteria2) приложение исключено из собственного VPN, поэтому тест идёт через локальный
 * SOCKS-порт Xray — это тот же путь до сервера, что и у остального трафика.
 */
object SpeedTest {
    private const val BASE = "https://speed.cloudflare.com"
    private const val PHASE_MS = 10_000L

    suspend fun run(protocol: Protocol, socksPort: Int, progress: (String) -> Unit): SpeedResult =
        withContext(Dispatchers.IO) {
            val proxy = if (socksPort > 0) Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
            else Proxy.NO_PROXY

            fun open(url: String) = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
                connectTimeout = 10_000
                readTimeout = 15_000
                setRequestProperty("User-Agent", "MyVPN-speedtest")
            }

            progress("Проверяю внешний IP…")
            val ip = runCatching {
                open("https://api.ipify.org").inputStream.bufferedReader().use { it.readText().trim() }
            }.getOrDefault("?")

            progress("Пинг…")
            val pings = (0 until 6).map {
                val t0 = System.nanoTime()
                open("$BASE/__down?bytes=0").inputStream.use { it.readBytes() }
                ((System.nanoTime() - t0) / 1_000_000).toInt()
            }.drop(1).sorted() // первый запрос — с TLS-рукопожатием
            val ping = pings[pings.size / 2]

            progress("Скачивание…")
            val down = open("$BASE/__down?bytes=200000000").run {
                val buf = ByteArray(64 * 1024)
                var bytes = 0L
                inputStream.use { input ->
                    val t0 = System.nanoTime()
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        bytes += n
                        if ((System.nanoTime() - t0) / 1_000_000 > PHASE_MS) break
                    }
                    mbps(bytes, System.nanoTime() - t0)
                }.also { disconnect() }
            }

            progress("Отдача…")
            val up = open("$BASE/__up").run {
                requestMethod = "POST"
                doOutput = true
                setChunkedStreamingMode(64 * 1024)
                setRequestProperty("Content-Type", "application/octet-stream")
                val chunk = Random.nextBytes(64 * 1024)
                var bytes = 0L
                val t0 = System.nanoTime()
                outputStream.use { out ->
                    while (bytes < 100_000_000 && (System.nanoTime() - t0) / 1_000_000 < PHASE_MS) {
                        out.write(chunk)
                        bytes += chunk.size
                    }
                }
                responseCode
                mbps(bytes, System.nanoTime() - t0).also { disconnect() }
            }

            SpeedResult(protocol, System.currentTimeMillis(), ping, down, up, ip)
        }

    private fun mbps(bytes: Long, nanos: Long): Double =
        if (nanos <= 0) 0.0 else bytes * 8.0 / (nanos / 1e9) / 1e6
}
