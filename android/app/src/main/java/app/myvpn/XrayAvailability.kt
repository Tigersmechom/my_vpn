package app.myvpn

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ResultReceiver
import go.Seq
import libv2ray.Libv2ray
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.concurrent.Executors
import kotlin.coroutines.resume

/** A distinct process keeps the Xray Go runtime separate from the AWG backend and VPN service. */
class XrayProbeService : Service() {
    private val worker = Executors.newSingleThreadExecutor()
    private var initialized = false
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val receiver = if (Build.VERSION.SDK_INT >= 33) intent?.getParcelableExtra("reply", ResultReceiver::class.java)
            else @Suppress("DEPRECATION") (intent?.getParcelableExtra("reply") as? ResultReceiver)
        val config = intent?.getStringExtra("config")
        if (receiver == null || config == null || config.toByteArray().size > 262_144) { stopSelf(); return START_NOT_STICKY }
        worker.execute {
            val delay = runCatching {
                if (!initialized) {
                    Seq.setContext(applicationContext)
                    Libv2ray.initCoreEnv(filesDir.absolutePath, "")
                    initialized = true
                }
                Libv2ray.measureOutboundDelay(config, "https://www.google.com/generate_204")
            }.getOrDefault(-1L)
            runCatching { receiver.send(0, Bundle().apply { putLong("delay", delay) }) }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        worker.shutdownNow()
        super.onDestroy()
        // Killing this dedicated process also closes any native network work on cancellation.
        android.os.Process.killProcess(android.os.Process.myPid())
    }

}

class XrayAvailability(private val context: Context) {
    private data class Sample(val ok: Boolean, val ms: Int)
    private data class History(val fingerprint: String, val values: MutableList<Sample>)
    private val history = mutableMapOf<String, History>()
    @Volatile private var stopped = false
    fun stop() { stopped = true; context.stopService(Intent(context, XrayProbeService::class.java)) }

    suspend fun check(profile: Profile, protocol: Protocol): AvailabilityResult {
        val config = JSONObject(XrayConfig.build(profile, protocol, 0))
        config.remove("inbounds")
        config.remove("routing")
        // A single proxy outbound: failed probes cannot silently fall back to the local internet.
        config.put("outbounds", JSONArray().put(config.getJSONArray("outbounds").getJSONObject(0)))
        val text = config.toString()
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(text.toByteArray()).joinToString("") { "%02x".format(it) }
        val state = history[protocol.name]?.takeIf { it.fingerprint == fingerprint }
            ?: History(fingerprint, mutableListOf()).also { history[protocol.name] = it }
        var delay = -1L
        try {
            delay = withTimeout(15_000) {
                suspendCancellableCoroutine { continuation ->
                    continuation.invokeOnCancellation { context.stopService(Intent(context, XrayProbeService::class.java)) }
                    if (stopped) { continuation.cancel(); return@suspendCancellableCoroutine }
                    val receiver = object : ResultReceiver(Handler(Looper.getMainLooper())) {
                        override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                            if (continuation.isActive) continuation.resume(resultData?.getLong("delay", -1) ?: -1)
                        }
                    }
                    try { context.startService(Intent(context, XrayProbeService::class.java).putExtra("config", text).putExtra("reply", receiver)) }
                    catch (_: Exception) { if (continuation.isActive) continuation.resume(-1L) }
                }
            }
        } catch (e: CancellationException) {
            if (!currentCoroutineContext().isActive) throw e
        }
        val ok = delay in 0..60_000
        state.values.add(Sample(ok, delay.coerceIn(0, 60_000).toInt()))
        if (state.values.size > 5) state.values.removeAt(0)
        val successful = state.values.filter { it.ok }.map { it.ms }
        val grade = when {
            ok && delay < 250 && successful.size == state.values.size -> "green"
            !ok && state.values.size >= 2 && !state.values[state.values.lastIndex - 1].ok -> "red"
            else -> "yellow"
        }
        return AvailabilityResult(grade, if (ok) "ok" else "unreachable", delay.coerceAtLeast(0).toInt(),
            (successful.maxOrNull() ?: 0) - (successful.minOrNull() ?: 0), successful.size, state.values.size, System.currentTimeMillis())
    }
}
