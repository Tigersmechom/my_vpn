package app.myvpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import org.amnezia.awg.backend.BackendException
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.NoopTunnelActionHandler
import org.amnezia.awg.backend.Tunnel

enum class VpnState { DOWN, CONNECTING, UP }

data class VpnStatus(
    val state: VpnState = VpnState.DOWN,
    val protocol: Protocol? = null,
    val error: String? = null,
    /** Порт локального SOCKS Xray — через него идёт тест скорости в режимах VLESS. */
    val socksPort: Int = 0,
    val since: Long = 0,
    val host: String = "",
)

/**
 * Единая точка управления подключением (основной процесс).
 * VLESS — через XrayVpnService в процессе :xray, AmneziaWG — через GoBackend прямо здесь.
 */
object VpnController {
    private const val TAG = "VpnController"

    private val _status = MutableStateFlow(VpnStatus())
    val status: StateFlow<VpnStatus> = _status

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private lateinit var app: Context

    private val backend by lazy { GoBackend(app, NoopTunnelActionHandler()) }
    private var wgUp = false

    private var xrayState = XrayVpnService.STATE_DOWN
    private var xrayDown: CompletableDeferred<Unit>? = null

    private val tunnel = object : Tunnel {
        override fun getName() = "myvpn"
        override fun isIpv4ResolutionPreferred() = true
        override fun isMetered() = false
        override fun onStateChange(newState: Tunnel.State) {
            Log.i(TAG, "wg state: $newState")
            if (newState == Tunnel.State.DOWN && wgUp) {
                wgUp = false
                if (_status.value.protocol?.usesXray == false) _status.value = VpnStatus()
            }
        }
    }

    private val xrayReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val state = intent.getStringExtra(XrayVpnService.EXTRA_STATE) ?: return
            val proto = intent.getStringExtra(XrayVpnService.EXTRA_PROTOCOL)?.let {
                _status.value.protocol?.takeIf { active -> active.name == it }
                    ?: Protocol.history(it, intent.getStringExtra(XrayVpnService.EXTRA_TITLE).orEmpty())
            }
            xrayState = state
            if (state == XrayVpnService.STATE_DOWN) xrayDown?.complete(Unit)

            // Не перетираем статус, если сейчас активен AmneziaWG
            val current = _status.value
            if (current.protocol != null && current.protocol.usesXray != true) return
            _status.value = when (state) {
                XrayVpnService.STATE_UP -> VpnStatus(
                    VpnState.UP, proto, socksPort = intent.getIntExtra(XrayVpnService.EXTRA_SOCKS, 0),
                    since = if (current.state == VpnState.UP) current.since else System.currentTimeMillis(),
                    host = intent.getStringExtra(XrayVpnService.EXTRA_HOST).orEmpty(),
                )
                XrayVpnService.STATE_CONNECTING -> VpnStatus(VpnState.CONNECTING, proto, host = intent.getStringExtra(XrayVpnService.EXTRA_HOST).orEmpty())
                else -> VpnStatus(VpnState.DOWN, proto, error = intent.getStringExtra(XrayVpnService.EXTRA_ERROR))
            }
        }
    }

    fun init(context: Context) {
        app = context.applicationContext
        ContextCompat.registerReceiver(
            app, xrayReceiver, IntentFilter(XrayVpnService.ACTION_STATUS), ContextCompat.RECEIVER_NOT_EXPORTED
        )
        // Если процесс :xray уже работает (UI перезапускался) — он ответит своим статусом
        app.sendBroadcast(Intent(XrayVpnService.ACTION_QUERY).setPackage(app.packageName))
    }

    fun connect(profile: Profile, protocol: Protocol) {
        scope.launch {
            mutex.withLock {
                stopAll()
                _status.value = VpnStatus(VpnState.CONNECTING, protocol, host = profile.host)
                if (protocol.usesXray) {
                    val intent = Intent(app, XrayVpnService::class.java)
                        .setAction(XrayVpnService.ACTION_START)
                        .putExtra(XrayVpnService.EXTRA_PROFILE, profile.toString())
                        .putExtra(XrayVpnService.EXTRA_PROTOCOL, protocol.name)
                    ContextCompat.startForegroundService(app, intent)
                } else {
                    try {
                        backend.setState(tunnel, Tunnel.State.UP, AwgConfig.build(profile))
                        wgUp = true
                        _status.value = VpnStatus(VpnState.UP, protocol, since = System.currentTimeMillis(), host = profile.host)
                    } catch (e: Throwable) {
                        Log.e(TAG, "AmneziaWG connection failed: ${e.javaClass.simpleName}")
                        _status.value = VpnStatus(VpnState.DOWN, protocol, error = describe(e))
                    }
                }
            }
        }
    }

    fun disconnect() {
        scope.launch {
            mutex.withLock {
                stopAll()
                _status.value = VpnStatus()
            }
        }
    }

    private suspend fun stopAll() {
        if (wgUp) {
            wgUp = false
            runCatching { backend.setState(tunnel, Tunnel.State.DOWN, null) }
                .onFailure { Log.w(TAG, "wg down", it) }
        }
        if (xrayState != XrayVpnService.STATE_DOWN) {
            val done = CompletableDeferred<Unit>().also { xrayDown = it }
            app.startService(Intent(app, XrayVpnService::class.java).setAction(XrayVpnService.ACTION_STOP))
            withTimeoutOrNull(5000) { done.await() }
            xrayDown = null
        }
    }

    private fun describe(e: Throwable): String = when (e) {
        is BackendException -> when (e.reason) {
            BackendException.Reason.VPN_NOT_AUTHORIZED -> "Нет разрешения на VPN"
            BackendException.Reason.DNS_RESOLUTION_FAILURE -> "Не удалось найти адрес сервера"
            else -> "Ошибка туннеля: ${e.reason}"
        }
        else -> "Не удалось подключиться. Проверьте профиль и доступность сервера."
    }
}
