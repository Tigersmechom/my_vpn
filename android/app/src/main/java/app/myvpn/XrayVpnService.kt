package app.myvpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import go.Seq
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.Libv2ray
import java.net.ServerSocket
import java.util.concurrent.Executors

/**
 * VPN на ядре Xray (процесс :xray). Xray сам читает пакеты из TUN (встроенный tun-inbound),
 * а чтобы его собственные соединения к серверу не уходили обратно в туннель,
 * приложение целиком исключено из VPN (addDisallowedApplication).
 */
class XrayVpnService : VpnService() {

    private val worker = Executors.newSingleThreadExecutor()
    private var tun: ParcelFileDescriptor? = null
    private var core: CoreController? = null
    private var protocol: Protocol? = null
    private var activeHost = ""
    private var socksPort = 0
    private var state = STATE_DOWN
    private var error: String? = null

    private val queryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = broadcastStatus()
    }

    override fun onCreate() {
        super.onCreate()
        ContextCompat.registerReceiver(
            this, queryReceiver, IntentFilter(ACTION_QUERY), ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val profile = Profile.parse(intent.getStringExtra(EXTRA_PROFILE)!!)
                val proto = Protocol.restored(intent.getStringExtra(EXTRA_PROTOCOL), profile)
                goForeground(proto)
                worker.execute { start(profile, proto) }
            }
            ACTION_STOP -> worker.execute { stop(null) }
            // Запуск системой (always-on VPN) не поддерживаем: нет выбранного профиля.
            else -> stopSelf()
        }
        return START_NOT_STICKY
    }

    private fun start(profile: Profile, proto: Protocol) {
        shutdownCore()
        protocol = proto
        activeHost = profile.host
        error = null
        setState(STATE_CONNECTING)
        try {
            ensureCoreEnv(this)
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(MTU)
                .addAddress("10.111.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDisallowedApplication(packageName)
            // IPv6-адрес не добавляем: тогда Android блокирует IPv6 целиком и он не утекает мимо туннеля.
            profile.dnsServers.forEach { runCatching { builder.addDnsServer(it) } }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

            val fd = builder.establish() ?: error("Нет разрешения на VPN")
            tun = fd
            socksPort = freePort()
            val controller = Libv2ray.newCoreController(Callback)
            controller.startLoop(XrayConfig.build(profile, proto, socksPort), fd.fd)
            check(controller.isRunning) { "Ядро Xray не запустилось" }
            core = controller
            setState(STATE_UP)
            goForeground(proto, started = true)
        } catch (e: Throwable) {
            Log.e(TAG, "Xray start failed: ${e.javaClass.simpleName}")
            stop("Не удалось запустить VPN. Проверьте профиль и разрешение VPN.")
        }
    }

    private fun stop(reason: String?) {
        shutdownCore()
        error = reason
        setState(STATE_DOWN)
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun shutdownCore() {
        core?.let { runCatching { it.stopLoop() }.onFailure { e -> Log.w(TAG, "stopLoop", e) } }
        core = null
        runCatching { tun?.close() }
        tun = null
        socksPort = 0
    }

    override fun onRevoke() {
        // Пользователь включил другой VPN или отозвал разрешение
        worker.execute { stop(null) }
    }

    override fun onDestroy() {
        unregisterReceiver(queryReceiver)
        shutdownCore()
        if (state != STATE_DOWN) setState(STATE_DOWN)
        worker.shutdown()
        super.onDestroy()
    }

    private fun setState(s: String) {
        state = s
        broadcastStatus()
    }

    private fun broadcastStatus() {
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName)
                .putExtra(EXTRA_STATE, state)
                .putExtra(EXTRA_PROTOCOL, protocol?.name)
                .putExtra(EXTRA_TITLE, protocol?.title)
                .putExtra(EXTRA_HOST, activeHost)
                .putExtra(EXTRA_SOCKS, socksPort)
                .putExtra(EXTRA_ERROR, error)
        )
    }

    private fun goForeground(proto: Protocol, started: Boolean = false) {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, XrayVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(if (started) "Туннель запущен: ${proto.title}" else "Запуск: ${proto.title}")
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Отключить", stop)
            .build()
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID, notification,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
        )
    }

    private object Callback : CoreCallbackHandler {
        override fun startup(): Long = 0
        override fun shutdown(): Long = 0
        override fun onEmitStatus(code: Long, message: String?): Long {
            Log.i(TAG, "core status: $code")
            return 0
        }
    }

    companion object {
        const val MTU = 1500

        const val ACTION_START = "app.myvpn.xray.START"
        const val ACTION_STOP = "app.myvpn.xray.STOP"
        const val ACTION_QUERY = "app.myvpn.xray.QUERY"
        const val ACTION_STATUS = "app.myvpn.xray.STATUS"

        const val EXTRA_PROFILE = "profile"
        const val EXTRA_PROTOCOL = "protocol"
        const val EXTRA_TITLE = "title"
        const val EXTRA_HOST = "host"
        const val EXTRA_STATE = "state"
        const val EXTRA_SOCKS = "socks"
        const val EXTRA_ERROR = "error"

        const val STATE_DOWN = "DOWN"
        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_UP = "UP"

        private const val TAG = "XrayVpnService"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1

        @Volatile
        private var coreEnvReady = false

        private fun ensureCoreEnv(context: Context) {
            if (coreEnvReady) return
            Seq.setContext(context.applicationContext)
            Libv2ray.initCoreEnv(context.filesDir.absolutePath, "")
            coreEnvReady = true
        }

        private fun freePort(): Int = ServerSocket(0).use { it.localPort }
    }
}
