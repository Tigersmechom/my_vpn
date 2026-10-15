package app.myvpn

import android.app.Application
import android.os.Build
import java.io.File

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // В процессе :xray контроллер не нужен — там работает только XrayVpnService
        if (!processName().endsWith(":xray")) VpnController.init(this)
    }

    private fun processName(): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) getProcessName()
        else runCatching { File("/proc/self/cmdline").readText().trim('\u0000', ' ') }.getOrDefault("")
}
