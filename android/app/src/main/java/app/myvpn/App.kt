package app.myvpn

import android.app.Application
import android.os.Build
import java.io.File

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        // Native probe and VPN processes have their own runtimes and no main-process controller.
        if (processName() == packageName) VpnController.init(this)
    }

    private fun processName(): String =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) getProcessName()
        else runCatching { File("/proc/self/cmdline").readText().trim('\u0000', ' ') }.getOrDefault("")
}
