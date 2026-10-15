package app.myvpn

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

data class SpeedResult(
    val protocol: Protocol,
    val time: Long,
    val pingMs: Int,
    val downMbps: Double,
    val upMbps: Double,
    val exitIp: String,
) {
    val label get() = protocol.title
}

/** Настройки приложения: текущий профиль, выбранный протокол, история замеров скорости. */
class Store internal constructor(
    private val prefs: SharedPreferences,
    private val loadDefault: () -> Profile,
    private val loadBootstrap: () -> UpdateBootstrap?,
) {
    constructor(context: Context) : this(
        context.applicationContext.getSharedPreferences("myvpn", Context.MODE_PRIVATE),
        { Profile.parse(context.applicationContext.assets.open("default_profile.json").bufferedReader().use { it.readText() }) },
        { kotlin.runCatching {
            context.applicationContext.assets.open("update_bootstrap.json").bufferedReader().use { UpdateBootstrap.parse(it.readText()) }
        }.getOrNull() },
    )

    val defaultProfile: Profile by lazy(loadDefault)

    var profile: Profile
        get() {
            val stored = prefs.getString(KEY_PROFILE, null) ?: return defaultProfile
            val migrated = runCatching { Profile.parse(stored) }.getOrNull() ?: return defaultProfile
            if (migrated.toString() != stored) prefs.edit().putString(KEY_PROFILE, migrated.toString()).apply()
            return migrated
        }
        set(value) = prefs.edit().putString(KEY_PROFILE, value.toString()).apply()

    fun resetProfile() {
        val remote = prefs.getString(KEY_REMOTE_PROFILE, null)?.let { runCatching { Profile.parse(it) }.getOrNull() }
        if (remote != null) profile = remote else prefs.edit().remove(KEY_PROFILE).apply()
    }

    val bootstrap: UpdateBootstrap? by lazy(loadBootstrap)

    val appliedRevision: Int get() = prefs.getInt(KEY_REVISION, 0)

    /** Профиль и номер обновления записываем одной транзакцией, активный VPN не трогаем. */
    @Synchronized
    fun applyUpdate(update: ProfileUpdate): Boolean {
        require(update.revision >= appliedRevision) { "Получено устаревшее обновление" }
        if (update.revision == appliedRevision) return false
        val previousProfile = prefs.getString(KEY_PROFILE, null)
        val previousRevision = appliedRevision
        val previousRemote = prefs.getString(KEY_REMOTE_PROFILE, null)
        if (!prefs.edit().putString(KEY_PROFILE, update.profile.toString())
                .putString(KEY_REMOTE_PROFILE, update.profile.toString())
                .putInt(KEY_REVISION, update.revision).commit()) {
            // SharedPreferences обновляет память даже при ошибке записи на диск.
            prefs.edit().putString(KEY_PROFILE, previousProfile).putString(KEY_REMOTE_PROFILE, previousRemote)
                .putInt(KEY_REVISION, previousRevision).commit()
            error("Не удалось сохранить обновление")
        }
        return true
    }

    var protocol: Protocol
        get() = Protocol.restored(prefs.getString(KEY_PROTOCOL, null), profile)
        set(value) = prefs.edit().putString(KEY_PROTOCOL, value.name).apply()

    fun results(): List<SpeedResult> {
        val arr = runCatching { JSONArray(prefs.getString(KEY_RESULTS, "[]")) }.getOrElse { JSONArray() }
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            // Старые замеры через посредника не смешиваем с прямым подключением.
            if (o.optBoolean("relay")) return@mapNotNull null
            runCatching {
                SpeedResult(
                    Protocol.history(o.getString("protocol"), o.optString("title")) ?: return@mapNotNull null, o.getLong("time"), o.getInt("ping"),
                    o.getDouble("down"), o.getDouble("up"), o.optString("ip"),
                )
            }.getOrNull()
        }
    }

    fun addResult(r: SpeedResult) {
        val list = listOf(r) + results().take(MAX_RESULTS - 1)
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject()
                    .put("protocol", it.protocol.name).put("title", it.protocol.title).put("time", it.time).put("ping", it.pingMs)
                    .put("down", it.downMbps).put("up", it.upMbps).put("ip", it.exitIp)
            )
        }
        prefs.edit().putString(KEY_RESULTS, arr.toString()).apply()
    }

    fun clearResults() = prefs.edit().remove(KEY_RESULTS).apply()

    private companion object {
        const val KEY_REMOTE_PROFILE = "verified_remote_profile"
        const val KEY_REVISION = "update_revision"
        const val KEY_PROFILE = "profile"
        const val KEY_PROTOCOL = "protocol"
        const val KEY_RESULTS = "results"
        const val MAX_RESULTS = 30
    }
}
