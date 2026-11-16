package app.myvpn

import org.json.JSONArray
import org.json.JSONObject

/** A route carries data for existing cores only; nested routes and country catalogs are rejected. */
object RouteValidation {
    fun validate(json: JSONObject) {
        if (json.has("probeAwg")) {
            val probe = json.getJSONObject("probeAwg")
            require(probe.keys().asSequence().toSet() == setOf("privateKey", "presharedKey", "address")) { "Некорректные ключи проверки" }
            for (key in listOf("privateKey", "presharedKey")) {
                require(runCatching { kotlin.io.encoding.Base64.decode(probe.getString(key)).size == 32 }.getOrDefault(false)) { "Некорректный ключ проверки" }
            }
            val address = probe.getString("address")
            require(address.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}/32")) &&
                address.substringBefore('/').split('.').all { it.toInt() <= 255 }) { "Некорректный адрес проверки" }
            val awg = json.getJSONObject("awg")
            require(probe.getString("privateKey") != awg.getString("privateKey") && address.substringBefore('/') != awg.getString("address").substringBefore('/')) { "Для проверки нужен отдельный ключ" }
        }
        if (json.has("enabledProtocols")) {
            val list = json.optJSONArray("enabledProtocols") ?: error("Некорректный список протоколов")
            val ids = (0 until list.length()).map { list.getString(it) }
            require(ids.isNotEmpty() && ids.size <= 4 && ids.distinct().size == ids.size &&
                ids.all { id -> Protocol.entries.any { it.name == id } } &&
                ids.any { id -> Protocol.supported.any { it.name == id } }) { "Некорректный список протоколов" }
        }
        require(!json.has("additionalServers")) { "Эта Android-сборка не использует каталог стран" }
        if (!json.has("routes")) return
        val routes = json.optJSONArray("routes") ?: error("Некорректные маршруты")
        require(routes.length() in 1..8) { "Некорректное число маршрутов" }
        val ids = mutableSetOf<String>()
        for (i in 0 until routes.length()) {
            val route = routes.getJSONObject(i)
            require(route.keys().asSequence().toSet() == setOf("id", "title", "profile")) { "Некорректный маршрут" }
            val id = route.getString("id")
            val title = route.getString("title")
            require(id.matches(Regex("[A-Za-z0-9_-]{1,32}")) && ids.add(id)) { "Некорректный ID маршрута" }
            require(title.isNotBlank() && title.length <= 80 && title.none { it.code < 32 || it.code == 127 }) { "Некорректное название маршрута" }
            val candidate = route.getJSONObject("profile")
            require(!candidate.has("routes") && !candidate.has("additionalServers") &&
                candidate.getString("client") == json.getString("client")) { "Некорректный профиль маршрута" }
            require(candidate.get("version") is Int && candidate.getInt("version") == 2) { "Некорректная версия маршрута" }
            val profile = Profile.parse(candidate.toString())
            ProfileValidation.requireComplete(profile)
        }
    }
}
