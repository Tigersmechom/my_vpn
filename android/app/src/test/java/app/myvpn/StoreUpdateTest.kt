package app.myvpn

import android.content.SharedPreferences
import org.junit.Assert.*
import org.junit.Test

class StoreUpdateTest {
    private fun profile(host: String) = Profile.parse("""{"version":2,"host":"$host","vless":{}}""")
    private fun store(prefs: MemoryPreferences = MemoryPreferences()) = Store(prefs, { profile("192.0.2.1") }, { null })

    @Test fun resetRestoresLastAuthenticatedProfileWithoutLoweringRevision() {
        val store = store()
        assertTrue(store.applyUpdate(ProfileUpdate(7, profile("192.0.2.2"))))
        store.profile = profile("192.0.2.3")
        store.resetProfile()
        assertEquals("192.0.2.2", store.profile.host)
        assertEquals(7, store.appliedRevision)
        assertFalse(store.applyUpdate(ProfileUpdate(7, profile("192.0.2.2"))))
        assertEquals("192.0.2.2", store.profile.host)
        assertThrows(IllegalArgumentException::class.java) { store.applyUpdate(ProfileUpdate(6, profile("192.0.2.4"))) }
    }

    @Test fun manualRefreshRepairsSameRevisionWithoutRollbackOrChangingSnapshot() {
        val store = store()
        val update = ProfileUpdate(7, profile("192.0.2.2"))
        store.applyUpdate(update)
        store.profile = profile("edited.example")
        val activeSnapshot = store.profile
        assertFalse(store.applyUpdate(update))
        assertEquals("edited.example", store.profile.host)
        assertTrue(store.applyUpdate(update, repair = true))
        assertEquals("192.0.2.2", store.profile.host)
        assertEquals("edited.example", activeSnapshot.host)
        assertFalse(store.applyUpdate(update, repair = true))
        assertThrows(IllegalArgumentException::class.java) { store.applyUpdate(ProfileUpdate(6, profile("old.example")), repair = true) }
    }

    @Test fun failedDiskWriteRestoresProfileSnapshotAndRevision() {
        val prefs = MemoryPreferences()
        val store = store(prefs)
        store.applyUpdate(ProfileUpdate(2, profile("192.0.2.2")))
        prefs.failNextCommit = true
        assertThrows(IllegalStateException::class.java) { store.applyUpdate(ProfileUpdate(3, profile("192.0.2.3"))) }
        assertEquals(2, store.appliedRevision)
        assertEquals("192.0.2.2", store.profile.host)
        store.resetProfile()
        assertEquals("192.0.2.2", store.profile.host)
    }

    @Test fun resetBeforeAnyRemoteUpdateRestoresBundledProfile() {
        val store = store()
        store.profile = profile("192.0.2.3")
        store.resetProfile()
        assertEquals("192.0.2.1", store.profile.host)
        assertEquals(0, store.appliedRevision)
    }

    @Test fun removedModeFallsBackAndRetiredHistoryIsHidden() {
        val store = store()
        store.protocol = Protocol.VLESS_TCP
        store.addResult(SpeedResult(Protocol.VLESS_TCP, 1, 10, 20.0, 30.0, "192.0.2.2"))
        assertEquals(Protocol.HY2, store.protocol)
        assertTrue(store.results().isEmpty())
    }

}

/** Models Android's commit behavior: in-memory state changes even if disk write fails. */
internal class MemoryPreferences : SharedPreferences {
    private val data = mutableMapOf<String, Any?>()
    var failNextCommit = false
    override fun getAll(): MutableMap<String, *> = data.toMutableMap()
    override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
    override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = key in data
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        private val pending = mutableMapOf<String, Any?>()
        private var clear = false
        override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply { pending[key!!] = value }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = apply { pending[key!!] = values }
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor = apply { pending[key!!] = value }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor = apply { pending[key!!] = value }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = apply { pending[key!!] = value }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = apply { pending[key!!] = value }
        override fun remove(key: String?): SharedPreferences.Editor = apply { pending[key!!] = null }
        override fun clear(): SharedPreferences.Editor = apply { clear = true }
        override fun apply() { commit() }
        override fun commit(): Boolean {
            if (clear) data.clear()
            for ((key, value) in pending) if (value == null) data.remove(key) else data[key] = value
            return (!failNextCommit).also { failNextCommit = false }
        }
    }
}
