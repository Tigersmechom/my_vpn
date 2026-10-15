package app.myvpn

import android.Manifest
import android.content.ClipboardManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Green = Color(0xFF22C55E)
private val Amber = Color(0xFFF59E0B)

class MainActivity : ComponentActivity() {
    private lateinit var store: Store

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        store = Store(this)
        setContent {
            val dark = isSystemInDarkTheme()
            MaterialTheme(
                colorScheme = if (dark) darkColorScheme(primary = Green, secondary = Green)
                else lightColorScheme(primary = Color(0xFF15803D), secondary = Color(0xFF15803D))
            ) {
                var screen by remember { mutableStateOf("home") }
                when (screen) {
                    "home" -> HomeScreen(store, onSettings = { screen = "settings" })
                    else -> SettingsScreen(store, onBack = { screen = "home" })
                }
            }
        }
    }
}

// ---------- Главный экран ----------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HomeScreen(store: Store, onSettings: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val status by VpnController.status.collectAsState()
    var protocol by remember { mutableStateOf(store.protocol) }
    var profile by remember { mutableStateOf(store.profile) }
    var refreshing by remember { mutableStateOf(false) }
    var refreshMessage by remember { mutableStateOf<String?>(null) }
    val results = remember { mutableStateListOf<SpeedResult>().apply { addAll(store.results()) } }
    var testing by remember { mutableStateOf(false) }
    var testStep by remember { mutableStateOf("") }
    var testError by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun doConnect() = VpnController.connect(store.profile, protocol)

    val notifPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (VpnService.prepare(context) == null) doConnect()
        else Toast.makeText(context, "Без разрешения VPN не запустится", Toast.LENGTH_SHORT).show()
    }

    fun connectWithPermission() {
        if (Build.VERSION.SDK_INT >= 33) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        val intent = VpnService.prepare(context)
        if (intent != null) vpnPermission.launch(intent) else doConnect()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("My VPN", fontWeight = FontWeight.SemiBold) },
                actions = {
                    IconButton(onClick = onSettings) { Icon(Icons.Default.Settings, "Настройки") }
                },
            )
        }
    ) { padding ->
        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding(), bottom = 32.dp + padding.calculateBottomPadding()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            item {
                StatusCard(status, status.host.takeIf { status.state != VpnState.DOWN && it.isNotBlank() } ?: profile.host) {
                    if (status.state == VpnState.DOWN) connectWithPermission() else VpnController.disconnect()
                }
            }

            item { SectionTitle("Протокол") }
            items(profile.protocols, key = { it.name }) { p ->
                ProtocolRow(p, selected = p.name == protocol.name) {
                    if (p == protocol) return@ProtocolRow
                    protocol = p
                    store.protocol = p
                    // Переключение на лету: сразу переподключаемся новым протоколом
                    if (status.state != VpnState.DOWN) connectWithPermission()
                }
            }

            item {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    OutlinedButton(
                        onClick = {
                            refreshing = true
                            refreshMessage = "Загружаю конфигурацию…"
                            scope.launch {
                                runCatching { ProfileUpdater.refresh(store) }
                                    .onSuccess { changed ->
                                        profile = store.profile
                                        protocol = store.protocol
                                        refreshMessage = if (changed) "Конфигурация обновлена. Применится при следующем подключении."
                                            else "Уже установлена последняя конфигурация."
                                    }
                                    .onFailure { refreshMessage = it.message ?: "Не удалось обновить конфигурацию" }
                                refreshing = false
                            }
                        },
                        enabled = !refreshing && store.bootstrap != null,
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text(if (refreshing) "Обновление…" else "Обновить конфигурацию") }
                    Text(
                        refreshMessage ?: if (store.bootstrap == null) "Обновления не настроены в этой сборке."
                            else "Смена сервера и новые режимы — без переустановки. Текущее соединение сохранится.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            item { SectionTitle("Тест скорости") }
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        val last = results.firstOrNull()
                        if (testing) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                                Spacer(Modifier.width(12.dp))
                                Text(testStep)
                            }
                        } else if (last != null) {
                            Text(last.label, style = MaterialTheme.typography.labelLarge)
                            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Metric("Пинг", "${last.pingMs} мс")
                                Metric("Загрузка", "%.1f Мбит/с".format(last.downMbps))
                                Metric("Отдача", "%.1f Мбит/с".format(last.upMbps))
                            }
                            Text("Внешний IP: ${last.exitIp}", style = MaterialTheme.typography.bodySmall)
                        } else {
                            Text("Подключитесь и запустите тест, чтобы сравнить протоколы.", style = MaterialTheme.typography.bodyMedium)
                        }
                        testError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                        Button(
                            onClick = {
                                val current = status.protocol ?: return@Button
                                testing = true
                                testError = null
                                scope.launch {
                                    runCatching { SpeedTest.run(current, status.socksPort) { testStep = it } }
                                        .onSuccess { store.addResult(it); results.add(0, it) }
                                        .onFailure { testError = "Тест не удался: ${it.message ?: it}" }
                                    testing = false
                                }
                            },
                            enabled = status.state == VpnState.UP && !testing,
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Запустить тест") }
                    }
                }
            }

            if (results.isNotEmpty()) {
                item { SectionTitle("Сравнение (среднее по последним 3 замерам)") }
                item { ComparisonTable(results) }
                item {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SectionTitle("История", Modifier.weight(1f))
                        TextButton(onClick = { store.clearResults(); results.clear() }) { Text("Очистить") }
                    }
                }
                items(results) { HistoryRow(it) }
            }
        }
    }
}

@Composable
private fun StatusCard(status: VpnStatus, host: String, onToggle: () -> Unit) {
    val color by animateColorAsState(
        when (status.state) {
            VpnState.UP -> Green
            VpnState.CONNECTING -> Amber
            VpnState.DOWN -> MaterialTheme.colorScheme.outline
        }, label = "status"
    )
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(status.state) {
        while (status.state == VpnState.UP) { now = System.currentTimeMillis(); delay(1000) }
    }

    Card(Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().padding(vertical = 28.dp, horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Box(
                Modifier
                    .size(148.dp)
                    .border(6.dp, color, CircleShape)
                    .padding(12.dp)
                    .background(color.copy(alpha = 0.15f), CircleShape)
                    .clickable(enabled = status.state != VpnState.CONNECTING, onClick = onToggle),
                contentAlignment = Alignment.Center,
            ) {
                if (status.state == VpnState.CONNECTING) CircularProgressIndicator(color = color)
                else Text(
                    if (status.state == VpnState.UP) "ОТКЛ." else "ВКЛ.",
                    fontSize = 24.sp, fontWeight = FontWeight.Bold, color = color,
                )
            }
            Spacer(Modifier.height(20.dp))
            Text(
                when (status.state) {
                    VpnState.UP -> "Подключено"
                    VpnState.CONNECTING -> "Подключение…"
                    VpnState.DOWN -> "Отключено"
                },
                style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
            )
            val details = buildList {
                status.protocol?.takeIf { status.state != VpnState.DOWN }?.let { add(it.title) }
                if (status.state == VpnState.UP && status.since > 0) add(formatDuration(now - status.since))
            }
            if (details.isNotEmpty()) Text(details.joinToString(" · "), style = MaterialTheme.typography.bodyMedium)
            Text(
                "Сервер $host",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            status.error?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ProtocolRow(p: Protocol, selected: Boolean, onClick: () -> Unit) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        ),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = selected, onClick = onClick)
            Column(Modifier.padding(start = 4.dp)) {
                Text(p.title, fontWeight = FontWeight.Medium)
                Text(p.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

@Composable
private fun ComparisonTable(results: List<SpeedResult>) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            TableRow("Протокол", "Пинг", "↓ Мбит/с", "↑ Мбит/с", header = true)
            HorizontalDivider()
            for (p in (Protocol.entries + results.map { it.protocol }).distinctBy { it.name }) {
                val title = p.title
                val last = results.filter { it.protocol.name == p.name }.take(3)
                if (last.isEmpty()) {
                    TableRow(title, "—", "—", "—")
                } else {
                    TableRow(
                        title,
                        "${last.map { it.pingMs }.average().toInt()} мс",
                        "%.1f".format(last.map { it.downMbps }.average()),
                        "%.1f".format(last.map { it.upMbps }.average()),
                    )
                }
            }
        }
    }
}

@Composable
private fun TableRow(a: String, b: String, c: String, d: String, header: Boolean = false) {
    val style = if (header) MaterialTheme.typography.labelMedium else MaterialTheme.typography.bodySmall
    val weight = if (header) FontWeight.SemiBold else FontWeight.Normal
    Row(Modifier.fillMaxWidth()) {
        Text(a, Modifier.weight(2.2f), style = style, fontWeight = weight)
        Text(b, Modifier.weight(1f), style = style, fontWeight = weight)
        Text(c, Modifier.weight(1.1f), style = style, fontWeight = weight)
        Text(d, Modifier.weight(1.1f), style = style, fontWeight = weight)
    }
}

@Composable
private fun HistoryRow(r: SpeedResult) {
    val time = remember(r.time) { SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(Date(r.time)) }
    Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp)) {
        Text(time, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
        Text(r.label, Modifier.weight(2f), style = MaterialTheme.typography.bodySmall)
        Text(
            "${r.pingMs} мс · ↓%.0f · ↑%.0f".format(r.downMbps, r.upMbps),
            Modifier.weight(1.6f), style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun Metric(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SectionTitle(text: String, modifier: Modifier = Modifier) {
    Text(
        text, modifier.padding(top = 8.dp),
        style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary,
    )
}

private fun formatDuration(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return "%02d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60)
}

// ---------- Настройки сервера ----------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SettingsScreen(store: Store, onBack: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val values = remember { mutableStateMapOf<String, String>().apply { putAll(valuesOf(store.profile)) } }
    var confirmReset by remember { mutableStateOf(false) }
    BackHandler(onBack = onBack)

    fun toast(text: String) = Toast.makeText(context, text, Toast.LENGTH_SHORT).show()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки сервера") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад") }
                },
            )
        }
    ) { padding ->
        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = padding.calculateTopPadding(), bottom = 32.dp + padding.calculateBottomPadding()),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item {
                Text(
                    "Данные сервера уже вписаны. Изменения применяются при следующем подключении.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            item {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        val clip = context.getSystemService(ClipboardManager::class.java).primaryClip
                        val text = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
                        runCatching { Profile.parse(text.orEmpty()) }
                            .onSuccess { values.putAll(valuesOf(it)); toast("Профиль вставлен — не забудьте сохранить") }
                            .onFailure { toast("В буфере нет профиля (JSON из `vpnctl profile`)") }
                    }, modifier = Modifier.weight(1f)) { Text("Из буфера") }
                    OutlinedButton(onClick = { confirmReset = true }, modifier = Modifier.weight(1f)) { Text("Сбросить") }
                }
            }
            for (group in Fields.groups) {
                item { SectionTitle(group.title) }
                items(group.fields, key = { it.path }) { f ->
                    OutlinedTextField(
                        value = values[f.path].orEmpty(),
                        onValueChange = { values[f.path] = it },
                        label = { Text(f.label) },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                        keyboardOptions = KeyboardOptions(keyboardType = if (f.numeric) KeyboardType.Number else KeyboardType.Ascii),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            item {
                Button(
                    onClick = {
                        store.profile = store.profile.with(values)
                        toast("Сохранено")
                        onBack()
                    },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    shape = RoundedCornerShape(12.dp),
                ) { Text("Сохранить") }
            }
        }
    }

    if (confirmReset) {
        AlertDialog(
            onDismissRequest = { confirmReset = false },
            title = { Text("Сбросить настройки?") },
            text = { Text("Вернутся данные последнего проверенного обновления; до первого обновления — данные из приложения.") },
            confirmButton = {
                TextButton(onClick = {
                    store.resetProfile()
                    values.putAll(valuesOf(store.profile))
                    confirmReset = false
                    toast("Настройки сброшены")
                }) { Text("Сбросить") }
            },
            dismissButton = { TextButton(onClick = { confirmReset = false }) { Text("Отмена") } },
        )
    }
}

private fun valuesOf(p: Profile): Map<String, String> = Fields.byPath.keys.associateWith { p.str(it) }
