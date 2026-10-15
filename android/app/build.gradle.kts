import java.net.URI
import java.security.MessageDigest

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Ядро Xray для Android (gomobile-сборка AndroidLibXrayLite). 60 МБ — в git не храним, качаем при первой сборке.
val xrayLibVersion = "v26.9.30"
val xrayLibSha256 = "cf71680b776b9ca583747ba652f816b047a655eab875d8951e6141636d88bbd6"
val xrayAar = file("libs/libv2ray-$xrayLibVersion.aar")

fun sha256(f: File): String =
    MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

if (!xrayAar.exists()) {
    logger.lifecycle("Скачиваю libv2ray.aar $xrayLibVersion…")
    xrayAar.parentFile.mkdirs()
    val tmp = File(xrayAar.path + ".part")
    URI("https://github.com/2dust/AndroidLibXrayLite/releases/download/$xrayLibVersion/libv2ray.aar")
        .toURL().openStream().use { input -> tmp.outputStream().use { input.copyTo(it) } }
    check(sha256(tmp) == xrayLibSha256) { "Контрольная сумма libv2ray.aar не совпала" }
    check(tmp.renameTo(xrayAar)) { "Не удалось сохранить libv2ray.aar" }
}
check(sha256(xrayAar) == xrayLibSha256) { "Контрольная сумма libv2ray.aar не совпала" }

// Профиль сервера по умолчанию: config/android.json (создаётся на сервере командой `vpnctl profile android`).
// Если его нет — собираемся с шаблоном config/example.json.
val profileSource = rootProject.file("../config/android.json").takeIf { it.exists() }
    ?: rootProject.file("../config/example.json")
val generatedAssets = layout.buildDirectory.dir("generated/defaultProfile")
val copyDefaultProfile by tasks.registering(Sync::class) {
    from(profileSource) { rename { "default_profile.json" } }
    from(rootProject.file("../config/android-update.json")) { rename { "update_bootstrap.json" } }
    into(generatedAssets)
}

android {
    namespace = "app.myvpn"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.myvpn"
        minSdk = 24
        targetSdk = 35
        versionCode = 2
        versionName = "1.1.0"
    }

    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a", "x86_64")
            isUniversalApk = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Подписываем debug-ключом, чтобы release-APK можно было сразу поставить.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    sourceSets["main"].assets.srcDir(generatedAssets)

    androidResources {
        // geo-файлы из libv2ray не нужны: маршрутизация в клиенте без geoip/geosite.
        ignoreAssetsPattern = "!geoip.dat:!geosite.dat:!geoip-only-cn-private.dat"
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    jvmToolchain(17)
}

tasks.named("preBuild") { dependsOn(copyDefaultProfile) }

dependencies {
    implementation(files(xrayAar))
    implementation("com.zaneschepke:amneziawg-android:2.3.7")

    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    implementation(platform("androidx.compose:compose-bom:2025.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}

// Optional offline interoperability check against the locally generated, private bootstrap.
tasks.withType<Test>().configureEach {
    if (System.getenv("MYVPN_VERIFY_LOCAL_FEED") == "1") {
        environment("MYVPN_VERIFY_LOCAL_FEED", "1")
        inputs.files(rootProject.file("../config/android-update.json"), rootProject.file("../updates/android.json"), profileSource)
    }
}
