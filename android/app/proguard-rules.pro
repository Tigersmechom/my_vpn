# gomobile (libv2ray): Go вызывает Java-классы через JNI по именам
-keep class go.** { *; }
-keep class libv2ray.** { *; }

# AmneziaWG: JNI-колбэки из libam-go
-keep class org.amnezia.awg.** { *; }
-dontwarn org.amnezia.awg.**
