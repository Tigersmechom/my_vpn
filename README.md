# My VPN — собственные приложения Android, macOS и Ubuntu

Персональный VPN на своём VPS. Основной клиент — Android; есть приложения для Apple Silicon
и Ubuntu Desktop 24.04 на Intel/AMD.
Настройки и дополнительные режимы доставляются кнопкой **«Обновить конфигурацию»**.
Посредник не используется. Разработка интеграции с v2rayTun прекращена.

## Режимы

| Режим | Транспорт | Роль |
|---|---|---|
| VLESS + REALITY + Vision | TCP 443 | Основное подключение; в приложениях 1.2.0 разрешена передача UDP/443 внутри туннеля |
| Hysteria 2 | UDP 443 | QUIC, вариант для сетей с доступным UDP |
| Hysteria 2 + Salamander | UDP, отдельный порт | QUIC с обфускацией |
| AmneziaWG | UDP, отдельный порт | Самостоятельный туннель с обфускацией |
| VLESS + XHTTP + REALITY | TCP 8443, HTTP/2 | Основной дополнительный транспорт; без Vision и без mux.cool |
| VLESS + gRPC + REALITY | TCP 8444, HTTP/2 | Дополнительный вариант HTTP/2 |
| Trojan + REALITY | TCP 9443 | Резерв с другим протоколом авторизации, включён Mux |
| Shadowsocks 2022 | TCP/UDP 8388 | Другой вид зашифрованного трафика; не имитация HTTPS |
| VLESS + Vision, другой SNI | TCP 2053 | Отдельный вход с другим REALITY target; UDP/443 разрешён |

Shadowsocks 2022 помечен в приложении как резерв: при проверке 17 октября TCP на текущем
маршруте работал нестабильно, хотя UDP DNS проходил. В изолированной проверке того же ядра
TCP передал полный ответ. Это не основание считать его надёжным основным режимом для этой сети.

Первые четыре режима входят в базовую установку. Остальные пять устанавливаются отдельной
службой `myvpn-extra.service`; существующие `xray` и AmneziaWG для этого не перезапускаются.
Для альтернативного SNI на текущем сервере проверен `www.yandex.ru`: TLS 1.3, HTTP/2 и сертификат.
Само указание SNI не направляет трафик через инфраструктуру этого сайта.

Это набор разных практических вариантов, а не рейтинг гарантированно работающих протоколов
для всей России. Если заблокирован адрес VPS или разрешены только отдельные адреса, смена
протокола на том же VPS может не помочь. AmneziaWG и Hysteria остаются UDP-протоколами.

Почему выбраны эти варианты:

- XHTTP поддерживает HTTP/2, padding и своё мультиплексирование. Разработчик отдельно
  предупреждает не включать для него mux.cool. [Описание XHTTP](https://github.com/XTLS/Xray-core/discussions/4113).
- REALITY поддерживает RAW, XHTTP и gRPC. Сочетание WebSocket + REALITY не используется.
  [Документация REALITY](https://xtls.github.io/en/config/transports/reality.html).
- Для Trojan включён Mux с учётом предупреждения разработчиков о TLS-in-TLS.
  [Документация Trojan](https://xtls.github.io/en/config/outbounds/trojan.html).
- Shadowsocks использует `2022-blake3-aes-256-gcm`, отдельные ключи клиентов и сервера.
  [Документация Shadowsocks](https://xtls.github.io/en/config/outbounds/shadowsocks.html).
- VMess/WebSocket и TLS/CDN-варианты не добавлены ради количества: Xray рекомендует XHTTP
  вместо WebSocket; публичный TLS frontend требует отдельной настройки сертификатов,
  а CDN может ограничиваться самим оператором. [WebSocket](https://xtls.github.io/en/config/transports/websocket.html),
  [измерения Cloudflare в российских сетях](https://blog.cloudflare.com/russian-internet-users-are-unable-to-access-the-open-internet/).
- NaïveProxy и TUIC требуют дополнительных ядер и отдельной интеграции в приложения.
  Обычные OpenVPN, IKEv2 и WireGuard не добавлены как основные средства обхода DPI.
  [NaïveProxy](https://github.com/klzgrad/naiveproxy), [TUIC](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md),
  [обзор протоколов Amnezia](https://docs.amnezia.org/documentation/protocols-info/).

## Готовые приложения

Версия **1.2.0**, Android code 3 / macOS build 3:

- `dist/MyVPN-1.2.0-android-arm64.apk` — современные Android-телефоны, Android 7+.
- `dist/MyVPN-1.2.0-android-universal.apk` — несколько архитектур.
- `dist/MyVPN-1.2.0-macos-arm64.zip` — Apple Silicon, macOS 13+.
- `dist/MyVPN-1.2.0-ubuntu24.04-amd64.deb` — Ubuntu Desktop 24.04, Intel/AMD.
- `dist/SHA256SUMS.txt` — контрольные суммы локальных сборок.

Сборки персональные: содержат профили VPN и ключ расшифровки обновлений. Они исключены из Git.
Android сохраняет прежнюю локальную debug-подпись для установки поверх версии 1.1.0.
Mac-приложение подписано ad-hoc, без нотарификации Apple; распакуйте и перенесите его в
«Программы». Установка сетевого компонента выполняется только по нажатию пользователя
с запросом пароля администратора. При подключении используйте один VPN за раз.

Ubuntu: установите пакет командой `sudo apt install ./MyVPN-1.2.0-ubuntu24.04-amd64.deb`,
затем откройте **My VPN** в меню приложений. Сетевой компонент запрашивает пароль через polkit;
установка сама по себе не включает VPN. Профиль Linux получает отдельные ключ и адрес
AmneziaWG для одновременного подключения с Mac. Режимы Xray используют общий аккаунт Mac.
[Установка, сборка и обслуживание Ubuntu](linux/README.md).

Версия 1.1.0 уже умеет получить пять дополнительных режимов кнопкой обновления: для них
переустановка не нужна. Исправления встроенного VLESS, диагностика и восстановление загрузки
через неисправный туннель входят в 1.2.0 и требуют установки этой версии.

## Android: туннель запущен, но Google не открывается

Запуск ядра не доказывает успешное соединение с сервером. В версии 1.2.0 статус обозначает
запуск туннеля, а кнопка **«Проверить соединение»** отдельно проверяет HTTPS и загрузку 64 КБ
через используемый локальный SOCKS. Частичная загрузка, таймаут и ошибка TLS/DNS показываются
как результаты диагностики. Проверка не переключает режим и не отключает VPN.

У обычного `xtls-rprx-vision` Xray отклоняет UDP/443. В приложениях 1.2.0 используется
`xtls-rprx-vision-udp443`, разрешающий QUIC внутри туннеля без изменения серверного flow.
Это устраняет ограничение клиента, но само по себе не доказывает причину конкретного
зависания Google. [Документация VLESS](https://xtls.github.io/en/config/outbounds/vless.html).

При проблеме:

1. Нажмите «Обновить конфигурацию» и дождитесь успешного сохранения.
2. Переподключитесь к VLESS и нажмите «Проверить соединение».
3. Если трафика нет, сравните VLESS XHTTP и VLESS с альтернативным SNI, затем UDP-режимы.
4. Сохраните результаты диагностики и укажите оператора/тип сети. Ошибка одного проверочного
   сайта не означает, что весь VPN недоступен.

На Android обновлятор сначала использует работающий SOCKS-туннель. При сетевой ошибке он
один раз пробует тот же адрес напрямую по HTTPS. Проверки сертификата, AES-GCM и ревизии
остаются обязательными; ошибка подлинности не запускает повторную попытку другим путём.
На macOS и Ubuntu загрузка следует системному маршруту: неработающий VPN может потребоваться
отключить вручную, чтобы получить новые настройки.

## Обновление одной кнопкой

- Публичные `updates/android.json`, `updates/mac.json` и `updates/linux.json` содержат только зашифрованные профили.
- Приватные `config/android-update.json`, `config/mac-update.json` и `config/linux-update.json` содержат постоянный HTTPS URL,
  идентификатор клиента, ключ AES-256-GCM и минимальную ревизию; в Git не попадают.
- Проверяются подлинность, клиент, схема, размер и ревизия. Откат к старой ревизии отклоняется.
- Запросы имеют уникальный параметр против кеширования. GitHub всё же может показывать новую
  публикацию с задержкой; встроенный минимум ревизии не даёт новой сборке принять старый профиль.
- Новый профиль сохраняется для следующего подключения. Уже работающий туннель использует
  прежние настройки. Сброс настроек восстанавливает последний проверенный профиль.
- `extraXray` позволяет добавить до восьми режимов встроенных VLESS, Hysteria, Trojan, VMess,
  Shadowsocks без новой сборки. Новый исполняемый код не загружается; новое ядро требует приложения.

Владелец сначала настраивает сервер, затем публикует профили. Ключи bootstrap при замене сервера
сохраняйте прежними: установленные приложения доверяют именно им. Сделайте их приватную
резервную копию; из публичного ciphertext ключ восстановить нельзя.

Подготовка инструмента публикации:

```bash
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-update.txt
```

После сохранения новых профилей в `config/android.json`, `config/mac.json` и `config/linux.json`:

```bash
.venv/bin/python tools/publish_updates.py --profile config/android.json --bootstrap config/android-update.json --output updates/android.json
.venv/bin/python tools/publish_updates.py --profile config/mac.json --bootstrap config/mac-update.json --output updates/mac.json
.venv/bin/python tools/publish_updates.py --profile config/linux.json --bootstrap config/linux-update.json --output updates/linux.json
git add updates/android.json updates/mac.json updates/linux.json
git commit -m "Update encrypted VPN profiles"
git push origin main
```

Каждый запуск проверяет старую публикацию и увеличивает ревизию. Для первого запуска на своём
репозитории добавьте `--init-url https://raw.githubusercontent.com/OWNER/REPO/refs/heads/main/updates/android.json`
или соответствующий адрес `mac.json`, затем соберите приложения со своими bootstrap-файлами.

## Сервер

Базовая установка для Ubuntu 22.04/24.04:

```bash
ssh root@SERVER 'mkdir -p /root/myvpn'
scp server/install.sh server/vpnctl server/export.py server/extra_protocols.py root@SERVER:/root/myvpn/
ssh root@SERVER 'bash /root/myvpn/install.sh'
```

Установщик сохраняет существующие ключи. Настройка дополнительных режимов отдельно:

```bash
python3 /usr/local/lib/myvpn/extra_protocols.py install --alternate-sni www.yandex.ru
python3 /usr/local/lib/myvpn/extra_protocols.py profile android --output /root/android-extra.json
python3 /usr/local/lib/myvpn/extra_protocols.py profile mac --output /root/mac-extra.json
```

Скачайте два приватных файла в локальные `config/android.json` и `config/mac.json`, проверьте
соединения и только после этого публикуйте обновление. Базовый `vpnctl profile` возвращает
основные режимы; для полного профиля используйте команду дополнительного модуля выше.

Модуль сохраняет собственные ключи в `/etc/myvpn/extra-protocols.json` с правами 600,
конфигурацию — в `/usr/local/etc/xray/extra.json`, службу — `myvpn-extra.service`.
Он проверяет конфигурацию до применения и восстанавливает прошлое состояние дополнительной
службы при ошибке. Повторная установка без изменений не вызывает перезапуск.
`render --output /root/preview.json` проверяет предварительную конфигурацию без применения.
Если есть firewall провайдера/хоста, разрешите дополнительные TCP-порты и UDP 8388 отдельно.

После добавления или удаления клиента обновляйте также дополнительные режимы. Актуальный
`vpnctl` согласует их автоматически при `render`, если модуль уже установлен; при использовании
старой версии повторите `extra_protocols.py install`. Удаление клиента только из старого
базового `vpnctl` не отзывает его отдельные ключи дополнительных протоколов.

```bash
vpnctl add phone2
vpnctl remove phone2
vpnctl status
systemctl status myvpn-extra.service
```

Миграция старой установки `vpnctl migrate` сохраняет резервные копии в `/etc/myvpn/backups/`.
Она удаляет старый обычный WG только при точном совпадении его конфигурации с прежней установкой.

## Сборка и безопасные проверки

```bash
cd android
JAVA_HOME=/opt/homebrew/opt/openjdk@17 ./gradlew testReleaseUnitTest lintRelease assembleRelease
```

```bash
cd macos
./build.sh
```

Нужны JDK 17/Android SDK для Android; Swift/Xcode Command Line Tools, Go, Git и curl для macOS.
Без личных профилей используется фиктивный `config/example.json`, без bootstrap обновления отключены.

```bash
.venv/bin/python -m unittest discover -s tests -v
python3 macos/scripts/check-configs.py
```

Проверки сервера используют изолированный `MYVPN_ROOT` и заглушки сервисов. Клиентские проверки
не устанавливают приложения и не поднимают системный VPN. Отдельная проверка передачи данных:

```bash
python3 tools/check_connections.py --profile config/android.json --interface en0
```

Здесь `en0` — физический Wi-Fi-интерфейс данного Mac; на другом компьютере выберите свой.
Инструмент запускает временные SOCKS-процессы только на loopback, проверяет Google, загрузку
128 КБ и UDP DNS для каждого режима Xray. Он не создаёт TUN и не меняет системные маршруты.
AmneziaWG требует отдельной проверки на устройстве.

17 октября 2026 года исходный VLESS на сервере прошёл загрузку Google, 128 КБ и UDP DNS через
физический интерфейс Mac. Проблема конкретного Android/его сети при этой проверке не
воспроизвелась; окончательный результат требует проверки на этом телефоне.

В Git не входят реальные профили, bootstrap, APK/app/deb, экспорты и скриншот с реквизитами.
Старые сборки и исходники сохранены локально в `.legacy/`; публичные файлы обновлений зашифрованы.
