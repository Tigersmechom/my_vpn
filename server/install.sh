#!/usr/bin/env bash
# Установка My VPN: VLESS + REALITY/TCP, Hysteria 2 (обычный и Salamander), AmneziaWG.
# Ubuntu 22.04/24.04, запуск от root. Скрипт идемпотентный: повторный запуск ничего не ломает
# и не меняет уже сгенерированные ключи.
#
#   bash install.sh
#
# Переменные окружения (необязательные):
#   PUBLIC_HOST       — IP или домен сервера (по умолчанию определяется автоматически)
#   REALITY_SNI       — сайт, под который маскируется Reality (по умолчанию выбирается из списка)
#   XRAY_VERSION      — версия Xray (по умолчанию v26.9.30)
#   AWG_GO_REF        — тег amneziawg-go
#   AWG_TOOLS_REF     — тег amneziawg-tools
#   GO_VERSION        — версия Go для сборки AmneziaWG
set -euo pipefail
umask 077

XRAY_VERSION="${XRAY_VERSION:-v26.9.30}"
AWG_GO_REF="${AWG_GO_REF:-v3.1.20260828}"
AWG_TOOLS_REF="${AWG_TOOLS_REF:-v1.0.20260618-2}"
GO_VERSION="${GO_VERSION:-1.27.2}"

STATE_DIR=/etc/myvpn
SERVER_ENV="$STATE_DIR/server.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mОшибка: %s\033[0m\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "запустите от root"
[[ -f "$SCRIPT_DIR/vpnctl" && -f "$SCRIPT_DIR/export.py" ]] || die "рядом с install.sh должны лежать vpnctl и export.py"
[[ -z ${MYVPN_ROOT:-} ]] || die "install.sh предназначен для настоящего сервера; MYVPN_ROOT используется только vpnctl в тестах"

export DEBIAN_FRONTEND=noninteractive

log "Пакеты"
apt-get update -qq
apt-get install -y -qq curl unzip jq openssl iptables python3 \
  build-essential git ca-certificates pkg-config >/dev/null

# Save state before adding fields or changing VPN configuration. These copies
# also cover upgrades from versions without Hysteria credentials.
if [[ -f $SERVER_ENV ]]; then
  backup="$STATE_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)-preinstall-$$"
  mkdir -p "$backup/config"
  chmod 700 "$STATE_DIR" "$STATE_DIR/backups" "$backup" "$backup/config"
  cp -p "$SERVER_ENV" "$backup/server.env"
  [[ ! -d $STATE_DIR/clients ]] || cp -R -p "$STATE_DIR/clients" "$backup/clients"
  for item in '/usr/local/etc/xray/config.json:xray.json' '/etc/amnezia/amneziawg/awg0.conf:awg0.conf' '/etc/wireguard/wg0.conf:wg0.conf'; do
    src="${item%:*}"; dst="${item##*:}"
    [[ ! -f $src ]] || cp -p "$src" "$backup/config/$dst"
  done
  printf 'Before install: restore server.env, clients and original configuration paths before restarting services.\n' >"$backup/manifest.txt"
  log "Резервная копия перед обновлением: $backup"
fi

log "Сетевые настройки ядра (forwarding, BBR, буферы)"
cat >/etc/sysctl.d/99-myvpn.conf <<'EOF'
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.core.netdev_max_backlog = 16384
EOF
sysctl --system >/dev/null

log "Xray $XRAY_VERSION"
if ! /usr/local/bin/xray version 2>/dev/null | grep -q "Xray ${XRAY_VERSION#v} "; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version "$XRAY_VERSION"
fi
/usr/local/bin/xray version | head -1

log "Go $GO_VERSION (для сборки AmneziaWG)"
case "$(uname -m)" in
  x86_64) GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  *) die "неподдерживаемая архитектура $(uname -m)" ;;
esac
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$GO_VERSION "; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
fi
export PATH=/usr/local/go/bin:$PATH

log "AmneziaWG ($AWG_GO_REF, tools $AWG_TOOLS_REF)"
BUILD=/opt/myvpn-build
mkdir -p "$BUILD"
if [[ "$(cat "$BUILD/awg-go.ref" 2>/dev/null)" != "$AWG_GO_REF" ]]; then
  rm -rf "$BUILD/amneziawg-go"
  git clone -q --depth 1 --branch "$AWG_GO_REF" https://github.com/amnezia-vpn/amneziawg-go.git "$BUILD/amneziawg-go"
  make -C "$BUILD/amneziawg-go" >/dev/null
  install -m 755 "$BUILD/amneziawg-go/amneziawg-go" /usr/bin/amneziawg-go
  echo "$AWG_GO_REF" >"$BUILD/awg-go.ref"
fi
if [[ "$(cat "$BUILD/awg-tools.ref" 2>/dev/null)" != "$AWG_TOOLS_REF" ]]; then
  rm -rf "$BUILD/amneziawg-tools"
  git clone -q --depth 1 --branch "$AWG_TOOLS_REF" https://github.com/amnezia-vpn/amneziawg-tools.git "$BUILD/amneziawg-tools"
  make -C "$BUILD/amneziawg-tools/src" >/dev/null
  make -C "$BUILD/amneziawg-tools/src" install WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes >/dev/null
  echo "$AWG_TOOLS_REF" >"$BUILD/awg-tools.ref"
fi
awg --version || true

log "Ключи и параметры сервера"
mkdir -p "$STATE_DIR/clients"
chmod 700 "$STATE_DIR" "$STATE_DIR/clients"

pick_sni() {
  local d
  for d in www.microsoft.com dl.google.com www.apple.com addons.mozilla.org www.samsung.com; do
    # Нужен сайт с TLS 1.3 и HTTP/2, иначе Reality будет выделяться.
    if [[ "$(curl -s -o /dev/null -m 8 --tlsv1.3 --http2 -w '%{http_version}' "https://$d/")" == "2" ]]; then
      echo "$d"; return
    fi
  done
  echo www.microsoft.com
}

if [[ ! -f "$SERVER_ENV" ]]; then
  host="${PUBLIC_HOST:-$(curl -4 -fsS -m 10 https://api.ipify.org || hostname -I | awk '{print $1}')}"
  wan_if="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}')"
  sni="${REALITY_SNI:-$(pick_sni)}"

  python3 - "$host" "$sni" "$wan_if" <<'PYVALIDATE' || die "неверный адрес сервера, SNI или сетевой интерфейс"
import ipaddress, re, sys
host, sni, interface = sys.argv[1:]
def domain(value):
    return len(value) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in value.split("."))
try:
    ipaddress.ip_address(host)
except ValueError:
    if not domain(host) or re.fullmatch(r"[0-9.]+", host): sys.exit(1)
if not domain(sni) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface): sys.exit(1)
PYVALIDATE

  x25519="$(/usr/local/bin/xray x25519)"
  reality_priv="$(awk -F': ' 'tolower($1) ~ /^private ?key/ {print $2}' <<<"$x25519")"
  reality_pub="$(awk -F': ' 'tolower($1) ~ /password|public ?key/ {print $2}' <<<"$x25519")"
  [[ -n $reality_priv && -n $reality_pub ]] || die "не удалось разобрать ключи из вывода xray x25519"

  awg_priv="$(awg genkey)"

  rnd() { shuf -i "$1-$2" -n 1; }
  s1=$(rnd 15 150); s2=$(rnd 15 150)
  while (( s1 + 56 == s2 )); do s2=$(rnd 15 150); done
  # H1-H4 — четыре разных значения, не пересекающиеся со стандартными типами WireGuard (1-4).
  mapfile -t hs < <(shuf -i 100000000-2147483647 -n 4)
  awg_port=$(rnd 30000 60000)

  # I1 — «сигнатурный» пакет перед рукопожатием, похожий на DNS-запрос www.yandex.ru.
  i1='<r 2><b 0x01000001000000000000037777770679616e6465780272750000010001>'

  cat >"$SERVER_ENV" <<EOF
PUBLIC_HOST='$host'
WAN_IF='$wan_if'
REALITY_SNI='$sni'
REALITY_PRIVATE_KEY='$reality_priv'
REALITY_PUBLIC_KEY='$reality_pub'
REALITY_SHORT_ID='$(openssl rand -hex 8)'
REALITY_FINGERPRINT='chrome'
VLESS_TCP_PORT=443
AWG_PORT=$awg_port
AWG_NET='10.77.77'
AWG_SERVER_PRIVATE_KEY='$awg_priv'
AWG_SERVER_PUBLIC_KEY='$(awg pubkey <<<"$awg_priv")'
AWG_JC=$(rnd 3 6)
AWG_JMIN=40
AWG_JMAX=70
AWG_S1=$s1
AWG_S2=$s2
AWG_S3=$(rnd 15 60)
AWG_S4=$(rnd 5 30)
AWG_H1=${hs[0]}
AWG_H2=${hs[1]}
AWG_H3=${hs[2]}
AWG_H4=${hs[3]}
AWG_I1='$i1'
CLIENT_DNS='1.1.1.1, 8.8.8.8'
EOF
  chmod 600 "$SERVER_ENV"
  echo "Сгенерированы новые ключи. Reality SNI: $sni"
else
  echo "Ключи уже есть ($SERVER_ENV), оставляю как есть"
fi

# Validate literal state syntax before using it as shell assignments. Older keys
# are accepted here so vpnctl migrate can remove them after a backup.
python3 - "$SERVER_ENV" <<'PYVALIDATE' || die "недопустимый server.env"
import os, re, stat, sys
path = sys.argv[1]
s = os.lstat(path)
if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) & 0o077:
    sys.exit("server.env должен быть обычным файлом root с правами 600")
seen = set()
allowed = set("PUBLIC_HOST WAN_IF REALITY_SNI REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY REALITY_SHORT_ID REALITY_FINGERPRINT VLESS_TCP_PORT AWG_PORT AWG_NET AWG_SERVER_PRIVATE_KEY AWG_SERVER_PUBLIC_KEY AWG_JC AWG_JMIN AWG_JMAX AWG_S1 AWG_S2 AWG_S3 AWG_S4 AWG_H1 AWG_H2 AWG_H3 AWG_H4 AWG_I1 CLIENT_DNS HY2_PORT HY2_OBFS_PORT HY2_SNI HY2_OBFS_PASSWORD HY2_CERT HY2_KEY HY2_PIN VLESS_XHTTP_PORT XHTTP_PATH WG_PORT WG_NET WG_SERVER_PRIVATE_KEY WG_SERVER_PUBLIC_KEY RELAY_HOST".split())
with open(path) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"): continue
        m = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(?:'([^'\r\n]*)'|([0-9]+))", line)
        if not m or m[1] not in allowed or m[1] in seen: sys.exit("недопустимое или повторное присваивание")
        seen.add(m[1])
PYVALIDATE

# Hysteria2 — добавлен позже, поэтому дописываем недостающие параметры и в существующую установку.
ensure_var() { grep -q "^$1=" "$SERVER_ENV" || echo "$1=$2" >>"$SERVER_ENV"; }
ensure_var HY2_PORT 443
ensure_var HY2_OBFS_PORT "$(shuf -i 20000-29999 -n 1)"
ensure_var HY2_SNI "'www.bing.com'"
ensure_var HY2_OBFS_PASSWORD "'$(openssl rand -hex 16)'"
ensure_var HY2_CERT "'/usr/local/etc/xray/hy2.crt'"
ensure_var HY2_KEY "'/usr/local/etc/xray/hy2.key'"
# shellcheck disable=SC1090
source "$SERVER_ENV"
if [[ -n ${backup:-} ]]; then
  [[ ! -f $HY2_CERT ]] || cp -p "$HY2_CERT" "$backup/config/hy2.crt"
  [[ ! -f $HY2_KEY ]] || cp -p "$HY2_KEY" "$backup/config/hy2.key"
  printf 'Hysteria certificate: %s\nHysteria key: %s\n' "$HY2_CERT" "$HY2_KEY" >>"$backup/manifest.txt"
fi
[[ -f $HY2_CERT && -f $HY2_KEY ]] || [[ ! -e $HY2_CERT && ! -e $HY2_KEY ]] || die "найден только один файл сертификата/ключа Hysteria; восстановите пару из резервной копии"
install -d -m 755 /usr/local/etc/xray
mkdir -p "$(dirname "$HY2_CERT")" "$(dirname "$HY2_KEY")"
if [[ ! -f $HY2_CERT ]]; then
  [[ -z ${HY2_PIN:-} ]] || die "сертификат с сохранённым отпечатком Hysteria отсутствует; восстановите сертификат и ключ из резервной копии"
  # Самоподписанный сертификат; клиенты проверяют его по отпечатку (pinning), а не по цепочке.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=$HY2_SNI" -addext "subjectAltName=DNS:$HY2_SNI" \
    -keyout "$HY2_KEY" -out "$HY2_CERT" 2>/dev/null
fi
chown root:nogroup "$HY2_KEY"
chmod 640 "$HY2_KEY"
chmod 644 "$HY2_CERT"
ensure_var HY2_PIN "'$(openssl x509 -in "$HY2_CERT" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr 'A-F' 'a-f')'"

install -m 755 "$SCRIPT_DIR/vpnctl" /usr/local/bin/vpnctl
install -d -m 755 /usr/local/lib/myvpn
install -m 755 "$SCRIPT_DIR/export.py" /usr/local/lib/myvpn/export.py
# Copy the optional manager without enabling its service on a fresh install.
# Existing add-on state is reconciled by vpnctl when clients/configs change.
if [[ -f "$SCRIPT_DIR/extra_protocols.py" ]]; then
  install -m 755 "$SCRIPT_DIR/extra_protocols.py" /usr/local/lib/myvpn/extra_protocols.py
fi

if ! compgen -G "$STATE_DIR/clients/*.env" >/dev/null; then
  log "Клиенты по умолчанию: android, mac"
  vpnctl add android --no-render
  vpnctl add mac --no-render
fi

log "Конфиги и сервисы"
vpnctl migrate

if systemctl is-active -q ufw; then
  # shellcheck disable=SC1090
  source "$SERVER_ENV"
  ufw allow "$VLESS_TCP_PORT/tcp"
  ufw allow "$AWG_PORT/udp"
  ufw allow "$HY2_PORT/udp" && ufw allow "$HY2_OBFS_PORT/udp"
fi

vpnctl status
log "Готово. Файлы для сторонних клиентов: vpnctl export <имя> <каталог>; ссылки: vpnctl links <имя>"
