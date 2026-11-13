#!/bin/bash
# Sourced only by the root-owned helper. No global PF flush/disable and no pf.conf edits.
# The stock Apple wildcard evaluates this anchor first; every decision is quick.
KS_ANCHOR=com.apple/000.myvpn

ks_validate_endpoint() {
  local ip="$1" port="$2" proto="$3" part
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "Kill switch: нужен IPv4 сервера"
  local old_ifs="$IFS"; IFS=.
  for part in $ip; do
    [[ $part == 0 || $part != 0* ]] && (( 10#$part <= 255 )) || die "Kill switch: неверный IPv4"
  done
  IFS="$old_ifs"
  [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || die "Kill switch: неверный порт"
  [[ $proto == tcp || $proto == udp || $proto == tcp-udp ]] || die "Kill switch: неверный транспорт"
}

ks_rules() {
  local iface="${1:-}" transport
  transport="$(cat "$RUN/ks.proto")"
  [[ $transport != tcp-udp ]] || transport='{ tcp, udp }'
  # No floating states for inner traffic: otherwise a TUN state could allow a
  # connection to escape through Wi-Fi after a route change. IPv6 stays blocked.
  cat <<EOF
pass quick on lo0 all no state
pass out quick inet proto udp from any port 68 to any port 67 no state
pass in quick inet proto udp from any port 67 to any port 68 no state
pass out quick inet proto $transport from any to $(cat "$RUN/ks.ip") port $(cat "$RUN/ks.port") user root keep state (if-bound)
EOF
  [[ -z $iface ]] || echo "pass quick on $iface inet all no state"
  echo 'block drop quick all label "myvpn-kill-switch"'
}

ks_check_layout() {
  # Reject a custom root ruleset rather than silently accepting an earlier pass
  # quick rule. Scrub rules do not make filtering decisions.
  local rules children skipped
  rules="$(pfctl -sr 2>/dev/null)" || die "Kill switch: PF недоступен"
  rules="$(printf '%s\n' "$rules" | sed '/^[[:space:]]*$/d; /^scrub/d')"
  if [[ -z $rules ]]; then
    # Only populate an EMPTY filter ruleset. -R leaves NAT, scrub, dummynet and
    # existing child anchors intact. Never reload /etc/pf.conf or use -F all.
    printf 'anchor "com.apple/*"\n' >"$RUN/pf-root.conf"
    pfctl -R -f "$RUN/pf-root.conf" >>"$LOG" 2>&1 || die "Kill switch: не удалось подключить anchor PF"
    rules="$(pfctl -sr 2>/dev/null | sed '/^[[:space:]]*$/d; /^scrub/d')"
  fi
  [[ $rules == 'anchor "com.apple/*" all' ]] || die "Kill switch: нестандартные правила PF; подключение отменено"
  children="$(pfctl -a com.apple -s Anchors 2>/dev/null)" || die "Kill switch: не удалось проверить anchors"
  [[ -z $(printf '%s\n' "$children" | awk '{name=$1; sub(/^com[.]apple\//,"",name); if (name < "000.myvpn") print}') ]] || die "Kill switch: другой anchor PF имеет приоритет"
  skipped="$(pfctl -v -s Interfaces 2>/dev/null)" || die "Kill switch: не удалось проверить интерфейсы PF"
  [[ -z $(printf '%s\n' "$skipped" | awk '/\(skip\)/ && $1 != "lo0" {print}') ]] || die "Kill switch: интерфейс исключён из PF"
}

ks_load() {
  local iface="${1:-}"
  [[ -z $iface || $iface =~ ^utun[0-9]{1,5}$ ]] || die "Kill switch: неверный интерфейс"
  ks_rules "$iface" >"$RUN/ks.next"
  pfctl -n -a "$KS_ANCHOR" -f "$RUN/ks.next" >>"$LOG" 2>&1 || die "Kill switch: PF отверг правила"
  pfctl -a "$KS_ANCHOR" -f "$RUN/ks.next" >>"$LOG" 2>&1 || die "Kill switch: не удалось загрузить правила"
  mv "$RUN/ks.next" "$RUN/ks.rules"
  printf '%s\n' "$iface" >"$RUN/ks.iface"
}

ks_arm() {
  ks_validate_endpoint "$1" "$2" "$3"
  ks_check_layout
  printf '%s\n' "$1" >"$RUN/ks.ip"
  printf '%s\n' "$2" >"$RUN/ks.port"
  printf '%s\n' "$3" >"$RUN/ks.proto"
  # First close the old TUN allowance; no unprotected gap while switching modes.
  touch "$RUN/ks.active"
  ks_load
  if [[ ! -s $RUN/ks.token ]]; then
    local result token
    result="$(pfctl -E 2>&1)" || die "Kill switch: не удалось включить PF"
    token="$(printf '%s\n' "$result" | awk '/Token[[:space:]]*:/ {print $NF}')"
    [[ $token =~ ^[0-9]+$ ]] || die "Kill switch: PF не выдал token"
    echo "$token" >"$RUN/ks.token"
  fi
  # Old states bypass ALL filter rules. Clear IPv4 AND IPv6 once on connection/
  # reconnection, after the deny rule is installed and before any core starts.
  pfctl -k 0.0.0.0/0 >>"$LOG" 2>&1 || die "Kill switch: не удалось закрыть старые IPv4-соединения"
  pfctl -k ::/0 >>"$LOG" 2>&1 || die "Kill switch: не удалось закрыть старые IPv6-соединения"
  ks_verified || die "Kill switch: защита не подтверждена"
}

ks_verified() {
  local rules children skipped
  [[ -f $RUN/ks.active && -s $RUN/ks.token ]] || return 1
  pfctl -si 2>/dev/null | grep '^Status: Enabled' >/dev/null || return 1
  rules="$(pfctl -sr 2>/dev/null | sed '/^[[:space:]]*$/d; /^scrub/d')" || return 1
  [[ $rules == 'anchor "com.apple/*" all' ]] || return 1
  children="$(pfctl -a com.apple -s Anchors 2>/dev/null)" || return 1
  [[ -z $(printf '%s\n' "$children" | awk '{name=$1; sub(/^com[.]apple\//,"",name); if (name < "000.myvpn") print}') ]] || return 1
  skipped="$(pfctl -v -s Interfaces 2>/dev/null)" || return 1
  [[ -z $(printf '%s\n' "$skipped" | awk '/\(skip\)/ && $1 != "lo0" {print}') ]] || return 1
  pfctl -a "$KS_ANCHOR" -sr 2>/dev/null | grep 'block drop quick all label "myvpn-kill-switch"' >/dev/null || return 1
}

ks_release() {
  # Called only by explicit Disconnect/uninstall. Failure keeps the marker and
  # reports an error, never tells the UI the network has been restored.
  [[ -f $RUN/ks.active ]] || return 0
  pfctl -a "$KS_ANCHOR" -f /dev/null >>"$LOG" 2>&1 || die "Не удалось снять kill switch; повторите отключение"
  if [[ -s $RUN/ks.token ]]; then
    pfctl -X "$(cat "$RUN/ks.token")" >>"$LOG" 2>&1 || die "Не удалось освободить PF token"
  fi
  rm -f "$RUN"/ks.*
}
