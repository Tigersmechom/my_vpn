#!/bin/bash
# Установка/удаление привилегированной части My VPN. Запускается приложением от root
# через стандартный запрос пароля администратора.
#
#   install-helper.sh install <папка Resources> <uid пользователя>
#   install-helper.sh uninstall
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin

DEST=/Library/PrivilegedHelperTools/myvpn
SUDOERS=/etc/sudoers.d/myvpn

case "${1:-}" in
  install)
    src="$2" uid="$3"
    [[ $uid =~ ^[0-9]+$ ]] || { echo "неверный uid" >&2; exit 1; }
    if [[ -x $DEST/myvpn-helper ]]; then
      status="$("$DEST/myvpn-helper" status)"
      if [[ $status != down* || $status == *'kill-switch on'* || $status == *'kill-switch failed'* ]]; then
        echo "Сначала явно отключите VPN в приложении; активный helper нельзя заменять" >&2
        exit 1
      fi
    fi
    mkdir -p "$DEST"
    chown root:wheel "$DEST"
    chmod 755 "$DEST"
    # Publish the new helper version only after its library and cores exist.
    for f in xray amneziawg-go awg kill-switch.sh myvpn-helper; do
      install -m 755 -o root -g wheel "$src/$f" "$DEST/$f"
    done
    tmp="$(mktemp)"
    echo "#$uid ALL=(root) NOPASSWD: $DEST/myvpn-helper" >"$tmp"
    visudo -cf "$tmp" >/dev/null
    install -m 440 -o root -g wheel "$tmp" "$SUDOERS"
    rm -f "$tmp"
    echo ok
    ;;
  uninstall)
    "$DEST/myvpn-helper" stop >/dev/null
    rm -f "$SUDOERS"
    rm -rf "$DEST"
    echo ok
    ;;
  *) echo "usage: $0 install <src> <uid> | uninstall" >&2; exit 1 ;;
esac
