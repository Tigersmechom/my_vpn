#!/bin/bash
# Full XFCE desktop on Ubuntu 24.04. VNC/HTTP listen on loopback; access uses SSH.
# VNC_PASSWORD_FILE and SSH_PUBLIC_KEY_FILE must point to private, prepared files.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run as root' >&2; exit 1; }
desktop_user=myvpn-desktop
desktop_home=/home/$desktop_user
source_dir=$(cd "$(dirname "$0")" && pwd)
[[ -f ${VNC_PASSWORD_FILE:-} && -f ${SSH_PUBLIC_KEY_FILE:-} ]] || { echo 'Missing prepared access files' >&2; exit 1; }
python3 - "$VNC_PASSWORD_FILE" <<'PY'
import pathlib,sys
password=pathlib.Path(sys.argv[1]).read_text().strip()
assert len(password.encode())==8 and password.isascii() and password.isalnum(), 'Expected eight random ASCII characters'
PY
ssh-keygen -l -f "$SSH_PUBLIC_KEY_FILE" >/dev/null
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends xfce4 xfce4-terminal tigervnc-standalone-server tigervnc-common tigervnc-tools dbus-x11 novnc websockify gnupg scrot >/dev/null

# Mozilla's signed repository supplies a regular desktop Firefox without Snap.
install -d -m 755 /etc/apt/keyrings
curl -fsSL https://packages.mozilla.org/apt/repo-signing-key.gpg -o /etc/apt/keyrings/packages.mozilla.org.asc
chmod 644 /etc/apt/keyrings/packages.mozilla.org.asc
fingerprint=$(gpg --batch --show-keys --with-colons /etc/apt/keyrings/packages.mozilla.org.asc 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')
[[ $fingerprint == 35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3 ]] || { echo 'Mozilla signing key mismatch' >&2; exit 1; }
cat >/etc/apt/sources.list.d/myvpn-mozilla.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/packages.mozilla.org.asc] https://packages.mozilla.org/apt mozilla main
EOF
cat >/etc/apt/preferences.d/myvpn-mozilla <<'EOF'
Package: firefox firefox-l10n-*
Pin: origin packages.mozilla.org
Pin-Priority: 1001
EOF
chmod 644 /etc/apt/sources.list.d/myvpn-mozilla.list /etc/apt/preferences.d/myvpn-mozilla
apt-get update -qq
apt-get install -y -qq --no-install-recommends firefox >/dev/null

id "$desktop_user" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$desktop_user"
if ! getent hosts "$(hostname)" >/dev/null; then
  server_name=$(hostname)
  [[ $server_name =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo 'Invalid local hostname' >&2; exit 1; }
  printf '127.0.1.1 %s.local %s\n' "$server_name" "$server_name" >>/etc/hosts
fi
install -d -m 700 -o "$desktop_user" -g "$desktop_user" "$desktop_home/.ssh" "$desktop_home/.vnc"
public_key=$(cat "$SSH_PUBLIC_KEY_FILE")
printf 'restrict,port-forwarding,permitopen="127.0.0.1:6080" %s\n' "$public_key" >"$desktop_home/.ssh/authorized_keys"
tigervncpasswd -f <"$VNC_PASSWORD_FILE" >"$desktop_home/.vnc/passwd"
chown "$desktop_user:$desktop_user" "$desktop_home/.ssh/authorized_keys" "$desktop_home/.vnc/passwd"
chmod 600 "$desktop_home/.ssh/authorized_keys" "$desktop_home/.vnc/passwd"
cat >/etc/ssh/sshd_config.d/70-myvpn-desktop.conf <<'EOF'
Match User myvpn-desktop
    PasswordAuthentication no
    AllowTcpForwarding local
    PermitOpen 127.0.0.1:6080
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    ForceCommand /bin/false
Match all
EOF
chmod 644 /etc/ssh/sshd_config.d/70-myvpn-desktop.conf
sshd -t
systemctl reload ssh

if ! swapon --show=NAME --noheadings | grep -Fx /swapfile-myvpn-desktop >/dev/null; then
  if [[ ! -f /swapfile-myvpn-desktop ]]; then
    fallocate -l 2G /swapfile-myvpn-desktop
    chmod 600 /swapfile-myvpn-desktop
    mkswap /swapfile-myvpn-desktop >/dev/null
  fi
  swapon /swapfile-myvpn-desktop
fi
grep -q '^/swapfile-myvpn-desktop ' /etc/fstab || printf '/swapfile-myvpn-desktop none swap sw 0 0\n' >>/etc/fstab
install -d -m 755 /usr/local/lib/myvpn-desktop
cat >/usr/local/lib/myvpn-desktop/session <<'EOF'
#!/bin/sh
unset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS
exec dbus-run-session -- startxfce4
EOF
chmod 755 /usr/local/lib/myvpn-desktop/session
install -m 644 "$source_dir/myvpn.html" /usr/share/novnc/myvpn.html
install -d -m 755 -o "$desktop_user" -g "$desktop_user" "$desktop_home/Desktop" "$desktop_home/.config/autostart"
cat >"$desktop_home/.config/autostart/firefox.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Firefox
Exec=firefox --new-window about:blank
Terminal=false
EOF
chmod 644 "$desktop_home/.config/autostart/firefox.desktop"
chown -R "$desktop_user:$desktop_user" "$desktop_home/.config"
cat >/etc/systemd/system/myvpn-desktop.service <<'EOF'
[Unit]
Description=My VPN private XFCE desktop
After=network.target
[Service]
Type=simple
User=myvpn-desktop
Group=myvpn-desktop
WorkingDirectory=/home/myvpn-desktop
Environment=HOME=/home/myvpn-desktop
Environment=XDG_RUNTIME_DIR=/run/myvpn-desktop
RuntimeDirectory=myvpn-desktop
RuntimeDirectoryMode=0700
ExecStart=/usr/bin/tigervncserver -fg -localhost yes -SecurityTypes VncAuth -rfbauth /home/myvpn-desktop/.vnc/passwd -geometry 1440x900 -depth 24 -xstartup /usr/local/lib/myvpn-desktop/session :1
Restart=on-failure
RestartSec=3
KillMode=control-group
TimeoutStopSec=15
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=/home/myvpn-desktop /run/myvpn-desktop
CPUWeight=20
MemoryHigh=1100M
MemoryMax=1400M
TasksMax=512
[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/myvpn-desktop-web.service <<'EOF'
[Unit]
Description=My VPN private noVNC gateway
After=myvpn-desktop.service
Requires=myvpn-desktop.service
[Service]
User=myvpn-desktop
Group=myvpn-desktop
ExecStart=/usr/bin/websockify --web /usr/share/novnc 127.0.0.1:6080 127.0.0.1:5901
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=150M
CPUWeight=20
[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/myvpn-desktop{,-web}.service
systemctl daemon-reload
systemctl enable --now myvpn-desktop.service myvpn-desktop-web.service
echo 'Private full desktop installed; SSH forwards only to loopback noVNC'
