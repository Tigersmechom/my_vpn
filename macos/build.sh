#!/bin/bash
# Сборка My VPN.app для macOS (Apple Silicon).
#   ./build.sh            → build/My VPN.app
# Нужны: Xcode (swift), Go (brew install go), git, curl.
set -euo pipefail
cd "$(dirname "$0")"

XRAY_VERSION=v26.9.30
XRAY_SHA256=4b363bd924df5bf09f87bd445755ff8e5742b9a8a0480cda261061416c3c7dce
AWG_GO_REF=v3.1.20260828
AWG_TOOLS_REF=v1.0.20260618-2

VENDOR="$PWD/vendor"
APP="$PWD/build/My VPN.app"
mkdir -p "$VENDOR"
export PATH="/opt/homebrew/bin:$PATH"

step() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }

if [[ ! -x $VENDOR/xray ]]; then
  step "Xray $XRAY_VERSION"
  tmp="$(mktemp -d)"
  curl -fsSL --retry 3 -o "$tmp/xray.zip" \
    "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-macos-arm64-v8a.zip"
  echo "$XRAY_SHA256  $tmp/xray.zip" | shasum -a 256 -c - >/dev/null
  unzip -qo "$tmp/xray.zip" xray -d "$VENDOR"
  rm -rf "$tmp"
fi

if [[ ! -x $VENDOR/amneziawg-go ]]; then
  step "amneziawg-go $AWG_GO_REF"
  command -v go >/dev/null || { echo "Нужен Go: brew install go" >&2; exit 1; }
  rm -rf "$VENDOR/src-awg-go"
  git clone -q --depth 1 --branch "$AWG_GO_REF" https://github.com/amnezia-vpn/amneziawg-go.git "$VENDOR/src-awg-go"
  make -C "$VENDOR/src-awg-go" >/dev/null
  cp "$VENDOR/src-awg-go/amneziawg-go" "$VENDOR/amneziawg-go"
fi

if [[ ! -x $VENDOR/awg ]]; then
  step "amneziawg-tools $AWG_TOOLS_REF"
  rm -rf "$VENDOR/src-awg-tools"
  git clone -q --depth 1 --branch "$AWG_TOOLS_REF" https://github.com/amnezia-vpn/amneziawg-tools.git "$VENDOR/src-awg-tools"
  MACOSX_DEPLOYMENT_TARGET=13.0 make -C "$VENDOR/src-awg-tools/src" >/dev/null
  cp "$VENDOR/src-awg-tools/src/wg" "$VENDOR/awg"
fi

step "Swift"
swift build -c release --arch arm64
BIN="$(swift build -c release --arch arm64 --show-bin-path)/MyVPN"

step "Иконка"
ICONSET="$PWD/build/AppIcon.iconset"
rm -rf "$ICONSET"
swift scripts/make-icon.swift "$ICONSET"
iconutil -c icns "$ICONSET" -o "$PWD/build/AppIcon.icns"

step "Сборка .app"
PROFILE=../config/mac.json
[[ -f $PROFILE ]] || { PROFILE=../config/example.json; echo "config/mac.json нет — беру шаблон example.json"; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/MyVPN"
cp "$VENDOR/xray" "$VENDOR/amneziawg-go" "$VENDOR/awg" helper/myvpn-helper helper/install-helper.sh "$APP/Contents/Resources/"
cp "$PROFILE" "$APP/Contents/Resources/default_profile.json"
if [[ -f ../config/mac-update.json ]]; then
  cp ../config/mac-update.json "$APP/Contents/Resources/update_bootstrap.json"
fi
cp "$PWD/build/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cat >"$APP/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>app.myvpn.mac</string>
  <key>CFBundleName</key><string>My VPN</string>
  <key>CFBundleDisplayName</key><string>My VPN</string>
  <key>CFBundleExecutable</key><string>MyVPN</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.1.0</string>
  <key>CFBundleVersion</key><string>2</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Копирование из Finder/архива может принести ресурсные атрибуты, несовместимые с подписью.
xattr -cr "$APP"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
step "Готово: $APP"
