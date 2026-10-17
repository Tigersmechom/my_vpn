#!/bin/bash
# Run on Ubuntu 24.04 with Go, git, curl, unzip, gcc, make and libc6-dev.
set -euo pipefail
cd "$(dirname "$0")"
[[ $(uname -s) == Linux ]] || { echo 'Run this script on Linux; build.py also runs on macOS with prepared cores.' >&2; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo 'Build native cores on Ubuntu 24.04 to match the package runtime libraries.' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64; archive=Xray-linux-64.zip; checksum=f851110beaff16e78d643f0ccfd9524b4a44dfd59bae3e34bb52bba378f7690e ;;
  aarch64) arch=arm64; archive=Xray-linux-arm64-v8a.zip; checksum=9886f077f9fd8e6713b84c377c1c7db4e53b9bfa8c276a5bd12561139522b473 ;;
  *) echo 'Supported architectures: amd64, arm64' >&2; exit 1 ;;
esac
vendor="$PWD/vendor/$arch"
mkdir -p "$vendor"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
curl -fsSL --retry 3 -o "$stage/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/v26.9.30/$archive"
printf '%s  %s\n' "$checksum" "$stage/xray.zip" | sha256sum -c -
unzip -qo "$stage/xray.zip" xray LICENSE -d "$stage/xray"
install -m 755 "$stage/xray/xray" "$vendor/xray"
install -m 644 "$stage/xray/LICENSE" "$vendor/LICENSE-Xray"
git clone -q --depth 1 --branch v3.1.20260828 https://github.com/amnezia-vpn/amneziawg-go.git "$stage/awg-go"
[[ $(git -C "$stage/awg-go" rev-parse HEAD) == b5928efb6ca19f0153958460c3d141f04abc5c2e ]]
(cd "$stage/awg-go"; CGO_ENABLED=0 go build -trimpath -ldflags=-s -o "$vendor/amneziawg-go" .)
install -m 644 "$stage/awg-go/LICENSE" "$vendor/LICENSE-AmneziaWG-Go"
git clone -q --depth 1 --branch v1.0.20260618-2 https://github.com/amnezia-vpn/amneziawg-tools.git "$stage/awg-tools"
[[ $(git -C "$stage/awg-tools" rev-parse HEAD) == 61e741780e8465a67a7d7fb6cffe14a8a15d624a ]]
make -C "$stage/awg-tools/src" -j2
install -m 755 "$stage/awg-tools/src/wg" "$vendor/awg"
install -m 644 "$stage/awg-tools/COPYING" "$vendor/LICENSE-AmneziaWG-Tools"
printf 'Cores ready: %s\n' "$vendor"
