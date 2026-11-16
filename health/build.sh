#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:$PATH"
TARGET="${1:-all}"
if [[ $TARGET == mac || $TARGET == all ]]; then
  mkdir -p ../macos/vendor
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o ../macos/vendor/health-core ./cmd/health-core
fi
if [[ $TARGET == android || $TARGET == all ]]; then
  NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk/27.2.12479018}"
  for spec in arm64-v8a:arm64:aarch64-linux-android armeabi-v7a:arm:armv7a-linux-androideabi x86_64:amd64:x86_64-linux-android; do
    IFS=: read -r abi arch triple <<< "$spec"
    mkdir -p "../android/app/src/main/jniLibs/$abi"
    GOOS=android GOARCH="$arch" GOARM=7 CGO_ENABLED=1 CC="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/${triple}24-clang" \
      go build -buildmode=pie -trimpath -ldflags='-s -w -extldflags=-Wl,-z,max-page-size=16384' -o "../android/app/src/main/jniLibs/$abi/libmyvpnhealth.so" ./cmd/health-core
  done
fi
