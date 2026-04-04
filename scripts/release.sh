#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENT="$ROOT/client"
MOBILE="$ROOT/mobile"
UPDATES="$ROOT/server/updates"

VERSION=$(node -p "require('$CLIENT/package.json').version")

echo "==> Build Linux..."
cd "$CLIENT" && ~/.nvm/versions/node/v20.20.1/bin/npm run build:linux

echo "==> Build Windows..."
~/.nvm/versions/node/v20.20.1/bin/npm run build:win

echo "==> Build APK..."
cd "$MOBILE" && ~/.nvm/versions/node/v20.20.1/bin/npm run build
cd "$MOBILE/android" && ./gradlew assembleRelease --quiet
APK_IN="$MOBILE/android/app/build/outputs/apk/release/app-release-unsigned.apk"
APK_OUT="$MOBILE/Realm-${VERSION}.apk"
~/android-sdk/build-tools/$(ls ~/android-sdk/build-tools/ | tail -1)/apksigner sign \
  --ks "$MOBILE/realm-release.keystore" --ks-pass pass:realm2024 --ks-key-alias realm \
  --out "$APK_OUT" "$APK_IN"

echo "==> Copie des artefacts vers server/updates/..."
mkdir -p "$UPDATES"
cp "$CLIENT/dist/latest.yml"                            "$UPDATES/"
cp "$CLIENT/dist/latest-linux.yml"                      "$UPDATES/"
cp "$CLIENT/dist/Realm-${VERSION}.AppImage"             "$UPDATES/"
cp "$CLIENT/dist/Realm Setup ${VERSION}.exe"            "$UPDATES/"
cp "$CLIENT/dist/Realm Setup ${VERSION}.exe.blockmap"   "$UPDATES/"

echo "==> Redémarrage du service..."
echo "12347" | sudo -S systemctl restart vox.service

echo ""
echo "Realm v${VERSION} déployé localement."
echo "  Linux  : $UPDATES/Realm-${VERSION}.AppImage"
echo "  Windows: $UPDATES/Realm Setup ${VERSION}.exe"
echo "  APK    : $APK_OUT"
