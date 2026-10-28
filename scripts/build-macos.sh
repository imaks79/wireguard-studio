#!/usr/bin/env bash
# Builds "WireGuard Studio.app" and a .zip of it into dist/.
# Run on macOS: ./scripts/build-macos.sh
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(uname -m)"
APP_NAME="WireGuard Studio"
DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"

# Stale `rustc -vV` cache can survive a Homebrew LLVM upgrade.
rm -f target/.rustc_info.json

cargo build --release -p wireguard-studio-gui

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp target/release/wireguard-studio "$APP/Contents/MacOS/wireguard-studio"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$APP_NAME</string>
  <key>CFBundleDisplayName</key><string>$APP_NAME</string>
  <key>CFBundleIdentifier</key><string>io.github.wireguard-studio</string>
  <key>CFBundleExecutable</key><string>wireguard-studio</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Ad-hoc signature so Apple Silicon will launch it (not notarized).
codesign --force --deep --sign - "$APP"

ZIP="$DIST/wireguard-studio-$VERSION-macos-$ARCH.zip"
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"

echo "Built: $APP"
echo "       $ZIP"
