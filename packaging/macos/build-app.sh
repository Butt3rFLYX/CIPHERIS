#!/bin/bash
# Builds dist/CIPHERIS.app and dist/CIPHERIS-macOS.zip on a Mac.
#   packaging/macos/build-app.sh             for this Mac only
#   packaging/macos/build-app.sh --universal Apple Silicon and Intel in one app
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
APP=dist/CIPHERIS.app
rm -rf "$APP" dist/CIPHERIS-macOS.zip
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

LOCKED=""
[ -f Cargo.lock ] && LOCKED="--locked"

if [[ "${1:-}" == "--universal" ]]; then
  rustup target add aarch64-apple-darwin x86_64-apple-darwin
  cargo build --release $LOCKED -p cipheris --target aarch64-apple-darwin
  cargo build --release $LOCKED -p cipheris --target x86_64-apple-darwin
  lipo -create -output "$APP/Contents/MacOS/cipheris" \
    target/aarch64-apple-darwin/release/cipheris \
    target/x86_64-apple-darwin/release/cipheris
else
  cargo build --release $LOCKED -p cipheris
  cp target/release/cipheris "$APP/Contents/MacOS/cipheris"
fi

# The icon set is rendered ahead of time (packaging/macos/AppIcon.iconset):
# 16 and 32 px come from the small logo, larger sizes from LOGO on its tile.
iconutil -c icns packaging/macos/AppIcon.iconset -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>CIPHERIS</string>
  <key>CFBundleDisplayName</key><string>CIPHERIS</string>
  <key>CFBundleIdentifier</key><string>io.github.butt3rflyx.cipheris</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>cipheris</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>MIT License</string>
</dict>
</plist>
PLIST

# Ad hoc signature (no paid Apple Developer ID).
codesign --force --deep --sign - "$APP"

(cd dist && ditto -c -k --keepParent CIPHERIS.app CIPHERIS-macOS.zip)
echo
echo "Done: $APP"
echo "Drag CIPHERIS.app into your Applications folder to install it."
