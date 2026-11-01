#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
BUNDLE_ID="dev.proxysift.app"
APP_NAME="ProxySift"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script packages the macOS GUI and must run on macOS." >&2
  exit 2
fi

case "$(uname -m)" in
  arm64|x86_64) ARCH="$(uname -m)" ;;
  *) echo "Unsupported macOS architecture: $(uname -m)" >&2; exit 2 ;;
esac

VERSION="$(cargo pkgid --manifest-path "$ROOT_DIR/Cargo.toml" | sed -E 's/.*@//')"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proxysift-package.XXXXXX")"
APP_BUNDLE="$TEMP_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_MACOS="$APP_CONTENTS/MacOS"
APP_BINARY="$APP_MACOS/$APP_NAME"
ARCHIVE_NAME="$APP_NAME-$VERSION-macos-$ARCH.zip"
TEMP_ARCHIVE="$TEMP_DIR/$ARCHIVE_NAME"
FINAL_ARCHIVE="$DIST_DIR/$ARCHIVE_NAME"

cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$DIST_DIR" "$APP_MACOS"
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --workspace --release --locked
cp "$ROOT_DIR/target/release/proxy-sift" "$APP_BINARY"
chmod 755 "$APP_BINARY"

cat > "$APP_CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$APP_NAME</string>
  <key>CFBundleIdentifier</key>
  <string>$BUNDLE_ID</string>
  <key>CFBundleName</key>
  <string>$APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>CFBundleVersion</key>
  <string>$VERSION</string>
  <key>LSApplicationCategoryType</key>
  <string>public.app-category.utilities</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
PLIST

plutil -lint "$APP_CONTENTS/Info.plist"

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$APP_BUNDLE"
  codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
else
  echo "CODESIGN_IDENTITY is unset; packaging an unsigned app bundle."
fi

ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$TEMP_ARCHIVE"

if [[ "${NOTARIZE:-false}" == "true" ]]; then
  if [[ -z "${CODESIGN_IDENTITY:-}" || -z "${APPLE_ID:-}" || -z "${APPLE_TEAM_ID:-}" || -z "${APPLE_APP_SPECIFIC_PASSWORD:-}" ]]; then
    echo "Notarization requires CODESIGN_IDENTITY, APPLE_ID, APPLE_TEAM_ID, and APPLE_APP_SPECIFIC_PASSWORD." >&2
    exit 2
  fi
  xcrun notarytool submit "$TEMP_ARCHIVE" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_SPECIFIC_PASSWORD" \
    --wait
  xcrun stapler staple "$APP_BUNDLE"
  xcrun stapler validate "$APP_BUNDLE"
  ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$TEMP_ARCHIVE"
fi

mv -f "$TEMP_ARCHIVE" "$FINAL_ARCHIVE"
shasum -a 256 "$FINAL_ARCHIVE" | tee "$FINAL_ARCHIVE.sha256"
echo "Created $FINAL_ARCHIVE"
