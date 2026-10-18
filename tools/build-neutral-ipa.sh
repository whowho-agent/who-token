#!/bin/bash
# Builds dist/Rutoken-unsigned.ipa for colleagues who sign it themselves (Sideloadly):
# neutral bundle id, no Apple signature or personal data, ad-hoc signed with placeholder-team
# entitlements so the re-signer can carry the shared keychain group over to its own team.
#
#   tools/build-neutral-ipa.sh [bundle-id]          default com.example.RutokenSafari
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

BUNDLE_ID="${1:-com.example.RutokenSafari}"
TEAM_PLACEHOLDER="XXXXXXXXXX"
DERIVED=.build/neutral
WORK=$DERIVED/sign
OUT=dist/Rutoken-unsigned.ipa

xcodegen generate -q
xcodebuild -project Rutoken.xcodeproj -scheme Rutoken -configuration Release \
  -destination 'generic/platform=iOS' -derivedDataPath "$DERIVED" -skipPackagePluginValidation \
  RB_BUNDLE_ID="$BUNDLE_ID" DEVELOPMENT_TEAM= CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= \
  OTHER_CFLAGS="\$(inherited) -ffile-prefix-map=$ROOT=." \
  OTHER_SWIFT_FLAGS="\$(inherited) -file-prefix-map $ROOT=." \
  build -quiet

rm -rf "$WORK" && mkdir -p "$WORK/Payload"
cp -R "$DERIVED/Build/Products/Release-iphoneos/Rutoken.app" "$WORK/Payload/"
APP="$WORK/Payload/Rutoken.app"

entitlements() { # <file> <bundle id>
  cat > "$1" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>application-identifier</key><string>$TEAM_PLACEHOLDER.$2</string>
  <key>com.apple.developer.team-identifier</key><string>$TEAM_PLACEHOLDER</string>
  <key>keychain-access-groups</key>
  <array><string>$TEAM_PLACEHOLDER.$BUNDLE_ID.shared</string></array>
</dict>
</plist>
PLIST
}
entitlements "$WORK/app.plist" "$BUNDLE_ID"
entitlements "$WORK/token.plist" "$BUNDLE_ID.TokenExtension"
entitlements "$WORK/safari.plist" "$BUNDLE_ID.SafariExtension"

shopt -s nullglob
for item in "$APP"/Frameworks/*.framework "$APP"/PlugIns/*.appex/Frameworks/*.framework "$APP"/*.dylib "$APP"/PlugIns/*.appex/*.dylib; do
  codesign -f -s - "$item" 2>/dev/null
done
codesign -f -s - --entitlements "$WORK/token.plist" "$APP/PlugIns/RutokenTokenExtension.appex" 2>/dev/null
codesign -f -s - --entitlements "$WORK/safari.plist" "$APP/PlugIns/RutokenSafariExtension.appex" 2>/dev/null
codesign -f -s - --entitlements "$WORK/app.plist" "$APP" 2>/dev/null
codesign --verify --deep "$APP"

mkdir -p dist && rm -f "$OUT"
(cd "$WORK" && zip -qry "$OLDPWD/$OUT" Payload)
echo "$OUT ($(du -h "$OUT" | cut -f1)), bundle id $BUNDLE_ID"
