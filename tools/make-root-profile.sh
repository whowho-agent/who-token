#!/bin/bash
# Builds an iOS configuration profile (.mobileconfig) that installs a root CA certificate,
# so Safari trusts internal sites whose server certificates were issued by that CA.
#
#   tools/make-root-profile.sh <root-ca.pem|.cer|.crt> [output.mobileconfig]
#
# Prints the certificate subject, expiry and SHA-256 fingerprint: compare the fingerprint with the one
# published by your IT department before installing the profile.
set -euo pipefail

if (( $# < 1 )); then
  echo "usage: $0 <root-ca.pem|.cer|.crt> [output.mobileconfig]" >&2
  exit 2
fi
INPUT="$1"
OPENSSL="${OPENSSL:-openssl}"

# Accept PEM or DER.
DER="$(mktemp)"
trap 'rm -f "$DER"' EXIT
if ! "$OPENSSL" x509 -in "$INPUT" -outform der -out "$DER" 2>/dev/null; then
  "$OPENSSL" x509 -inform der -in "$INPUT" -outform der -out "$DER"
fi

SUBJECT_CN="$("$OPENSSL" x509 -inform der -in "$DER" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p' | head -1)"
NAME="${SUBJECT_CN:-Root CA}"
IS_CA="$("$OPENSSL" x509 -inform der -in "$DER" -noout -ext basicConstraints 2>/dev/null | grep -c 'CA:TRUE' || true)"
if [[ "$IS_CA" == "0" ]]; then
  echo "warning: this certificate is not a CA certificate (no CA:TRUE); Safari won't use it as a root" >&2
fi
OUTPUT="${2:-$NAME.mobileconfig}"

B64="$(base64 < "$DER" | tr -d '\n')"
UUID1="$(uuidgen)"
UUID2="$(uuidgen)"
cat > "$OUTPUT" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>$NAME.cer</string>
      <key>PayloadContent</key><data>$B64</data>
      <key>PayloadDisplayName</key><string>$NAME</string>
      <key>PayloadIdentifier</key><string>local.rutoken-safari.root.$UUID1</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>$UUID1</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>Корневой сертификат: $NAME</string>
  <key>PayloadIdentifier</key><string>local.rutoken-safari.profile.$UUID2</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>$UUID2</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
PLIST
plutil -lint "$OUTPUT" >/dev/null

echo "Profile:  $OUTPUT"
"$OPENSSL" x509 -inform der -in "$DER" -noout -subject -enddate
"$OPENSSL" x509 -inform der -in "$DER" -noout -fingerprint -sha256
