#!/bin/bash
# mTLS test stand: HTTPS server that requires a client certificate issued by one of the CAs
# in stand/ca/*.pem (put the root and intermediate CAs of your token certificate there).
#
#   stand/run-stand.sh [port]          default port 8443
#
# The server certificate is issued by a local "Test Stand CA" (stand/pki/, not committed).
# To open the stand in Safari, install stand/pki/stand-ca.pem on the iPhone as a profile and enable full
# trust for it. The page (openssl s_server -www) shows the TLS session and the verified client certificate.
set -euo pipefail

cd "$(dirname "$0")"
PORT="${1:-8443}"
OPENSSL="${OPENSSL:-/opt/homebrew/bin/openssl}"
IP="$(ipconfig getifaddr en0 || echo 127.0.0.1)"
HOST="$(scutil --get LocalHostName).local"
PKI=pki
mkdir -p "$PKI"

if [[ ! -f $PKI/stand-ca.key ]]; then
  "$OPENSSL" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
    -keyout $PKI/stand-ca.key -out $PKI/stand-ca.pem \
    -subj "/O=RutokenBrowser/CN=RutokenBrowser Test Stand CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# Reissue the server certificate on every start: the Mac's IP may change.
"$OPENSSL" req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout $PKI/server.key -out $PKI/server.csr -subj "/CN=$HOST" 2>/dev/null
"$OPENSSL" x509 -req -in $PKI/server.csr -CA $PKI/stand-ca.pem -CAkey $PKI/stand-ca.key -CAcreateserial \
  -days 30 -out $PKI/server.pem \
  -extfile <(printf "subjectAltName=DNS:%s,DNS:localhost,IP:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature" "$HOST" "$IP") 2>/dev/null
shopt -s nullglob
CLIENT_CAS=(ca/*.pem)
if (( ${#CLIENT_CAS[@]} == 0 )); then
  echo "No client CA certificates in stand/ca/*.pem, see stand/ca/README.md" >&2
  exit 1
fi
cat "${CLIENT_CAS[@]}" > $PKI/client-ca-chain.pem

echo "mTLS stand: https://$IP:$PORT/  (https://$HOST:$PORT/)"
echo "Client CAs: ${CLIENT_CAS[*]}"
exec "$OPENSSL" s_server -accept "$PORT" \
  -cert $PKI/server.pem -key $PKI/server.key \
  -CAfile $PKI/client-ca-chain.pem -Verify 2 -verify_return_error \
  -www
