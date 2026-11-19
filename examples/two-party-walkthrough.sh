#!/usr/bin/env bash
#
# End-to-end OTL Identity walkthrough: an LOU issues an LEI credential to a
# VASP, the VASP publishes it, a counterparty fetches and validates it, and
# then revocation flips it to invalid.
#
# Everything runs locally over real HTTPS. Resolution is HTTPS-only with no
# bypass, so the script generates a throwaway certificate and points Node at
# it — rather than the CLI growing an insecure mode for demos.
#
# Usage:  examples/two-party-walkthrough.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OTL="node --experimental-strip-types --conditions=otl-source ${ROOT}/packages/cli/src/bin.ts"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "${WORK}"' EXIT

LOU_PORT=8443
VASP_PORT=8444
# Every party here is on localhost, which the resolver refuses by default as a
# private address. Commands that fetch from another party opt in explicitly.
LOCAL=--allow-private-addresses
# Generated per run rather than hardcoded. These protect throwaway keys in a
# directory deleted on exit, so nothing is at stake here -- but an example is
# copied, and a literal passphrase in a script is the wrong thing to copy.
export OTL_KEYSTORE_PASSPHRASE="$(openssl rand -base64 24)"
export OTL_PREROTATION_PASSPHRASE="$(openssl rand -base64 24)"

step() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
note() { printf '   %s\n' "$1"; }

step "0. A throwaway TLS certificate for localhost"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" \
  -keyout "${WORK}/tls.key" -out "${WORK}/tls.crt" 2>/dev/null
export NODE_EXTRA_CA_CERTS="${WORK}/tls.crt"
note "clients will trust ${WORK}/tls.crt for this run only"

# Each party gets its own OTL_HOME, as three separate operators would.
LOU_HOME="${WORK}/lou"; VASP_HOME="${WORK}/vasp"; PEER_HOME="${WORK}/peer"

step "1. The LOU creates its DID and an issuance key"
LOU_DID=$(OTL_HOME=$LOU_HOME $OTL did create --domain "localhost:${LOU_PORT}" --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0)).did")
note "$LOU_DID"
OTL_HOME=$LOU_HOME $OTL credential add-issuance-key --json >/dev/null 2>&1
note "added #credential-issuance-key (spec 3.2.1)"

step "2. The VASP creates its DID"
VASP_DID=$(OTL_HOME=$VASP_HOME $OTL did create --domain "localhost:${VASP_PORT}" --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0)).did")
note "$VASP_DID"

# A port already in use makes `serve` die silently, and the run then fetches
# from whatever else is listening -- producing a confusing half-failure several
# steps later rather than an error here. Check first.
for port in $LOU_PORT $VASP_PORT; do
  if lsof -nP -iTCP:$port -sTCP:LISTEN >/dev/null 2>&1; then
    echo "error: port ${port} is already in use." >&2
    echo "  Something else is listening there; this walkthrough needs both" >&2
    echo "  ${LOU_PORT} and ${VASP_PORT}. Find it with: lsof -nP -iTCP:${port} -sTCP:LISTEN" >&2
    exit 1
  fi
done

step "3. Both publish their DID logs over HTTPS"
LOU_EXPORT=$(OTL_HOME=$LOU_HOME $OTL export --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0)).exportDir")
VASP_EXPORT=$(OTL_HOME=$VASP_HOME $OTL export --json 2>/dev/null | node -p "JSON.parse(require('fs').readFileSync(0)).exportDir")
OTL_HOME=$LOU_HOME  $OTL serve --port $LOU_PORT  --cert "${WORK}/tls.crt" --key "${WORK}/tls.key" >"${WORK}/lou-serve.log" 2>&1 &
OTL_HOME=$VASP_HOME $OTL serve --port $VASP_PORT --cert "${WORK}/tls.crt" --key "${WORK}/tls.key" >"${WORK}/vasp-serve.log" 2>&1 &

# Wait for both to actually answer. Proceeding on a fixed sleep is what turns a
# dead server into "credential INVALID" six steps later.
for entry in "LOU:${LOU_PORT}" "VASP:${VASP_PORT}"; do
  name="${entry%%:*}"; port="${entry##*:}"; ready=""
  for _ in $(seq 1 40); do
    if curl -sf --cacert "${WORK}/tls.crt" "https://localhost:${port}/.well-known/did.jsonl" >/dev/null 2>&1; then
      ready=yes; break
    fi
    sleep 0.25
  done
  if [ -z "$ready" ]; then
    echo "error: the ${name} server on port ${port} never became ready." >&2
    sed 's/^/  /' "${WORK}/$(echo "$name" | tr '[:upper:]' '[:lower:]')-serve.log" >&2 || true
    exit 1
  fi
done
note "LOU  → https://localhost:${LOU_PORT}/.well-known/did.jsonl"
note "VASP → https://localhost:${VASP_PORT}/.well-known/did.jsonl"

step "4. A counterparty validates the VASP's DID to genesis"
OTL_HOME=$PEER_HOME $OTL validate "$VASP_DID" "$LOCAL" 2>/dev/null | sed 's/^/   /'

step "5. The LOU issues an LEI credential to the VASP"
# 00000000000000000098 is a synthetic LEI with valid ISO 17442 check digits.
# --gleif-file supplies a Level 1 record locally, so the walkthrough needs no
# network and no real company's data. The record is still validated against
# spec 4.9; only the lookup is bypassed.
OTL_HOME=$LOU_HOME $OTL credential issue \
  --lei 00000000000000000098 --subject "$VASP_DID" \
  --gleif-file "${ROOT}/examples/gleif-record.json" --json > "${WORK}/issued.json" 2>/dev/null
node -e "
  const r = JSON.parse(require('fs').readFileSync('${WORK}/issued.json','utf8'));
  require('fs').writeFileSync('${WORK}/credential.json', JSON.stringify(r.credential, null, 2));
  console.log('   ' + r.credential.id);
  console.log('   subject: ' + r.credential.credentialSubject.entity.legalName);
"

step "6. The VASP stores it and publishes a presentation"
OTL_HOME=$VASP_HOME $OTL credential add --file "${WORK}/credential.json" 2>/dev/null | sed 's/^/   /'
OTL_HOME=$VASP_HOME $OTL whois publish --json >/dev/null 2>&1
OTL_HOME=$VASP_HOME $OTL export --json >/dev/null 2>&1
note "published https://localhost:${VASP_PORT}/.well-known/whois.vp"

step "7. The counterparty fetches the credential — with an EMPTY trust perimeter"
OTL_HOME=$PEER_HOME $OTL credential fetch "$VASP_DID" "$LOCAL" 2>&1 | sed 's/^/   /' || true
note "rejected: no protocol-defined root of trust exists (spec 4.6)"

step "8. The counterparty decides to trust this LOU"
OTL_HOME=$PEER_HOME $OTL trust add --did "$LOU_DID" --note "walkthrough LOU" 2>/dev/null | sed 's/^/   /'

step "9. It fetches again — now valid"
OTL_HOME=$PEER_HOME $OTL credential fetch "$VASP_DID" "$LOCAL" 2>/dev/null | sed 's/^/   /'

step "10. The LOU revokes the credential"
CRED_ID=$(node -p "JSON.parse(require('fs').readFileSync('${WORK}/credential.json','utf8')).id")
OTL_HOME=$LOU_HOME $OTL credential revoke --credential "$CRED_ID" 2>/dev/null | sed 's/^/   /'
OTL_HOME=$LOU_HOME $OTL export --json >/dev/null 2>&1

step "11. The counterparty fetches once more — now INVALID"
# Exits 2 because the credential is no longer valid, which is the point here.
OTL_HOME=$PEER_HOME $OTL credential fetch "$VASP_DID" "$LOCAL" 2>/dev/null | sed 's/^/   /' || true

printf '\n\033[1mDone.\033[0m Nothing was trusted by default; the counterparty had to choose.\n'
