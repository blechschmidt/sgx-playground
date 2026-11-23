#!/usr/bin/env bash
# Probes which Intel PCS endpoints answer without an API key
# (docs/NO_API_KEY.md). Needs only curl and Internet access; no SGX.
#
#   scripts/check-intel-pcs-keyless.sh [--pcs URL]
#
# The PCK certificate endpoints are probed with a made-up encrypted PPID:
# an answer of 400 (InvalidRequestSyntax) means the request got past
# authentication, 401 means it needs a key. Two controls show that the
# 401 check works: PCS v3, and v4 with an empty key header (which is what
# the stock PCCS sends when its ApiKey is "").
set -euo pipefail

pcs=https://api.trustedservices.intel.com
while [ $# -gt 0 ]; do
    case "$1" in
        --pcs) pcs="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "check-intel-pcs-keyless.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

base="$pcs/sgx/certification"
ppid="$(printf 'A%.0s' $(seq 768))"     # 384 bytes, hex: well-formed length, bogus value
cpusvn=00000000000000000000000000000000
fmspc=00606A000000                      # any FMSPC known to Intel
failed=0

# probe NAME EXPECTED URL [curl args...]
probe() {
    local name="$1" want="$2" url="$3"; shift 3
    local got
    got="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 30 "$@" "$url" || echo 000)"
    if [ "$got" = "$want" ]; then
        printf 'ok    %-48s %s\n' "$name" "$got"
    else
        printf 'FAIL  %-48s %s (expected %s)\n' "$name" "$got" "$want"
        failed=1
    fi
}

echo "Keyless requests to $pcs:"
probe "v4 pckcert  (quote generation, QCNL)" 400 \
    "$base/v4/pckcert?encrypted_ppid=$ppid&cpusvn=$cpusvn&pcesvn=0000&pceid=0000"
probe "v4 pckcerts (PCCS REQ mode)" 400 \
    "$base/v4/pckcerts?encrypted_ppid=$ppid&pceid=0000"
probe "v4 tcb      (verification)" 200 "$base/v4/tcb?fmspc=$fmspc"
probe "v4 qe/identity (verification)" 200 "$base/v4/qe/identity"
probe "v4 pckcrl   (verification)" 200 "$base/v4/pckcrl?ca=platform&encoding=der"
probe "Root CA CRL (verification)" 200 \
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
echo "Controls (must be refused):"
probe "v3 pckcert  without key" 401 \
    "$base/v3/pckcert?encrypted_ppid=$ppid&cpusvn=$cpusvn&pcesvn=0000&pceid=0000"
probe "v4 pckcerts with empty key header" 401 \
    "$base/v4/pckcerts?encrypted_ppid=$ppid&pceid=0000" -H 'Ocp-Apim-Subscription-Key;'

if [ "$failed" -eq 0 ]; then
    echo "Intel PCS v4 needs no API key for quote generation or verification."
else
    echo "Intel PCS behaved differently than docs/NO_API_KEY.md describes." >&2
fi
exit "$failed"
