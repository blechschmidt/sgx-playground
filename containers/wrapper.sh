#!/bin/sh
# stunnel `exec` target for the remote executor, running the containerized
# Rust host (nix build .#host-app-image, or scripts/nix-build-host-image.sh).
#
# sgx-playground/config/server/stunnel.conf runs one copy of this script per
# TLS connection, with the decrypted stream on stdin/stdout:
#
#   [sgx-playground]
#   accept = 0.0.0.0:443
#   cert   = /etc/letsencrypt/live/<host>/fullchain.pem
#   key    = /etc/letsencrypt/live/<host>/privkey.pem
#   exec   = /path/to/sgx-ra/containers/wrapper.sh
#
# The container gets
#   * /dev/sgx_enclave   to load our enclave and Intel's QE3/ID enclave,
#   * /dev/sgx_provision for the PCE (it has the PROVISION_KEY attribute),
#   * a QCNL config, if $SGX_RA_QCNL_CONF names one. Without it the image's
#     built-in config fetches the PCK certificate from Intel's PCS v4, which
#     needs no API key and no PCCS (docs/NO_API_KEY.md). Point it at e.g.
#     config/sgx_default_qcnl.local-pccs.conf to use a PCCS instead,
#   * host networking, so such a PCCS on localhost:8081 is reachable.
# Nothing else: no privileged mode, no volumes with secrets. The host app
# is untrusted and never sees a key.
#
# `-i` keeps stdin open; no `-t` (a TTY would mangle the binary stream).
#
# The host app keeps the wire on stdout and all diagnostics on stderr
# (crates/sgx-ra-host/src/stdio.rs). stunnel's `exec`, however, connects the
# child's stdin, stdout AND stderr to the same TLS socket, so anything on
# stderr would be injected into the wire ahead of the quote and corrupt the
# protocol. We therefore divert the container's stderr to a log file
# ($SGX_RA_HOST_LOG, default /var/log/sgx-ra-host.log) instead of letting it
# reach the client. This is the Rust equivalent of the blueprint wrapper's
# `./app 2>/dev/null`.
set -eu

IMAGE="${SGX_RA_HOST_IMAGE:-sgx-ra-echo-host:latest}"
QCNL_CONF="${SGX_RA_QCNL_CONF:-}"
LOG="${SGX_RA_HOST_LOG:-/var/log/sgx-ra-host.log}"

# Keep diagnostics off the wire; fall back to discarding them if the log
# path is not writable (never send them to the inherited socket on fd 2).
if { : >>"$LOG"; } 2>/dev/null; then
    exec 2>>"$LOG"
else
    exec 2>/dev/null
fi

if [ -n "$QCNL_CONF" ]; then
    set -- -v "$QCNL_CONF:/etc/sgx_default_qcnl.conf:ro" "$IMAGE" "$@"
else
    set -- "$IMAGE" "$@"
fi

exec docker run --rm -i \
    --network host \
    --device /dev/sgx_enclave \
    --device /dev/sgx_provision \
    --read-only --tmpfs /tmp \
    --cap-drop ALL --security-opt no-new-privileges \
    "$@"
