#!/usr/bin/env bash
# Tests for run_diagnostics.sh. Everything runs against local services, so no internet
# access is needed:
#   - a local TLS server with a certificate that expires in 2 days
#   - a closed local port
#   - the loopback interface for the MTU probe
# A stand in ping (tests/fake_ping/ping) then acts like a path with a 1300 byte link, so
# the low MTU branch for this platform runs without root, and the test checks the ping
# options the script used.
# On Linux as root it also builds three network namespaces with a 1300 byte link in the
# middle and checks that the MTU probe reports it. Without root that part is skipped.
# On macOS with VPN_DIAG_LO0_TEST=1 it sets the loopback MTU to 1300 with sudo, checks
# that the real ping now hits that limit, runs the script against it and puts the MTU back.
# It changes a system setting, so it only runs when asked, as in the GitHub workflow.
#
# Usage: ./tests/run_tests.sh          (sudo ./tests/run_tests.sh on Linux for the MTU lab)
#        VPN_DIAG_LO0_TEST=1 ./tests/run_tests.sh   (macOS with passwordless sudo)
set -uo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$(dirname "$TEST_DIR")/run_diagnostics.sh"
SCRATCH_DIR=$(mktemp -d)
OS_NAME=$(uname -s)
TLS_SERVER_PID=""
LO0_MTU_BEFORE=""
LO0_TEST_ADDRESS=192.0.2.99
TLS_PORT=$((20000 + $$ % 10000))
CLOSED_PORT=$((TLS_PORT + 1))

PASSED_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0
pass() { echo "[PASS] $1"; PASSED_COUNT=$((PASSED_COUNT+1)); }
fail() { echo "[FAIL] $1"; FAILED_COUNT=$((FAILED_COUNT+1)); }
skip() { echo "[SKIP] $1"; SKIPPED_COUNT=$((SKIPPED_COUNT+1)); }

restore_lo0() {
  if [[ -n "$LO0_MTU_BEFORE" ]]; then
    sudo -n ifconfig lo0 -alias "$LO0_TEST_ADDRESS" 2>/dev/null
    sudo -n ifconfig lo0 mtu "$LO0_MTU_BEFORE"
    LO0_MTU_BEFORE=""
  fi
}

cleanup() {
  restore_lo0
  if [[ -n "$TLS_SERVER_PID" ]]; then
    kill "$TLS_SERVER_PID" 2>/dev/null
    wait "$TLS_SERVER_PID" 2>/dev/null
  fi
  for NS in vd_client vd_router vd_server; do ip netns del "$NS" 2>/dev/null; done
  rm -rf "$SCRATCH_DIR"
}
trap cleanup EXIT

#run_case NAME WANTED_EXIT ARGS... runs the script and keeps its output for expect_line
run_case() {
  CASE_NAME="$1"
  local WANTED_EXIT="$2"
  shift 2
  TIMEOUT=3 "$SCRIPT" "$@" >"$SCRATCH_DIR/out.txt" 2>&1
  local ACTUAL_EXIT=$?
  if [[ "$ACTUAL_EXIT" == "$WANTED_EXIT" ]]; then
    pass "$CASE_NAME: exit code $ACTUAL_EXIT"
  else
    fail "$CASE_NAME: exit code $ACTUAL_EXIT, wanted $WANTED_EXIT"
    sed 's/^/    /' "$SCRATCH_DIR/out.txt"
  fi
}

expect_line() {
  if grep -Eq -- "$1" "$SCRATCH_DIR/out.txt"; then
    pass "$CASE_NAME: $2"
  else
    fail "$CASE_NAME: no line matching $1"
    sed 's/^/    /' "$SCRATCH_DIR/out.txt"
  fi
}

echo "== Arguments"
run_case "unknown argument" 2 --no-such-flag

echo "== Local TLS server with a certificate that expires in 2 days"
command -v openssl >/dev/null || { echo "openssl is needed for these tests"; exit 2; }
#the same openssl the script will use, because LibreSSL and OpenSSL 3 do not always agree as client and server
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
  -keyout "$SCRATCH_DIR/key.pem" -out "$SCRATCH_DIR/cert.pem" >/dev/null 2>&1
openssl s_server -quiet -accept "$TLS_PORT" -cert "$SCRATCH_DIR/cert.pem" -key "$SCRATCH_DIR/key.pem" -www >/dev/null 2>&1 &
TLS_SERVER_PID=$!
sleep 1

run_case "short lived certificate" 1 --host 127.0.0.1 --port "$TLS_PORT" --mtu-ip 127.0.0.1
expect_line '^\[PASS \] DNS resolved 127\.0\.0\.1 → 127\.0\.0\.1' "DNS check passes for an address literal"
expect_line "^\[PASS \] TCP connect to 127\.0\.0\.1:$TLS_PORT$" "TCP connect passes"
expect_line '^\[FAIL \] TLS cert expires in 1 days \(< 5\)$' "TLS check fails a certificate that expires inside --min-tls-days"
expect_line '^\[PASS \] Path MTU looks sane \(1472 byte DF payload, path MTU about 1500\)$' "MTU probe passes on loopback"
expect_line "^\[FAIL \] HTTPS GET https://127\.0\.0\.1:$TLS_PORT failed: curl: \(60\)" "HTTPS check fails on the self signed certificate and shows curl's error"
expect_line '^Summary: [0-9]+ PASS, 2 FAIL, [0-9]+ checks$' "summary counts 2 failures"

run_case "short lived certificate with --min-tls-days 1" 1 --host 127.0.0.1 --port "$TLS_PORT" --mtu-ip 127.0.0.1 --min-tls-days 1
expect_line '^\[PASS \] TLS handshake OK; cert expires in 1 days$' "TLS check passes once the threshold is lower"

echo "== Closed port"
run_case "closed port" 1 --host 127.0.0.1 --port "$CLOSED_PORT" --mtu-ip 127.0.0.1
expect_line "^\[FAIL \] TCP connect to 127\.0\.0\.1:$CLOSED_PORT failed" "TCP connect fails"
expect_line '^\[FAIL \] TLS handshake/cert parse failed' "TLS check fails"

echo "== MTU probe against an address that does not answer ping"
#192.0.2.1 is in TEST-NET-1, which is reserved for documentation and is not routed
run_case "silent MTU target" 1 --host 127.0.0.1 --port "$TLS_PORT" --mtu-ip 192.0.2.1
expect_line '^\[INFO \] MTU probe skipped, 192\.0\.2\.1 does not answer a plain ping$' "probe is skipped, not failed"

echo "== Low MTU with a stand in ping that acts like a 1300 byte link"
REAL_PING_PATH=$(command -v ping)
CASE_NAME="stand in ping"
REAL_PING="$REAL_PING_PATH" FAKE_PING_LOG="$SCRATCH_DIR/ping.log" PATH="$TEST_DIR/fake_ping:$PATH" TIMEOUT=3 \
  "$SCRIPT" --host 127.0.0.1 --port "$TLS_PORT" --mtu-ip 127.0.0.1 >"$SCRATCH_DIR/out.txt" 2>&1
expect_line '^\[FAIL \] Low path MTU detected \(1272 byte DF payload, path MTU about 1300\)' "the $OS_NAME branch reports the 1300 byte link"
if [[ "$OS_NAME" == Darwin ]]; then
  WANTED_DF_CALL="-c1 -t 2 -D -s 1472 127.0.0.1"
else
  WANTED_DF_CALL="-c1 -W 2 -M do -s 1472 127.0.0.1"
fi
cp "$SCRATCH_DIR/ping.log" "$SCRATCH_DIR/out.txt"
expect_line "^$WANTED_DF_CALL\$" "the script pings with: ping $WANTED_DF_CALL"
expect_line '^-c1 -[tW] 2 (-D|-M do) -s 1272 127\.0\.0\.1$' "the ladder steps down to 1272"

echo "== Low MTU on the macOS loopback interface (sudo, VPN_DIAG_LO0_TEST=1)"
if [[ "$OS_NAME" == Darwin && "${VPN_DIAG_LO0_TEST:-0}" == 1 ]]; then
  LO0_MTU_BEFORE=$(ifconfig lo0 | sed -n 's/.* mtu \([0-9]*\).*/\1/p' | head -1)
  #the alias is added after the MTU change, so its route is created with the small MTU
  sudo -n ifconfig lo0 mtu 1300
  sudo -n ifconfig lo0 alias "$LO0_TEST_ADDRESS" netmask 255.255.255.255
  ifconfig lo0 | sed 's/^/    /'
  if ping -c1 -t 2 -D -s 1272 "$LO0_TEST_ADDRESS" >/dev/null 2>&1 && ! ping -c1 -t 2 -D -s 1273 "$LO0_TEST_ADDRESS" >/dev/null 2>&1; then
    pass "real ping: 1272 byte DF payload gets through lo0 and 1273 does not"
  else
    fail "real ping: lo0 does not behave like a 1300 byte link"
  fi
  CASE_NAME="lo0 at MTU 1300"
  TIMEOUT=3 "$SCRIPT" --host 127.0.0.1 --port "$TLS_PORT" --mtu-ip "$LO0_TEST_ADDRESS" >"$SCRATCH_DIR/out.txt" 2>&1
  expect_line '^\[FAIL \] Low path MTU detected \(1272 byte DF payload, path MTU about 1300\)' "the script reports the 1300 byte loopback path with the real ping"
  RESTORE_TO="$LO0_MTU_BEFORE"
  restore_lo0
  if ifconfig lo0 | grep -q " mtu $RESTORE_TO" && ! ifconfig lo0 | grep -q "$LO0_TEST_ADDRESS"; then
    pass "lo0 is back to MTU $RESTORE_TO without the test address"
  else
    fail "lo0 was not restored to MTU $RESTORE_TO"
  fi
else
  skip "needs macOS, passwordless sudo and VPN_DIAG_LO0_TEST=1"
fi

echo "== Low MTU in the middle of the path (Linux, root)"
if [[ "$OS_NAME" == Linux && $EUID -eq 0 ]] && command -v ip >/dev/null; then
  #client 10.77.1.2 -> router -> server 10.77.2.2, and the router to server link gets the small MTU
  for NS in vd_client vd_router vd_server; do ip netns add "$NS"; ip -n "$NS" link set lo up; done
  ip link add vd_c0 type veth peer name vd_r0
  ip link add vd_r1 type veth peer name vd_s0
  ip link set vd_c0 netns vd_client
  ip link set vd_r0 netns vd_router
  ip link set vd_r1 netns vd_router
  ip link set vd_s0 netns vd_server
  ip -n vd_client addr add 10.77.1.2/24 dev vd_c0
  ip -n vd_router addr add 10.77.1.1/24 dev vd_r0
  ip -n vd_router addr add 10.77.2.1/24 dev vd_r1
  ip -n vd_server addr add 10.77.2.2/24 dev vd_s0
  for DEV in vd_client:vd_c0 vd_router:vd_r0 vd_router:vd_r1 vd_server:vd_s0; do
    ip -n "${DEV%%:*}" link set "${DEV#*:}" up
  done
  ip -n vd_client route add default via 10.77.1.1
  ip -n vd_server route add default via 10.77.2.1
  ip netns exec vd_router sysctl -qw net.ipv4.ip_forward=1

  CASE_NAME="1500 byte path"
  ip netns exec vd_client env TIMEOUT=2 "$SCRIPT" --host 10.77.2.2 --port 9 --mtu-ip 10.77.2.2 >"$SCRATCH_DIR/out.txt" 2>&1
  expect_line '^\[PASS \] Path MTU looks sane \(1472 byte DF payload, path MTU about 1500\)$' "full size path passes"

  ip -n vd_router link set vd_r1 mtu 1300
  ip -n vd_server link set vd_s0 mtu 1300
  CASE_NAME="1300 byte hop"
  ip netns exec vd_client env TIMEOUT=2 "$SCRIPT" --host 10.77.2.2 --port 9 --mtu-ip 10.77.2.2 >"$SCRATCH_DIR/out.txt" 2>&1
  expect_line '^\[FAIL \] Low path MTU detected \(1272 byte DF payload, path MTU about 1300\)' "the router's 1300 byte link is found"
else
  skip "needs Linux and root (sudo ./tests/run_tests.sh)"
fi

echo "Summary: $PASSED_COUNT passed, $FAILED_COUNT failed, $SKIPPED_COUNT skipped"
[[ $FAILED_COUNT -eq 0 ]]
