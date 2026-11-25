#!/usr/bin/env bash
# File: run_diagnostics.sh
# Purpose: First-touch VPN diagnostics for DNS/route/MTU/TLS + WireGuard/OpenVPN presence
# Platform: Linux and macOS. No sudo required for most checks.
# Output: PASS/FAIL lines and a summary at the end.

set -euo pipefail

# -------- config / args --------
TARGET_HOST=${TARGET_HOST:-"example.com"}     # public site to sanity check
TARGET_PORT=${TARGET_PORT:-443}
CORP_CIDR=${CORP_CIDR:-"10.0.0.0/8"}          # set to your corp prefix for split-tunnel checks
MTU_TEST_IP=${MTU_TEST_IP:-"8.8.8.8"}         # ping MTU test target
MIN_TLS_DAYS=${MIN_TLS_DAYS:-5}               # warn if cert expires < X days
TIMEOUT=${TIMEOUT:-6}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) TARGET_HOST="$2"; shift 2 ;;
    --port) TARGET_PORT="$2"; shift 2 ;;
    --corp-cidr) CORP_CIDR="$2"; shift 2 ;;
    --mtu-ip) MTU_TEST_IP="$2"; shift 2 ;;
    --min-tls-days) MIN_TLS_DAYS="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 2 ;;
  esac
done

PASS=0
FAIL=0
INFO() { printf "[INFO ] %s\n" "$*"; }
OK()   { printf "[PASS ] %s\n" "$*"; PASS=$((PASS+1)); }
BAD()  { printf "[FAIL ] %s\n" "$*"; FAIL=$((FAIL+1)); }

has() { command -v "$1" >/dev/null 2>&1; }

OS_NAME=$(uname -s)

# -------- helpers --------
# The system resolver goes first. dig reads only /etc/resolv.conf, so it misses /etc/hosts
# and the per-domain resolvers a VPN client installs (scutil --dns on macOS,
# systemd-resolved on Linux). Those are exactly the names a VPN check cares about.
resolve_dns() {
  local host="$1"
  if [[ "$OS_NAME" == Darwin ]] && has dscacheutil; then
    dscacheutil -q host -a name "$host" 2>/dev/null | awk '/^ip(v6)?_address:/{print $2}' || true
  elif has getent; then
    getent ahosts "$host" 2>/dev/null | awk '{print $1}' | awk '!seen[$0]++' || true
  elif has dig; then
    dig +time=$TIMEOUT +short "$host" A "$host" AAAA | sed '/^$/d' | grep -v '\.$' || true
  elif has nslookup; then
    nslookup -timeout=$TIMEOUT "$host" 2>/dev/null | awk '/^Address: /{print $2}' || true
  else
    # fallback via ping
    ping -c1 -W$TIMEOUT "$host" 2>/dev/null | sed -n 's/.*(\([0-9.:]*\)).*/\1/p'
  fi
}

route_if() {
  local ip="$1"
  if has ip; then
    ip route get "$ip" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p'
  elif has route; then
    route get "$ip" 2>/dev/null | sed -n 's/.*interface: \([^ ]*\).*/\1/p'
  else
    echo "unknown"
  fi
}

# TCP connect with a time limit. timeout comes from GNU coreutils on Linux and ships with
# recent macOS. gtimeout is the Homebrew name. nc -z is the fallback on older macOS.
tcp_connect() {
  local host="$1" port="$2"
  if has timeout; then
    timeout "$TIMEOUT" bash -c "</dev/tcp/$host/$port" 2>/dev/null
  elif has gtimeout; then
    gtimeout "$TIMEOUT" bash -c "</dev/tcp/$host/$port" 2>/dev/null
  elif has nc; then
    nc -z -w "$TIMEOUT" "$host" "$port" >/dev/null 2>&1
  else
    bash -c "</dev/tcp/$host/$port" 2>/dev/null
  fi
}

# TLS days to expiry using openssl (best-effort)
cert_days_left() {
  local host="$1" port="$2"
  if ! has openssl; then echo "-1"; return; fi
  local end
  # no -verify_quiet: the LibreSSL openssl that ships with macOS rejects it, and stderr is discarded anyway
  end=$(echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//') || true
  if [[ -z "$end" ]]; then echo "-1"; return; fi
  local end_epoch now_epoch
  end_epoch=$(date -j -f '%b %d %T %Y %Z' "$end" +%s 2>/dev/null || date -d "$end" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  if [[ $end_epoch -le 0 ]]; then echo "-1"; return; fi
  echo $(( (end_epoch - now_epoch) / 86400 ))
}

# df_ping SIZE IP sends one ping of SIZE payload bytes with the don't-fragment bit set.
# Linux iputils ping sets DF with -M do and takes -W in seconds. macOS ping sets DF with -D,
# takes -W in milliseconds and has -t for an overall timeout in seconds, which is what is used here.
df_ping() {
  local size="$1" ip="$2"
  if [[ "$OS_NAME" == Darwin ]]; then
    ping -c1 -t 2 -D -s "$size" "$ip" >/dev/null 2>&1
  else
    ping -c1 -W 2 -M "do" -s "$size" "$ip" >/dev/null 2>&1
  fi
}

# Prints the largest DF payload from 1472 down to 1200 in 20 byte steps that gets a reply.
# Return codes: 0 found a size, 1 no size got through, 2 the probe cannot run here,
# 3 the target does not answer a plain ping, so the ladder would prove nothing.
mtu_probe() {
  local ip="$1" size=1472
  has ping || return 2
  if [[ "$OS_NAME" != Darwin ]] && ! ping -c1 -W 1 -M "do" -s 56 127.0.0.1 >/dev/null 2>&1; then
    return 2   # a ping without -M do, such as busybox
  fi
  if [[ "$OS_NAME" == Darwin ]]; then
    ping -c1 -t 2 "$ip" >/dev/null 2>&1 || return 3
  else
    ping -c1 -W 2 "$ip" >/dev/null 2>&1 || return 3
  fi
  while (( size >= 1200 )); do
    if df_ping "$size" "$ip"; then
      echo "$size"; return 0
    fi
    size=$((size-20))
  done
  return 1
}

# -------- checks --------
INFO "Target host: $TARGET_HOST:$TARGET_PORT"

# 1) DNS resolution
IPS=$(resolve_dns "$TARGET_HOST" | tr '\n' ' ')
if [[ -n "$IPS" ]]; then
  OK "DNS resolved $TARGET_HOST → $IPS"
else
  BAD "DNS failed for $TARGET_HOST (check resolv.conf/NM/VPN DNS pushes)"
fi

# 2) TCP reachability
if tcp_connect "$TARGET_HOST" "$TARGET_PORT"; then
  OK "TCP connect to $TARGET_HOST:$TARGET_PORT"
else
  BAD "TCP connect to $TARGET_HOST:$TARGET_PORT failed (firewall/proxy/VPN split?)"
fi

# 3) TLS handshake + expiry
DAYS=$(cert_days_left "$TARGET_HOST" "$TARGET_PORT")
if [[ "$DAYS" == "-1" ]]; then
  BAD "TLS handshake/cert parse failed (SNI/firewall/mitm?)"
else
  if (( DAYS < MIN_TLS_DAYS )); then
    BAD "TLS cert expires in $DAYS days (< $MIN_TLS_DAYS)"
  else
    OK "TLS handshake OK; cert expires in $DAYS days"
  fi
fi

# 4) Default route / interface
PUB_IF=$(route_if 1.1.1.1)
CORP_IF=$(route_if "${CORP_CIDR%%/*}")
[[ -n "$PUB_IF" ]] && OK "Default route interface: $PUB_IF" || BAD "Cannot determine default route interface"
[[ -n "$CORP_IF" ]] && OK "Corp route interface for $CORP_CIDR: $CORP_IF" || BAD "No route to $CORP_CIDR (split-tunnel?)"
if [[ -n "$PUB_IF" && -n "$CORP_IF" && "$PUB_IF" == "$CORP_IF" ]]; then
  INFO "Public and corp traffic share interface ($PUB_IF), likely full-tunnel"
else
  INFO "Interfaces differ (pub=$PUB_IF, corp=$CORP_IF), likely split-tunnel"
fi

# 5) MTU sanity
MTU_RC=0
MTU=$(mtu_probe "$MTU_TEST_IP") || MTU_RC=$?
if (( MTU_RC == 0 )); then
  if (( MTU < 1350 )); then
    BAD "Low path MTU detected ($MTU byte DF payload, path MTU about $((MTU+28))). Expect TLS breaks/fragmentation."
  else
    OK "Path MTU looks sane ($MTU byte DF payload, path MTU about $((MTU+28)))"
  fi
elif (( MTU_RC == 1 )); then
  BAD "No DF ping of 1200 bytes or more reaches $MTU_TEST_IP, but a small ping does. Path MTU is below 1228 or PMTUD is broken."
elif (( MTU_RC == 3 )); then
  INFO "MTU probe skipped, $MTU_TEST_IP does not answer a plain ping"
else
  INFO "MTU probe skipped, this ping cannot set the don't-fragment bit"
fi

# 6) VPN presence (WireGuard/OpenVPN)
if has wg && wg show 2>/dev/null | grep -q interface; then
  OK "WireGuard active: $(wg show | awk '/interface:/{print $2}' | paste -sd, -)"
else
  INFO "WireGuard not detected"
fi

if pgrep -fa openvpn >/dev/null 2>&1; then
  OK "OpenVPN process present"
elif systemctl is-active --quiet openvpn 2>/dev/null; then
  OK "OpenVPN service active"
else
  INFO "OpenVPN not detected"
fi

# 7) Simple HTTPS fetch with curl (if present)
if has curl; then
  # keep curl's own error, which names the cause (certificate, timeout, proxy), and put it on the FAIL line
  if CURL_ERROR=$(curl -fsS --max-time $TIMEOUT -o /dev/null "https://$TARGET_HOST:$TARGET_PORT" 2>&1); then
    OK "HTTPS GET https://$TARGET_HOST:$TARGET_PORT succeeded"
  else
    BAD "HTTPS GET https://$TARGET_HOST:$TARGET_PORT failed: $(printf '%s\n' "$CURL_ERROR" | head -1)"
  fi
fi

# -------- summary --------
TOTAL=$((PASS+FAIL))
echo "--------------------------------------"
echo "Summary: $PASS PASS, $FAIL FAIL, $TOTAL checks"

# exit non-zero if any FAIL
exit $(( FAIL>0 ))
