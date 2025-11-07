#!/usr/bin/env bash
# File: run_diagnostics.sh
# Purpose: First-touch VPN diagnostics for DNS/route/MTU/TLS + WireGuard/OpenVPN presence
# Platform: Linux/macOS (best on Linux). No sudo required for most checks.
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

# -------- helpers --------
resolve_dns() {
  local host="$1"
  if has dig; then
    dig +time=$TIMEOUT +short "$host" A "$host" AAAA | sed '/^$/d' || true
  elif has getent; then
    getent hosts "$host" | awk '{print $1}' || true
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

# TLS days to expiry using openssl (best-effort)
cert_days_left() {
  local host="$1" port="$2"
  if ! has openssl; then echo "-1"; return; fi
  local end
  end=$(echo | openssl s_client -servername "$host" -connect "$host:$port" -verify_quiet 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//') || true
  if [[ -z "$end" ]]; then echo "-1"; return; fi
  local end_epoch now_epoch
  end_epoch=$(date -j -f '%b %d %T %Y %Z' "$end" +%s 2>/dev/null || date -d "$end" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  if [[ $end_epoch -le 0 ]]; then echo "-1"; return; fi
  echo $(( (end_epoch - now_epoch) / 86400 ))
}

mtu_probe() {
  local ip="$1" size=1472 rc=1
  if has ping; then
    while (( size >= 1200 )); do
      if ping -c1 -M do -s "$size" "$ip" >/dev/null 2>&1; then
        echo "$size"; return 0
      fi
      size=$((size-20))
    done
  fi
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
if timeout $TIMEOUT bash -c "</dev/tcp/$TARGET_HOST/$TARGET_PORT" 2>/dev/null; then
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
CORP_IF=$(route_if $(echo "$CORP_CIDR" | cut -d'/' -f1))
[[ -n "$PUB_IF" ]] && OK "Default route interface: $PUB_IF" || BAD "Cannot determine default route interface"
[[ -n "$CORP_IF" ]] && OK "Corp route interface for $CORP_CIDR: $CORP_IF" || BAD "No route to $CORP_CIDR (split-tunnel?)"
if [[ -n "$PUB_IF" && -n "$CORP_IF" && "$PUB_IF" == "$CORP_IF" ]]; then
  INFO "Public and corp traffic share interface ($PUB_IF) — likely full-tunnel"
else
  INFO "Interfaces differ (pub=$PUB_IF, corp=$CORP_IF) — likely split-tunnel"
fi

# 5) MTU sanity
MTU=$(mtu_probe "$MTU_TEST_IP" || true)
if [[ -n "$MTU" ]]; then
  if (( MTU < 1350 )); then
    BAD "Low path MTU detected ($MTU). Expect TLS breaks/fragmentation."
  else
    OK "Path MTU looks sane ($MTU)"
  fi
else
  INFO "MTU probe skipped (no ping -M do?)"
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
  if curl -fsS --max-time $TIMEOUT "https://$TARGET_HOST:$TARGET_PORT" >/dev/null; then
    OK "HTTPS GET https://$TARGET_HOST:$TARGET_PORT succeeded"
  else
    BAD "HTTPS GET https://$TARGET_HOST:$TARGET_PORT failed (proxy/cert/route?)"
  fi
fi

# -------- summary --------
TOTAL=$((PASS+FAIL))
echo "--------------------------------------"
echo "Summary: $PASS PASS, $FAIL FAIL, $TOTAL checks"

# exit non-zero if any FAIL
exit $(( FAIL>0 ))
