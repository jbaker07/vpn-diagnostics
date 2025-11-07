# Fix-My-VPN Diagnostics (MVP)

First-touch VPN triage for DNS, TCP reachability, TLS handshake/expiry, default routes/split-tunnel, MTU, and VPN presence (WireGuard/OpenVPN).

## Quick start
chmod +x run_diagnostics.sh
./run_diagnostics.sh --host example.com --corp-cidr 10.0.0.0/8

## Common flags
--host example.com       # target to sanity-check
--port 443               # port to test
--corp-cidr 10.0.0.0/8   # corp prefix to test split-tunnel
--mtu-ip 8.8.8.8         # MTU ping target
--min-tls-days 5         # warn if cert expires soon

## Exit codes
0 = all good
1 = failures present
