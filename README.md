# VPN Diagnostics

A Bash script for first-touch VPN triage. It runs the checks a support engineer would otherwise type by hand (DNS, TCP reachability, TLS certificate expiry, routing and split tunneling, path MTU, VPN client presence and an HTTPS fetch) and prints one PASS, FAIL or INFO line per check with a summary at the end.

Most checks need no root access.

## What it checks

1. **DNS.** Resolves the target with `dig` (A and AAAA), falling back to `getent`, `nslookup` or `ping` if dig is not installed.
2. **TCP reachability.** Opens a connection to the target host and port through Bash's `/dev/tcp`, wrapped in `timeout`.
3. **TLS certificate.** Connects with `openssl s_client` using SNI, reads the certificate end date and reports the days left. It fails if the certificate cannot be read or expires sooner than `--min-tls-days`. Chain validation errors are not treated as failures.
4. **Routing and split tunneling.** Finds the egress interface for a public address (1.1.1.1) and for the first address of `--corp-cidr`, using `ip route get` on Linux or `route get` on macOS. If both use the same interface it prints an INFO line saying the setup is likely full tunnel, otherwise likely split tunnel. This is a hint, not a verdict. With no VPN up, both lookups use the default interface.
5. **Path MTU.** Sends don't-fragment pings to `--mtu-ip` from 1472 bytes down to 1200 bytes in 20-byte steps and fails if the largest size that works is under 1350. This needs the Linux `ping -M do` option, so on macOS the check is skipped with an INFO line.
6. **VPN presence.** Lists active WireGuard interfaces with `wg show` and looks for an OpenVPN process or an active `openvpn` systemd service. `wg show` usually needs root, so run with sudo to see WireGuard interfaces.
7. **HTTPS fetch.** Runs `curl -f` against `https://<host>:<port>` and fails on a connection error or an HTTP status of 400 or above.

## Requirements

- Bash, `ping`, `openssl` and `curl`
- `timeout` from GNU coreutils for the TCP check. Linux has it. On macOS install coreutils with Homebrew, or the TCP check reports FAIL.
- Optional: `dig`, `ip` (iproute2), `wg` (wireguard-tools)

## Usage

```bash
chmod +x run_diagnostics.sh
./run_diagnostics.sh --host example.com --corp-cidr 10.0.0.0/8
```

| Flag | Environment variable | Default | Description |
|------|----------------------|---------|-------------|
| `--host` | `TARGET_HOST` | `example.com` | Host to resolve, connect to and fetch |
| `--port` | `TARGET_PORT` | `443` | Port for the TCP, TLS and HTTPS checks |
| `--corp-cidr` | `CORP_CIDR` | `10.0.0.0/8` | Corporate prefix used for the split-tunnel check |
| `--mtu-ip` | `MTU_TEST_IP` | `8.8.8.8` | Target for the MTU ping ladder |
| `--min-tls-days` | `MIN_TLS_DAYS` | `5` | Fail if the certificate expires sooner than this |
| none | `TIMEOUT` | `6` | Timeout in seconds for DNS, TCP and curl |

Example output from a macOS laptop with no VPN connected:

```text
[INFO ] Target host: example.com:443
[PASS ] DNS resolved example.com → 104.20.23.154 172.66.147.243 2606:4700:10::6814:179a 2606:4700:10::ac42:93f3
[PASS ] TCP connect to example.com:443
[PASS ] TLS handshake OK; cert expires in 32 days
[PASS ] Default route interface: en1
[PASS ] Corp route interface for 10.0.0.0/8: en1
[INFO ] Public and corp traffic share interface (en1), likely full-tunnel
[INFO ] MTU probe skipped (no ping -M do?)
[INFO ] WireGuard not detected
[INFO ] OpenVPN not detected
[PASS ] HTTPS GET https://example.com:443 succeeded
--------------------------------------
Summary: 6 PASS, 0 FAIL, 6 checks
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No check failed |
| 1 | At least one check failed |
| 2 | Unknown command-line argument |
