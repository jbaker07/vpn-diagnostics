# VPN Diagnostics

A Bash script for first-touch VPN triage. It runs the checks a support engineer would otherwise type by hand (DNS, TCP reachability, TLS certificate expiry, routing and split tunneling, path MTU, VPN client presence and an HTTPS fetch) and prints one PASS, FAIL or INFO line per check with a summary at the end.

Most checks need no root access.

## What it checks

1. **DNS.** Resolves the target through the system resolver: `dscacheutil` on macOS and `getent ahosts` on Linux. It falls back to `dig`, `nslookup` or `ping` when those are missing. The system resolver goes first because `dig` reads only `/etc/resolv.conf`, so it misses `/etc/hosts` and the per-domain resolvers a VPN client installs for internal names (the extra resolvers in `scutil --dns` on macOS, or systemd-resolved on Linux). A name that only the VPN's DNS knows would look broken to `dig` while it works for every application.
2. **TCP reachability.** Opens a connection to the target host and port through Bash's `/dev/tcp` with a time limit from `timeout` (GNU coreutils on Linux, and shipped with recent macOS), `gtimeout` (the Homebrew name), or `nc -z -w` as the fallback on older macOS.
3. **TLS certificate.** Connects with `openssl s_client` using SNI, reads the certificate end date and reports the days left. It fails if the certificate cannot be read or expires sooner than `--min-tls-days`. Chain validation errors are not treated as failures. It works with both OpenSSL and the LibreSSL `openssl` that ships with macOS.
4. **Routing and split tunneling.** Finds the egress interface for a public address (1.1.1.1) and for the first address of `--corp-cidr`, using `ip route get` on Linux or `route get` on macOS. If both use the same interface it prints an INFO line saying the setup is likely full tunnel, otherwise likely split tunnel. This is a hint, not a verdict. With no VPN up, both lookups use the default interface.
5. **Path MTU.** First sends one plain ping to `--mtu-ip`. If that gets no reply the check is skipped with an INFO line, because a host that ignores ping would fail every size and look like an MTU problem. Otherwise it sends don't-fragment pings from 1472 bytes of payload (a 1500 byte packet) down to 1200 bytes in 20 byte steps, reports the largest that gets through with the path MTU it implies (payload plus 28 bytes of IP and ICMP headers), and fails if that payload is under 1350. It also fails when the plain ping works but no DF size does. Linux uses `ping -M do -W 2`. macOS uses `ping -D -t 2`, since macOS ping sets the DF bit with `-D` and its `-W` counts milliseconds, not seconds. A ping without a DF option, such as busybox, gets an INFO line instead.
6. **VPN presence.** Lists active WireGuard interfaces with `wg show` and looks for an OpenVPN process or an active `openvpn` systemd service. `wg show` usually needs root, so run with sudo to see WireGuard interfaces.
7. **HTTPS fetch.** Runs `curl -f` against `https://<host>:<port>` and fails on a connection error or an HTTP status of 400 or above. The FAIL line includes curl's own error, for example `curl: (60) SSL certificate problem: self signed certificate`.

## Requirements

- Bash, `ping`, `openssl` and `curl`
- Optional: `timeout` or `gtimeout` for the TCP check time limit (`nc` is used when neither is installed), `dig`, `ip` (iproute2), `wg` (wireguard-tools)

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

Example output from a macOS machine with no VPN connected:

```text
[INFO ] Target host: example.com:443
[PASS ] DNS resolved example.com → 2606:4700:10::6814:179a 2606:4700:10::ac42:93f3 172.66.147.243 104.20.23.154
[PASS ] TCP connect to example.com:443
[PASS ] TLS handshake OK; cert expires in 32 days
[PASS ] Default route interface: en1
[PASS ] Corp route interface for 10.0.0.0/8: en1
[INFO ] Public and corp traffic share interface (en1), likely full-tunnel
[PASS ] Path MTU looks sane (1472 byte DF payload, path MTU about 1500)
[INFO ] WireGuard not detected
[INFO ] OpenVPN not detected
[PASS ] HTTPS GET https://example.com:443 succeeded
--------------------------------------
Summary: 7 PASS, 0 FAIL, 7 checks
```

On a path with a smaller link in the middle, the MTU line turns into a failure. This one comes from the Linux namespace lab in the tests, where the router's link to the server has an MTU of 1300:

```text
[FAIL ] Low path MTU detected (1272 byte DF payload, path MTU about 1300). Expect TLS breaks/fragmentation.
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No check failed |
| 1 | At least one check failed |
| 2 | Unknown command-line argument |

## Tests

`tests/run_tests.sh` runs the script against local services only, so it needs no internet access:

- a local `openssl s_server` with a certificate that expires in 2 days, which has to pass DNS and TCP, fail the TLS check at the default `--min-tls-days 5`, pass it at `--min-tls-days 1`, and fail the HTTPS fetch with curl's self signed certificate error
- a closed local port, which has to fail TCP and TLS
- the loopback interface as the MTU target, which has to pass at 1472
- 192.0.2.1, a documentation address that never answers, which has to skip the MTU check rather than fail it
- the exit codes, including 2 for an unknown argument
- a stand in `ping` (`tests/fake_ping/ping`, put first in `PATH`) that acts like a path with a 1300 byte link: a DF ping whose packet would be bigger fails the way the real one does, and every other ping goes to the real `ping`. The script has to report `1272 byte DF payload, path MTU about 1300`, and the test checks from the stand in's log that it pinged with `-c1 -t 2 -D -s 1472` on macOS or `-c1 -W 2 -M do -s 1472` on Linux. This runs the low MTU branch of the current platform without root.

On Linux as root it also builds three network namespaces (client, router, server), runs the script inside the client and checks that the MTU check passes at 1500 and reports `1272 byte DF payload, path MTU about 1300` once the router's link to the server is set to 1300. The router answers with ICMP fragmentation needed, the same way a real hop does.

On macOS with `VPN_DIAG_LO0_TEST=1` and passwordless sudo, it sets the loopback interface `lo0` to MTU 1300, adds the test address 192.0.2.99 to it, checks that the real `ping -D` gets a 1272 byte payload through and not a 1273 byte one, runs the script against 192.0.2.99 and expects the same low MTU line, then puts `lo0` back and checks that it is back. It changes a system setting, so it only runs when asked.

```bash
./tests/run_tests.sh                          # macOS or Linux
sudo ./tests/run_tests.sh                     # Linux, adds the namespace MTU lab
VPN_DIAG_LO0_TEST=1 ./tests/run_tests.sh      # macOS with passwordless sudo, adds the loopback MTU check
```

```text
== Arguments
[PASS] unknown argument: exit code 2
...
== Low MTU in the middle of the path (Linux, root)
[PASS] 1500 byte path: full size path passes
[PASS] 1300 byte hop: the router's 1300 byte link is found
Summary: 20 passed, 0 failed, 1 skipped
```

The GitHub Actions workflow in `.github/workflows/tests.yml` runs the tests as root on Ubuntu 24.04 and on macOS with `VPN_DIAG_LO0_TEST=1`, since GitHub's macOS runners have passwordless sudo.
