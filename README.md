# Advanced Port Scanner

A professional async TCP port scanner built in Python. Performs high-speed port scanning with service detection, banner grabbing, and OS fingerprinting using `asyncio` for maximum concurrency.

## Features

- **Async TCP Connect Scan** — non-blocking, high-concurrency scanning powered by asyncio
- **SYN (Half-Open) Scan** — stealthier scanning using raw sockets (requires root)
- **Service Detection** — identifies 120+ common services by port number
- **Banner Grabbing** — captures service banners from open ports for version fingerprinting
- **OS Fingerprinting** — heuristic OS detection based on TTL values and open port signatures
- **Flexible Targeting** — single hosts, CIDR ranges (`10.0.0.0/24`), or comma-separated lists
- **Port Specification** — single ports, ranges (`1-1024`), lists (`22,80,443`), or `--top-ports N`
- **Multiple Output Formats** — color-coded terminal table, JSON, and CSV
- **Progress Bar** — real-time scan progress in the terminal
- **Adjustable Concurrency** — tune performance with `--threads`

## Scan Types

### TCP Connect Scan (default)

Completes the full TCP three-way handshake. Reliable and does not require elevated privileges. Suitable for most use cases.

```
python3 scanner.py --target 192.168.1.1 --ports 1-1024
```

### SYN Scan (requires root)

Sends a SYN packet and analyses the response without completing the handshake. Faster and less likely to be logged by the target, but requires root privileges for raw socket access.

```
sudo python3 scanner.py --target 192.168.1.1 --ports 1-1024 --syn
```

## Installation

```bash
git clone https://github.com/joemunene/advanced-port-scanner.git
cd advanced-port-scanner
pip install -r requirements.txt
```

The scanner uses Python's standard library (`asyncio`, `socket`, `struct`) for all core functionality. The only external dependency is `colorama` for terminal colours (optional — the tool degrades gracefully without it).

**Requirements:** Python 3.10+

## Usage

```
python3 scanner.py --target TARGET [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--target`, `-t` | Host, CIDR range, or comma-separated list | (required) |
| `--ports`, `-p` | Port spec: `80`, `1-1024`, `22,80,443` | top 100 |
| `--top-ports N` | Scan the top N common ports | 100 |
| `--timeout` | Connection timeout in seconds | 1.0 |
| `--threads` | Max concurrent connections | 200 |
| `--format`, `-f` | Output format: `table`, `json`, `csv` | table |
| `--output`, `-o` | Write results to a file | stdout |
| `--syn` | Use SYN scan (requires root) | off |

### Examples

Scan a single host on the top 1024 ports:

```bash
python3 scanner.py --target 192.168.1.1 --ports 1-1024
```

Scan a subnet with the top 50 ports and save JSON output:

```bash
python3 scanner.py --target 10.0.0.0/24 --top-ports 50 --format json --output results.json
```

Scan multiple hosts with high concurrency:

```bash
python3 scanner.py --target 192.168.1.1,192.168.1.2,192.168.1.3 --ports 22,80,443,3306,5432 --threads 500
```

SYN scan with custom timeout:

```bash
sudo python3 scanner.py --target 192.168.1.1 --ports 1-1024 --syn --timeout 2
```

## Example Output

```
==============================================================================
Scan Report: 192.168.1.1
------------------------------------------------------------------------------
  OS Hint  : Linux/Unix (TTL<=64) | Linux/Unix (SSH, no SMB)
  TTL      : 64
  Scan Time: 4.32s
------------------------------------------------------------------------------
  PORT      STATE     SERVICE           BANNER / INFO
------------------------------------------------------------------------------
  22        open      ssh               SSH-2.0-OpenSSH_8.9p1 Ubuntu-3
  80        open      http              HTTP/1.1 200 OK
  443       open      https             HTTPS / TLS
  3306      open      mysql             5.7.42-0ubuntu0.18.04.1
==============================================================================
```

## Performance Notes

- Default concurrency of 200 simultaneous connections works well for most networks.
- For local network scanning, increase to `--threads 500` or higher for faster results.
- For scanning across the internet, keep concurrency moderate and increase `--timeout` to avoid false negatives.
- Scanning all 65,535 ports on a single host with 500 threads typically completes in under 60 seconds on a fast connection.
- The async architecture means "threads" are actually coroutine slots, not OS threads, so memory overhead is minimal.

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Unauthorized port scanning may violate laws and regulations in your jurisdiction. Always obtain explicit written permission before scanning any network or system that you do not own.

The authors assume no liability for misuse of this software.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
