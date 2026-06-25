# Scanner Setup Guide

## Overview

Othos supports three scanner protocols:

| Protocol | Type | Connection | Best For |
|---|---|---|---|
| **eSCL** | Network | Ethernet/WiFi | Modern network scanners (HP, Canon, Epson, etc.) |
| **SANE** | USB | Direct cable | Linux USB scanners |
| **WIA** | USB | Direct cable | Windows USB scanners |

**eSCL scanners** work with the **Othos Scanner Agent** — a pip-installable Python package that runs on any device connected to the same network as your scanner (Mac, Windows, Linux, Raspberry Pi) and creates a secure WebSocket tunnel to the Othos backend.

**USB scanners (SANE/WIA)** require the backend to run on the same machine as the scanner (on-prem only) or use a local network setup with Tailscale VPN.

This architecture works identically for local development and production deployments — no VPN or port forwarding required.

---

## Architecture

```
Frontend (browser)
      │  POST /api/v1/scan/sessions
      │  POST /api/v1/scan/sessions/:id/configure
      │  POST /api/v1/scan/sessions/:id/scan
      ▼
Backend (Docker container / Cloud)
      │  WebSocket: proxies scan to agent
      │  GET /api/v1/scanners/agent/ws/{agent_id}
      ▼
Othos Agent (runs on office network device)
      │  HTTP: local LAN access
      │  Discovers and controls scanners
      ▼
Scanner (HP DeskJet / any eSCL device)
```

**Key Benefits:**
- Agent runs on the same LAN as the scanner — can reach `192.168.x.x` IPs directly
- WebSocket connection is outbound from agent → backend (no inbound firewall rules)
- Works through NAT, firewalls, and cloud deployments without VPN
- Identical setup for development and production

---

## Development Setup (All Platforms)

The same agent-based workflow is used for local development and production.

### Prerequisites

- Python 3.8+ installed on the machine running the agent
- **eSCL-compatible network scanner** (most modern HP, Canon, Epson, Brother printers)
- The agent machine must be on the same network as the scanner
- Backend running (local Docker or cloud)

> **Note:** The agent only supports eSCL network scanners. For USB scanners (SANE/WIA), see the Direct LAN Setup section below.

### Step 1 — Install the Agent

From the machine that can reach your scanner:

```bash
pip3 install git+https://github.com/hiedberg/othos-agent.git
```

### Step 2 — Find your printer IP (optional but recommended)

> **Skip this step if you have mDNS/Bonjour enabled** (most home/office networks). The agent will discover the scanner automatically via Bonjour without needing its IP.

On **corporate or enterprise networks** (e.g. `10.x.x.x`, `172.x.x.x`) the ARP table shows raw IPs with no hostnames, so scanner brand names won't appear. Use the MAC address OUI prefix instead:

**macOS / Linux:**
```bash
arp -a | awk '{print $2, $4}' | grep -viE "^(--|ff:ff|01:00|33:33)" | sort
```
Then look up the vendor of each MAC address at **https://macvendors.com** — scanner/printer vendors include `HP Inc`, `Seiko Epson`, `Canon`, `Brother`, `Xerox`.

**Windows (PowerShell):**
```powershell
arp -a | Select-String -Pattern "dynamic" | ForEach-Object {
    $parts = $_.ToString().Trim() -split '\s+'
    [PSCustomObject]@{ IP = $parts[0]; MAC = $parts[1] }
} | Format-Table -AutoSize
```
Look up MAC prefixes at https://macvendors.com.

**Alternatively — if your scanner has a display panel:**
Go to the printer's **Settings → Network / Wi-Fi → TCP/IP** menu. The IP address is shown directly.

Once you have the IP, pass it to the agent with `--hint` (tries that IP first, then falls back to subnet scan) or `--scanner` (skips scan entirely):
```bash
# Try a hinted IP first
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000 --hint 10.112.132.202

# Use exact IP:PORT (fastest, no scan needed)
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000 --scanner 10.112.132.202:80
```

### Step 3 — Generate a Pairing Code

1. Open the Othos web app → **Settings → Scanners → Connect Agent**
2. Enter the printer IP (e.g. `192.168.1.253:8080`) in the Step 2 field
3. Click **Generate Pairing Code** — a 10-minute one-time code appears and the run command is copied to your clipboard

### Step 4 — Run the Agent

```bash
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000
```

**With a known printer IP (skips subnet scan — faster and more reliable):**
```bash
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000 --scanner 192.168.1.253:8080
```

**With ngrok (for testing external access):**
```bash
python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://your-app.ngrok-free.app --insecure
```

**SSL Options:**

| Flag | Purpose | When to Use |
|---|---|---|
| `--insecure` | Skip SSL verification | Development with ngrok, self-signed certs |
| `--ca-bundle /path/to/ca.pem` | Use custom CA bundle | On-prem with internal/private CA |
| `--subnet 192.168.x.0/24` | Force specific subnet | Auto-detection fails |
| `--scanner IP:PORT` | Skip discovery, use known IP directly | Fastest — bypasses subnet scan |

**Expected output:**
```
2024-01-15 09:30:12 [INFO] Othos Agent v1.0.0 starting...
2024-01-15 09:30:12 [INFO] Pairing with workspace...
2024-01-15 09:30:13 [INFO] Paired successfully! Agent ID: abc-123-def
2024-01-15 09:30:13 [INFO] Connecting to WebSocket...
2024-01-15 09:30:14 [INFO] WebSocket connected
2024-01-15 09:30:14 [INFO] Scanning subnet 192.168.1.0/24 for eSCL printers...
2024-01-15 09:30:16 [INFO] Found scanner [eSCL]: HP DeskJet 2700 at 192.168.1.253:80
2024-01-15 09:30:16 [INFO] Reported 1 scanner(s) to backend
```

### Step 5 — Verify in the UI

Return to **Settings → Scanners → Connect Agent**:
- Agent status shows **Connected**
- Discovered scanners appear under **Registered Scanners**

### Step 6 — Scan

1. Go to **Documents** or **Extraction**
2. Click **Scan** → Select your scanner
3. Place a page on the scanner glass and click **Scan**

---

## Production Setup

### Cloud Server + Office Printer (eSCL via Agent)

For **network scanners** (eSCL) in cloud deployments:

```
AWS/GCP/Azure Backend
      │  WebSocket (outbound from office)
      ▼
Office Device running othos-agent
      │  LAN HTTP to printer
      ▼
HP DeskJet / any eSCL printer (192.168.x.x)
```

**Setup:**
1. Install agent on office device:
   ```bash
   pip3 install git+https://github.com/hiedberg/othos-agent.git
   ```
2. Generate pairing code in UI (Settings → Scanners → Connect Agent)
3. Run agent with production server:
   ```bash
   python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://othos.yourdomain.com --scanner 192.168.1.253:8080
   ```

> **USB scanners (SANE/WIA)** are not supported via the agent. Use Tailscale VPN or on-prem deployment for USB scanners.

### Running as a Service

**macOS (launchd):**
```bash
# Create ~/Library/LaunchAgents/com.othos.agent.plist
launchctl load ~/Library/LaunchAgents/com.othos.agent.plist
```

**Linux (systemd):**
```ini
[Unit]
Description=Othos Scanner Agent

[Service]
ExecStart=python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://othos.yourdomain.com --scanner 192.168.1.253:8080
Restart=always

[Install]
WantedBy=multi-user.target
```

**Raspberry Pi:** Same systemd method as Linux — recommended for always-on office deployments.

---

## Alternative: Tailscale VPN Setup

Use Tailscale when you want the backend to directly reach scanners on a remote LAN (bypassing the agent).

### Use Case

- Cloud backend (AWS Lightsail, GCP, Azure) needs to reach office printers on `192.168.x.x`
- You prefer direct LAN access over the agent-based WebSocket tunnel
- Already using Tailscale for other infrastructure

### Architecture

```
AWS Backend (100.x.x.x) ──Tailscale──► Office Mac/Linux (subnet router)
                                              │
                                              ▼
                                     HP DeskJet (192.168.1.253)
```

### Setup

#### 1. Install Tailscale on office subnet router

```bash
# macOS
brew install tailscale
brew services start tailscale
sudo tailscale up --advertise-routes=192.168.1.0/24 --accept-routes

# Linux
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --advertise-routes=192.168.1.0/24 --accept-routes
```

#### 2. Approve routes in Tailscale Admin

1. Go to https://login.tailscale.com/admin/machines
2. Find your router → click **...** → **Edit route settings**
3. Enable `192.168.1.0/24` → Save

#### 3. Install Tailscale on backend server

```bash
curl -fsSL https://tailscale.com/install.sh | sudo sh
sudo tailscale up --accept-routes
```

#### 4. Register scanner in UI

Go to **Settings → Scanners → Add Manually**:

| Field | Value |
|---|---|
| Scanner Name | HP DeskJet 2700 |
| IP Address | `192.168.1.253` |
| Port | `80` |
| Protocol | `eSCL` |

The backend will now reach the printer directly through Tailscale.

### Ongoing Requirements

- Subnet router must stay online with Tailscale active
- For always-on use, use a dedicated Linux machine or Raspberry Pi instead of a developer Mac

---

## USB Scanner Setup (SANE/WIA - On-Prem Only)

USB scanners require the backend to have direct hardware access. This only works for on-prem deployments or when the backend runs on the same machine as the scanner.

### Linux (SANE)

SANE is auto-detected when the `sane` Python package is installed.

```bash
# Install SANE system libraries
sudo apt-get install sane libsane-dev

# Install Python bindings
pip install sane

# Test scanner detection
scanimage -L
```

### Windows (WIA)

WIA scanners are auto-detected when running the backend natively on Windows with the `pywin32` package installed.

```bash
pip install pywin32
```

> **Note:** Docker Desktop on Windows cannot access USB scanners directly. Run the backend natively or use WSL2 with USB passthrough.

---

## Legacy: Direct LAN Setup (eSCL - On-Prem Only)

If Othos is self-hosted on the same LAN as eSCL network printers (no agent needed):

```env
SCANNER_IPS=192.168.1.100,192.168.1.101
SCANNER_NAMES=Canon Office,HP Breakroom
SCANNER_PORTS=80,80
SCANNER_WORKSPACE_ID=uuid-here  # optional
```

Scanners auto-register on backend startup. Discovery probes the local network directly.

---

## Environment Reference

### Backend Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SCANNER_DISCOVERY_PORTS` | No | `8080,80,443` | Ports to probe during discovery |
| `SCANNER_DISCOVERY_TIMEOUT_SECONDS` | No | `2.0` | Per-host probe timeout |
| `SCANNER_DISCOVERY_MAX_HOSTS` | No | `512` | Max hosts per discovery run |

### Frontend Environment Variables

| Variable | Required | Description |
|---|---|---|
| `VITE_API_URL` | No | Backend API URL for agent pairing command display |

---

## Quick Reference

### Install / Uninstall / Upgrade

| Operation | Command | Notes |
|---|---|---|
| **Install (production)** | `pip3 install git+https://github.com/hiedberg/othos-agent.git` | From git repo |
| **Install (local dev)** | `pip3 install -e .` | Editable — picks up live code changes |
| **Uninstall** | `pip3 uninstall othos-agent` | Standard pip, works on all platforms |
| **Version check** | `python3 -m othos_agent --version` | Prints `othos-agent 1.0.0` and exits |
| **Upgrade** | `python3 -m othos_agent --upgrade` | Upgrades via the same Python that installed the agent, then exits |

> `--upgrade` uses `sys.executable` internally — upgrades against the correct pip regardless of PATH. Works identically on macOS, Linux, and Windows.

### Agent Commands

```bash
# Install
pip3 install git+https://github.com/hiedberg/othos-agent.git

# Check installed version
python3 -m othos_agent --version

# Upgrade to latest
python3 -m othos_agent --upgrade

# Local development
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000

# With known printer IP (faster, skips subnet scan)
python3 -m othos_agent --code XXXX-XXXX-XXXX --server http://localhost:8000 --scanner 192.168.1.253:8080

# Production (HTTPS)
python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://othos.yourdomain.com --scanner 192.168.1.253:8080

# With ngrok / self-signed cert
python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://xxx.ngrok-free.app --insecure

# Force specific subnet
python3 -m othos_agent --code XXXX-XXXX-XXXX --server https://othos.yourdomain.com --subnet 192.168.1.0/24

# Uninstall
pip3 uninstall othos-agent
```

### Backend Logs

```bash
# View agent-related logs
docker logs othos-backend | grep -i agent

# View scanner-related logs
docker logs othos-backend | grep -i scanner
```

### Testing Scanner Directly

```bash
# From agent machine - test scanner eSCL endpoint
curl http://192.168.1.253/eSCL/ScannerCapabilities
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **Agent Connection Issues** |
| Agent pairing returns 403 CSRF | Old backend version | Backend `/api/v1/scanners/agent/` is CSRF-exempt; upgrade backend if needed |
| Agent WebSocket disconnects repeatedly | SSL cert verification failure | Use `--insecure` for ngrok/self-signed, or `--ca-bundle` for internal CA |
| Agent connects but no printers found | No eSCL devices on subnet or wrong subnet detection | Check agent startup log for detected interfaces; pass `--subnet 10.x.0.0/16` for corporate networks |
| Step 2 `arp -a` shows only IPs, no names | Corporate/enterprise network — no hostname resolution | Use MAC OUI lookup (see Step 2) or check printer display panel for IP |
| Scanner found on home network but not office/work laptop | Default network interface picks wrong subnet | Agent will list all interfaces at startup; pass `--subnet` matching the interface the scanner is on |
| **Scanner Discovery Issues** |
| `No scanners found` in UI | Agent not running or no eSCL scanners on network | Verify agent is connected in UI; check agent logs; ensure scanner supports eSCL |
| Scanner shows "Offline" | Agent disconnected | Check agent machine is online and WebSocket connection is active |
| **Scan Failures** |
| Scan starts but times out | Scanner busy or network issue | Check scanner is ready (not in sleep mode); verify LAN connectivity from agent machine |
| Scan completes but file not received | Upload failed | Check agent logs for upload errors; verify backend storage is accessible |
| **Tailscale VPN Issues** |
| Scanner shows "Unreachable" via Tailscale | Subnet router offline or routes not approved | Check subnet router is running; approve routes in Tailscale admin console |
| Tailscale tunnel drops intermittently | Mac went to sleep or network changed | Use dedicated Linux/Raspberry Pi as subnet router instead of Mac |
| **Legacy: Direct LAN Mode (On-Prem Only)** |
| `No scanners found` on auto-discover | Backend not on same LAN as printers | Use **Add Manually** instead, or switch to agent-based setup |
