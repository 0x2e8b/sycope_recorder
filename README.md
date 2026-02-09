# n2disk PCAP Extraction for Sycope

Continuous packet recording with on-demand PCAP extraction triggered by Sycope alerts.

## Purpose

The system continuously records network traffic to PCAP files in rolling mode (oldest files are overwritten automatically). When Sycope detects an alert, it sends a webhook containing alert details (IP, port, protocol, timestamp). The listener receives the webhook, builds a BPF filter, and uses `npcapextract` to extract only the matching packets from the recorded PCAPs. The extracted PCAP file is then served over HTTP for download.

## Requirements

### System

- **Linux** with a network interface for capture (default: `ens18`)
- **n2disk** — ntop tool for continuous packet recording to PCAP ([ntop.org](https://www.ntop.org/products/traffic-recording-replay/n2disk/))
- **npcapextract** — ntop tool for extracting packets from n2disk timeline (installed alongside n2disk)
- **Python 3.6+**
- **Sycope** — configured to send webhook alerts to the listener address

### Storage

- `/storage/pcaps/rolling` — rolling PCAPs (n2disk writes 5-minute files here)
- `/storage/pcaps/alerts` — extracted alert PCAPs

## Project Structure

```
n2disk/
├── config/
│   ├── config.json       # Runtime configuration (IPs, ports, paths, defaults)
│   ├── n2disk.conf       # n2disk daemon configuration
│   └── n2disk.service    # systemd unit file
├── src/
│   ├── config_loader.py  # Shared config loading module
│   ├── listener.py       # Webhook listener — receives alerts, extracts PCAPs
│   └── fileserver.py     # HTTP file server — serves extracted PCAPs
├── examples/             # Demo files
└── README.md

```

## Configuration

All runtime settings are in `config/config.json`:

| Field | Description | Default |
|-------|-------------|---------|
| `host` | Server IP address (used for file server URL) | `192.168.0.109` |
| `listen_port` | Webhook listener port | `8888` |
| `fileserver_port` | File server port | `8081` |
| `timeline_dir` | n2disk rolling PCAP directory | `/storage/pcaps/rolling` |
| `output_dir` | Extracted PCAP output directory | `/storage/pcaps/alerts` |
| `default_filter` | Default BPF filter mode | `full` |
| `default_before` | Default seconds before alert | `360` |
| `default_after` | Default seconds after alert | `360` |
| `max_concurrent_extractions` | Max concurrent `npcapextract` runs | `1` |
| `listener_auth_user` | Listener basic auth username (empty = disabled) | `""` |
| `listener_auth_pass` | Listener basic auth password (empty = disabled) | `""` |
| `fileserver_auth_user` | Fileserver basic auth username (empty = disabled) | `""` |
| `fileserver_auth_pass` | Fileserver basic auth password (empty = disabled) | `""` |
| `allowed_ips` | Optional allowlist for fileserver (CIDR or IP) | `[]` (e.g. `["192.168.0.0/24", "10.0.0.5"]`) |

## Components

| Script | Port | Description |
|--------|------|-------------|
| `src/listener.py` | 8888 | Receives webhook POST from Sycope, runs `npcapextract`, returns URL to extracted PCAP |
| `src/fileserver.py` | 8081 | Serves extracted PCAP files over HTTP |

## Setup

### n2disk (systemd)

```bash
cp config/n2disk.conf /etc/n2disk/n2disk.conf
cp config/n2disk.service /etc/systemd/system/n2disk.service
systemctl daemon-reload
systemctl enable --now n2disk
```

### Listener + file server

```bash
python3 src/listener.py &
python3 src/fileserver.py &
```

> Note: both services are unauthenticated by default. Put them behind a firewall, reverse proxy, or other access control if exposed outside a trusted network.
> The fileserver supports optional IP allowlisting (`allowed_ips`) and directory listing is disabled by default.
> If `max_concurrent_extractions` is exceeded, the listener responds with HTTP `429` and a `Retry-After: 5` header.

### Listener + file server (systemd)

Optional systemd units to keep the services running after reboots:

```bash
# listener
cat >/etc/systemd/system/pcap-listener.service <<'EOF'
[Unit]
Description=Sycope PCAP extraction listener
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/n2disk/src
ExecStart=/usr/bin/python3 /opt/n2disk/src/listener.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# fileserver
cat >/etc/systemd/system/pcap-fileserver.service <<'EOF'
[Unit]
Description=PCAP file server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/n2disk/src
ExecStart=/usr/bin/python3 /opt/n2disk/src/fileserver.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now pcap-listener pcap-fileserver
```

### Sycope configuration

In Sycope, add a webhook action pointing to the listener:

```
POST http://<LISTENER_IP>:8888/extract?filter=full&before=360&after=360
```

Available filter modes: `full`, `hosts`, `client`, `server`, `port`. The `before`/`after` parameters define the extraction time window (in seconds) relative to the alert timestamp.

If you enabled listener basic auth in `config/config.json`, set **basicAuth** in Sycope with the same username/password.
Fileserver uses its own credentials (`fileserver_auth_user` / `fileserver_auth_pass`).

### Example alert payload

```json
{
  "id": "alert_12345",
  "name": "Suspicious traffic",
  "clientIp": "10.0.0.10",
  "serverIp": "10.0.0.20",
  "serverPort": 443,
  "protocolName": "tcp",
  "unixTimestamp": 1739100000
}
```

## How it works

```
Network traffic
     │
     ▼
  n2disk ──────► /storage/pcaps/rolling/ (rolling PCAPs, 5-min files)
                        │
Sycope alert            │
     │                  │
     ▼                  ▼
 listener.py ──► npcapextract ──► /storage/pcaps/alerts/*.pcap
                                        │
                                        ▼
                                  fileserver.py ──► HTTP download
```

## Troubleshooting

- **No extracted PCAPs created**: check that `npcapextract` is in `PATH` and `timeline_dir` is correct.
- **Empty PCAP files**: BPF might be too strict or the alert timestamp is outside the rolling window.
- **"NO BPF FILTER" response**: alert payload is missing IPs/port/protocol fields used for filter creation.
- **HTTP 429**: too many concurrent extractions; increase `max_concurrent_extractions` or retry later.
- **Permission errors**: ensure the service user can read `timeline_dir` and write to `output_dir`. The rolling directory is owned by `n2disk:ntop` — the service user must be in the `ntop` group.
    
## Demo / replay (optional)

`src/netflow_replay.py` replays NetFlow v9 packets from a PCAP to a Sycope collector for demo purposes.  
Update `PCAP_FILE`, `SYCOPE_IP`, and `SYCOPE_PORT` inside the script before running.
