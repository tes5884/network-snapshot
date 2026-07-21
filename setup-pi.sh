#!/usr/bin/env bash
# Provision a Raspberry Pi as a phone-dispatched field scanner.
# Run from the cloned repo directory:  sudo bash setup-pi.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "== Network Snapshot — field scanner setup =="

# 1. Install the scanning tools (nmap, arp-scan, tcpdump, …)
python3 "$DIR/collect.py" --check --yes || true

# 2. Agent config
if [ ! -f "$DIR/agent.conf" ]; then
  cp "$DIR/agent.conf.example" "$DIR/agent.conf"
  echo
  echo ">> Edit $DIR/agent.conf — set teqhub_url and enroll_secret — then re-run this script."
  exit 1
fi

# 3. systemd service (runs as root; scans need raw sockets)
UNIT=/etc/systemd/system/netsnapshot-agent.service
tee "$UNIT" >/dev/null <<SERVICE
[Unit]
Description=Network Snapshot field scanner agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=/usr/bin/python3 $DIR/agent.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now netsnapshot-agent.service

echo
echo "Agent installed and running. It will appear in TEQhub → Scanners as an"
echo "'unclaimed' device — open the app and claim/name it. Then dispatch scans"
echo "to it from your phone."
echo "Logs:  journalctl -u netsnapshot-agent -f"
