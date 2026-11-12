#!/usr/bin/env bash
set -euo pipefail
echo "HOST=$(hostname) USER=$(id -un)"
ip -4 -o addr show eth1
ping -c 2 -W 2 192.168.10.10
command -v python3
command -v tcpdump
df -h /home
