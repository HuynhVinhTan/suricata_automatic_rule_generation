#!/usr/bin/env bash
set -euo pipefail
echo "HOST=$(hostname) USER=$(id -un)"
ip -4 -o addr show ens33
echo "SURICATA=$(systemctl is-active suricata)"
echo "FILEBEAT=$(systemctl is-active filebeat)"
suricata --build-info | head -5
pgrep -af '/usr/bin/suricata' || true
pgrep -af '/usr/share/filebeat/bin/filebeat' || true
stat -c 'EVE=%n SIZE=%s MTIME=%y' /var/log/suricata/eve.json
df -h / /var/log
echo 'SHOWCASE_ROOT=/home/tanhv/suricata-ai-showcase'
