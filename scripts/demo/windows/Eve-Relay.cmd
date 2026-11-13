@echo off
set SINK=%~1
if "%SINK%"=="" set SINK=/home/tanhv/suricata-ai-showcase/eve-shadow
ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm1 "tail -F -n 0 /var/log/suricata/eve.json" | ssh -T -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes suricata-vm3 "/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-relay-sink.py --root %SINK%"

