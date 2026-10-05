#!/bin/sh
# A customer of carrier B (node-b) calls a number served by your agent (node-c,
# range +1). Usage: examples/voice-agent/call.sh [number] [seconds]
set -eu
NUMBER=${1:-14155550142}
SECS=${2:-12}
cd "$(dirname "$0")/../.."
docker compose exec -T uac-b sh -c "IP=\$(hostname -i | awk '{print \$1}'); \
  sipp -sf /scenarios/uac.xml -s $NUMBER -set caller 447700900777 -i \$IP -mi \$IP \
  -p 5180 -mp 7180 -m 1 -d $((SECS * 1000 + 400)) -nostdin -timeout 60s -timeout_error \
  -trace_msg -message_file /tmp/agent-call.msg node-b1:5060 >/tmp/agent-call.log 2>&1 \
  && grep -q 'Successful call.*1' /tmp/agent-call.log"
# The Call-ID and From-tag your agent's SIP stack sees on the INVITE:
docker compose exec -T uac-b sh -c "awk '/^INVITE /{f=1} \
  f&&/^From:/{t=\$0; sub(/.*tag=/,\"\",t)} f&&/^Call-ID:/{c=\$2} \
  f&&c!=\"\"&&t!=\"\"{print \"call_id=\"c\"  from_tag=\"t; exit}' /tmp/agent-call.msg; rm -f /tmp/agent-call.msg"
echo "call to +$NUMBER answered by the agent after a carrier-B customer dialled it (${SECS}s)"
