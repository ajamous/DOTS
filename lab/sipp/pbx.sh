#!/bin/sh
# The operator's PBX: register AOR "pbx" at the home node, then answer calls.
#   DOTS_NODE_ID  node id used as the registration domain
#   REGISTRAR     host to register with (an instance of the node)
set -eu
: "${DOTS_NODE_ID:?}" "${REGISTRAR:?}"
IP=$(hostname -i | awk '{print $1}')

register() {
  sipp -sf /scenarios/register.xml -m 1 -p "$1" -i "$IP" -nostdin \
    -set domain "$DOTS_NODE_ID" -set contact_port 5060 \
    -timeout 5s -timeout_error "$REGISTRAR:5060" >/dev/null 2>&1
}

until register 5070; do echo "waiting for $REGISTRAR"; sleep 2; done
echo "registered pbx@$DOTS_NODE_ID via $REGISTRAR"
( while sleep 20; do register 5071 || true; done ) &

exec sipp -sf /scenarios/uas.xml -i "$IP" -p 5060 -mi "$IP" -rtp_echo -nostdin \
  -max_socket 2000 -trace_err -error_file /tmp/uas_errors.log
