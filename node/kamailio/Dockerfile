# DOTS node: Kamailio from distribution packages (decision D9).
#   default:                Ubuntu 26.04 LTS archive (Kamailio 6.0.x)
#   KAMAILIO_REPO=kamailio61 BASE_IMAGE=ubuntu:24.04: deb.kamailio.org (6.1.x)
ARG BASE_IMAGE=ubuntu:26.04
FROM ${BASE_IMAGE}
ARG KAMAILIO_REPO=ubuntu
RUN set -eu; apt-get update; \
    if [ "$KAMAILIO_REPO" != "ubuntu" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg; \
      curl -fsSL https://deb.kamailio.org/kamailiodebkey.gpg | gpg --dearmor -o /usr/share/keyrings/kamailio.gpg; \
      echo "deb [signed-by=/usr/share/keyrings/kamailio.gpg] http://deb.kamailio.org/$KAMAILIO_REPO noble main" \
        > /etc/apt/sources.list.d/kamailio.list; \
      sed -i "s/ noble / $(. /etc/os-release; echo $VERSION_CODENAME) /" /etc/apt/sources.list.d/kamailio.list; \
      apt-get update; \
    fi; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      kamailio kamailio-tls-modules kamailio-secsipid-modules kamailio-json-modules \
      kamailio-extra-modules kamailio-utils-modules kamailio-postgres-modules ca-certificates; \
    rm -rf /var/lib/apt/lists/*
COPY node/kamailio/kamailio.cfg /etc/kamailio/kamailio.cfg
COPY node/kamailio/entrypoint.sh /usr/local/bin/dots-kamailio
EXPOSE 5060/udp 5061/tcp 8088/tcp
ENTRYPOINT ["/usr/local/bin/dots-kamailio"]
