# SIPp 3.7 from the Ubuntu 26.04 LTS archive, plus the lab scenarios.
FROM ubuntu:26.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sip-tester iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY lab/sipp/*.xml /scenarios/
COPY lab/sipp/pbx.sh /usr/local/bin/dots-pbx
WORKDIR /scenarios
