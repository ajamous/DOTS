# rtpengine (userspace forwarding) from the Ubuntu 26.04 LTS archive.
FROM ubuntu:26.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rtpengine-daemon iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY node/rtpengine/entrypoint.sh /usr/local/bin/dots-rtpengine
ENTRYPOINT ["/usr/local/bin/dots-rtpengine"]
