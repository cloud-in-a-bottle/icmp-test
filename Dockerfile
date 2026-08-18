FROM python:3.12-slim

# iputils-ping  -> the system `ping` binary (uses ICMP datagram sockets, falls
#                  back to raw sockets)
# traceroute    -> exercises the non-echo ICMP (time-exceeded) path
# libcap2-bin   -> `capsh --print` for capability introspection
# iproute2      -> `ip addr` / `ip route` for netns introspection
# util-linux    -> `setpriv`, used to re-run probes as a non-root uid/gid
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping \
        traceroute \
        libcap2-bin \
        iproute2 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py /app/app.py

# A copy of ping carrying the cap_net_raw file capability. The probe suite runs
# it as an unprivileged uid to show the standard workaround for images whose
# USER is not root: CAP_NET_RAW is in the container's bounding set, so a file
# capability on the binary survives the uid change, while a plain ICMP datagram
# socket does not (podman defaults net.ipv4.ping_group_range to "0 0").
RUN cp "$(command -v ping)" /usr/local/bin/ping-filecap \
    && (setcap cap_net_raw+ep /usr/local/bin/ping-filecap \
        || echo "setcap unavailable at build time; ping-filecap has no capability")

EXPOSE 5000
CMD ["python", "-u", "/app/app.py"]
