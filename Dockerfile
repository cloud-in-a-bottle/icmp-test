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

EXPOSE 5000
CMD ["python", "-u", "/app/app.py"]
