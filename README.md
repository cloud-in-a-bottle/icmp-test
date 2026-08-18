# icmp-test

A diagnostic Cloud in a Bottle app that answers, empirically and from inside an
app container: **can a Cloud in a Bottle app send and receive ICMP pings?**

It exists because the answer is not obvious. App containers run under rootless
podman with `--cap-drop=ALL` plus a re-added baseline that includes `NET_RAW`,
and the default network backend is `pasta`, which translates only certain kinds
of traffic between the container namespace and the host.

## What it tests

1. **Outbound ICMP echo** — three independent mechanisms:
   - an ICMP datagram ("ping") socket: `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`,
     which needs the caller's gid to be inside `net.ipv4.ping_group_range`;
   - a raw socket: `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`, which needs `CAP_NET_RAW`;
   - the system `ping` binary.
2. **The same probes as an unprivileged uid/gid** (`nobody`, via `setpriv`), which
   is what an app image that sets a non-root `USER` actually gets.
3. **IPv6 / ICMPv6** equivalents.
4. **Non-echo ICMP** — a TTL-limited echo (expects a `time-exceeded` from the
   first hop) and `traceroute -I`. This is what traceroute, mtr, and path-MTU
   discovery depend on.
5. **Inbound ICMP** — a background sniffer holds a raw ICMP socket and records
   every ICMP packet delivered into the container's network namespace. Ping the
   instance from elsewhere, then read `/api/sniffer` to see whether the request
   was delivered to the app.

It also dumps the relevant environment: uid/gid, `CapEff`/`CapBnd`/`CapAmb`,
`capsh --print`, `net.ipv4.ping_group_range`, `getcap` on the `ping` binary,
interfaces, routes, and `resolv.conf`.

## Endpoints

| Path | Description |
| --- | --- |
| `/` | HTML report; runs the whole suite on each load |
| `/api/suite` | the same report as JSON (`?count=N`, `?targets=a,b,c`) |
| `/api/ping` | one probe: `?target=1.1.1.1&mode=dgram\|raw\|binary\|dgram-unprivileged\|raw-unprivileged\|binary-unprivileged&count=3&ttl=&v6=0` |
| `/api/sniffer` | inbound ICMP observed so far |
| `/api/env` | capabilities, sysctls, interfaces |
| `/health` | liveness (`ok`) |

## Deploy

```
oh app deploy https://github.com/cloud-in-a-bottle/icmp-test
```

Then open `https://icmp-test.<your-zone>/`.

To check the inbound direction, ping the instance's public IP from your machine
while the app is running, then reload the page and look at
`inbound_echo_requests`.

## CLI

The probes can be run directly, which is also how the unprivileged variants are
executed internally:

```
python app.py --probe --mode dgram --target 1.1.1.1 --count 3
python app.py --probe --mode raw --target 1.1.1.1 --ttl 1
```
