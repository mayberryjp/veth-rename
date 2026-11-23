# IPFIX installation specification

This guide installs the GitHub release of veth-renamer and enables its optional
eBPF-to-IPFIX exporter on an Ubuntu Docker host. Commands are for the exporter
server unless explicitly marked **collector**.

Run the commands as root (`sudo -i` if needed). Stop and resolve any failed step
before continuing.

## 1. Prerequisites

- Rootful Docker Engine running on the host.
- Linux kernel 6.6 or newer with TCX/eBPF support.
- Debian architecture `amd64` or `arm64`.
- A reachable collector listening for **UDP IPFIX version 10**.
- Firewall/routing rules allowing traffic to the collector's UDP port.

```bash
uname -r
dpkg --print-architecture
systemctl is-active docker
docker info
```

Ubuntu 24.04 and a compatible Ubuntu 26.04 host can run the package. The Ubuntu
24.04 pin in GitHub Actions applies only to build machines. Neither Go nor clang
is required on the server: the executable embeds the compiled eBPF program.

Use a trusted network. UDP IPFIX is neither encrypted nor delivery-guaranteed.

## 2. Download and install the GitHub release

Version `v0.1.9` includes this feature and is published at:

[v0.1.9 release](https://github.com/mayberryjp/veth-rename/releases/tag/v0.1.9)

For any newer version, wait until its release workflow has passed and the release
page contains the appropriate `.deb` package and `checksums.txt`. A Git tag or a
successful branch build alone does not make packages available.

Download the pinned installer, then run it only if the download succeeds:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/mayberryjp/veth-rename/v0.1.9/install.sh \
  -o /root/veth-renamer-install-v0.1.9.sh \
  && bash /root/veth-renamer-install-v0.1.9.sh --version v0.1.9
```

The downloaded script can be reviewed before execution by running the download
and `bash` commands separately. It automatically selects `amd64` or `arm64`,
downloads the Debian package, verifies its SHA-256 checksum and package identity,
and installs it using `apt-get`. Package installation does **not** start, enable,
or restart the daemon. On upgrades, an already running daemon keeps using its
previous executable until explicitly restarted.

Verify installation:

```bash
dpkg-query -W -f='${Package} ${Version}\n' veth-renamer
ls -l /usr/sbin/veth-renamer
ls -l /usr/share/doc/veth-renamer/ipfix.example.yaml \
      /usr/share/doc/veth-renamer/ipfix.conf
```

If the installer reports a failure, do not proceed to restart the service.
For release-asset `404` errors, confirm that the chosen version's release and
packages exist; its build may still be running. The API download fallback needs
`python3` if it is not already installed.

## 3. Configure IPFIX

Create the configuration directory and copy the example only when no
configuration already exists:

```bash
install -d -m 0755 /etc/veth-renamer
if [ ! -e /etc/veth-renamer/ipfix.yaml ]; then
  install -m 0644 /usr/share/doc/veth-renamer/ipfix.example.yaml \
    /etc/veth-renamer/ipfix.yaml
fi
nano /etc/veth-renamer/ipfix.yaml
```

Back up an existing configuration before editing it. Use YAML, not JSON.
Unknown fields, duplicate fields and invalid types are rejected.

Example:

```yaml
collector: "10.0.0.50:4739"
observation_domain_id: 1
active_timeout: 60s
idle_timeout: 15s
poll_interval: 1s
template_refresh: 30s
template_refresh_packets: 20
max_message_size: 464
max_flows_per_veth: 65536
sampling_rate: 1
capture_filter: ""
```

**Replace `10.0.0.50` with your actual collector address.** The shipped
`192.0.2.10` value is a documentation placeholder, not an operational collector.
Port `4739` is an example; use the port your collector actually listens on.

| Setting | Meaning |
|---|---|
| `collector` | Required DNS/IPv4 `host:port` or IPv6 `[address]:port`; UDP only. DNS resolves at startup. |
| `observation_domain_id` | Use a distinct ID for each exporter host; the example uses 1. |
| `active_timeout` | Export a segment of a continuing flow after 60 seconds. |
| `idle_timeout` | Export a flow after 15 seconds without another observed packet. |
| `poll_interval` | Check metering and queued exports every second. Must not exceed either flow timeout. |
| `template_refresh` | Refresh templates after 30 seconds, including during ongoing traffic; maximum 10 minutes. |
| `template_refresh_packets` | Also refresh after 20 successful data messages. Zero disables this condition, not timed refresh. |
| `max_message_size` | IPFIX UDP payload limit, 156..65507 bytes. Default 464 is conservative for unknown PMTU. |
| `max_flows_per_veth` | Concurrent active-flow capacity per monitored veth; default 65536. |
| `sampling_rate` | 1 means unsampled; N selects every Nth observed frame per veth. Counters are not scaled up. |
| `capture_filter` | `""` for all eligible IP traffic, or `ip`, `ip6`, `tcp`, `udp`, `icmp`, `icmp6`. |

For a **verified 1280-byte effective WireGuard path MTU**, a payload limit of
1200 bytes is suitable. Do not assume the physical interface MTU equals the path
MTU. Account for any additional headers or encapsulation.

The exporter enables nonfragmenting Linux PMTU discovery and clamps the payload
to the socket's path estimate, allowing for IPv4/UDP or IPv6/UDP headers.
`EMSGSIZE` reduces the budget and retains unsent records for rebatching.

## 4. Enable IPFIX in systemd

Installing the package alone does not enable monitoring. The service needs
`--ipfix-config=/etc/veth-renamer/ipfix.yaml` and the additional capabilities and
address families supplied by this drop-in:

```bash
install -d -m 0755 /etc/systemd/system/veth-renamer.service.d
if [ ! -e /etc/systemd/system/veth-renamer.service.d/ipfix.conf ]; then
  install -m 0644 /usr/share/doc/veth-renamer/ipfix.conf \
    /etc/systemd/system/veth-renamer.service.d/ipfix.conf
fi
nano /etc/systemd/system/veth-renamer.service.d/ipfix.conf
```

The supplied contents are:

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/veth-renamer --mode=primary-repair --mapping-file=/run/veth-renamer/mappings.json --ipfix-config=/etc/veth-renamer/ipfix.yaml
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_BPF CAP_PERFMON
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
```

**Preserve existing custom naming flags** when editing `ExecStart`. Review other
drop-ins for conflicting overrides. Keep the empty `ExecStart=` before the
replacement command. Do not add `--once`, `--dry-run` or network-namespace
isolation: monitoring requires daemon mode in the host network namespace.

The supplied service retains the existing `primary-repair` renaming behavior,
which can briefly interrupt a veth while repairing its name. IPFIX observation
itself does not modify packets, lower interfaces or replace existing classifiers.

## 5. Reload, enable and restart

Reload the unit and inspect the effective settings:

```bash
systemctl daemon-reload
systemctl cat veth-renamer.service
systemctl show veth-renamer.service \
  -p ExecStart -p CapabilityBoundingSet -p RestrictAddressFamilies
```

Confirm that the effective command includes `--ipfix-config`, that `CAP_BPF`,
`CAP_PERFMON` and `CAP_NET_ADMIN` are present, and that `AF_INET` and `AF_INET6`
are allowed. Resolve conflicting overrides before starting.

Enable startup at boot and start/restart the daemon:

```bash
systemctl enable veth-renamer.service \
  && systemctl restart veth-renamer.service
```

Changing YAML requires another restart. Editing a systemd drop-in requires
`systemctl daemon-reload` before that restart.

## 6. Verify operation

### Service and startup logs

```bash
systemctl is-enabled veth-renamer.service
systemctl is-active veth-renamer.service
systemctl status veth-renamer.service --no-pager
journalctl -u veth-renamer.service --since '5 minutes ago' --no-pager
```

Look for **`eBPF IPFIX monitoring enabled`** and inspect subsequent errors.
An active service or an enabled-monitoring log alone does not prove packet
capture or collector delivery.

### Eligible containers and traffic

Only verified host-side Docker veths belonging to containers with the existing
rename labels are monitored. Unlabeled containers, macvlan interfaces, physical
NICs and shared bridges are excluded.

For a container with one bridge-network attachment, the Compose label is:

```yaml
labels:
  host-veth-name: veth_myapp
```

Names must be unique on the host and fit the existing 1..15-character naming
rules. Already managed containers need no new labels. Changing labels on an
existing container generally requires recreating it; plan that separately to
avoid an unexpected service interruption. See the
[repository label documentation](README.md#labels) for multiple networks.

Generate normal IPv4/IPv6 traffic through a managed container's veth. With the
example timers, flow records normally appear after 15 seconds idle or 60 seconds
of continued traffic, plus polling/export delay. Templates send at startup and
refresh periodically, not in every data message.

### Exporter-side packet verification

If `tcpdump` is unavailable, install it with `apt-get install tcpdump`.
Replace the example address and port below:

```bash
tcpdump -ni any \
  '(udp and dst host 10.0.0.50 and dst port 4739) or icmp or icmp6'
```

Expect outgoing UDP packets to the configured collector. ICMP/ICMPv6 capture
can also expose unreachable-port or path-MTU errors. Stop capture with Ctrl+C.
Seeing outgoing packets proves local transmission, not remote reception.

### Collector-side verification

On the **collector**, check the UDP listener in the namespace/container where
the collector process runs:

```bash
ss -lunp | grep ':4739'
tcpdump -ni any 'udp dst port 4739'
```

The listener must bind a reachable address or wildcard, not only localhost.
For a containerized collector, publish the port as **UDP**, for example
`4739:4739/udp`; a TCP-only mapping is insufficient. A host-side `ss` listing
may not show a container listener when publishing uses NAT.

Finally, confirm the collector decodes IPFIX v10 templates 256/257 and actual
IPv4/IPv6 flow records. Flows are unidirectional; the collector correlates the
opposite direction. Configure template caching per transport session and
observation domain, with a lifetime of at least three times `template_refresh`
(at least 90 seconds for the example). UDP template loss can leave data
undecodable until the next refresh.

## 7. Common failures

| Symptom | Checks and action |
|---|---|
| Release download returns `404` | Wait for the tagged release workflow to finish; verify the release contains packages and checksums. |
| No monitoring-enabled startup log | Check the effective `ExecStart`, YAML path and startup errors; installation alone does not enable IPFIX. |
| YAML parse/validation error | Use `.yaml`/`.yml`, valid YAML types and supported fields; JSON is not supported. |
| eBPF load/attach error | Check kernel 6.6+, host namespace and the supplied capability settings. Verifier/attachment errors are logged explicitly. |
| UDP `connection refused` | Usually an ICMP Port Unreachable: check collector IP/port, UDP listener, bind address, container port mapping and firewall reject rules. UDP has no handshake, but connected sockets can report ICMP errors on later writes. |
| Templates but no flow records | Check container labels, endpoint verification, eligible traffic, filters, sampling and flow timeout delays. |
| Outgoing packets but no received/decoded records | Check routing/firewalls, collector capture, UDP transport, template cache and IPFIX v10 decoding. Successful sends are not collector acknowledgments. |
| `EMSGSIZE` or reduced-budget errors | Verify effective PMTU and encapsulation; the exporter retains the unsent suffix and retries smaller batches. |
| Metering-loss or incomplete-export errors | Check traffic volume, concurrent flow pressure and collector outages. Ring/pending buffers are bounded; no lossless guarantee applies under overload. |

Socket failures retain active/pending flow state and retry with backoff from
1 second to 30 seconds. Socket recreation sends templates before new-session
data. Restart/shutdown has a shared two-second flush budget; process termination
can still lose unexported in-memory records.

No status API, status file or periodic summary is provided. Verify with journald,
packet observation and the collector's decoded records.
