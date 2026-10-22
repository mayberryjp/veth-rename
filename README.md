# veth-renamer

A small, dependency-free Go daemon for **rootful Docker Engine on an Ubuntu
host**. It reads container labels, finds the matching host-side bridge veth,
and applies a primary or alternative interface name. It also names macvlan
interfaces inside container network namespaces. Unlabeled containers are
never renamed.

## Important correction to the original proposal

**Do not assume an active veth can be renamed.** Linux normally rejects primary
interface renames while a device is UP (`Device or resource busy`). This service
never brings interfaces down, retries with downtime, or changes firewall rules.
Consequently, **primary mode will commonly report errors instead of renaming
running Docker interfaces**. Primary mode is the requested default, not a
guarantee of live renaming.

For readable names without disrupting running containers, use
`--mode=alternative`. This adds a Linux alternative name while preserving
Docker's original primary name and interface index. Alternative names require
kernel/iproute2 support (Linux 5.4+ and suitably recent iproute2); the installed
`ip` must support `ip link property add ... altname ...`. Ubuntu 22.04/24.04
normally have that support. Whether other software accepts alternative names
depends on the tool/version: test your actual tcpdump, SNMP agent, and monitoring
stack. An alternative name does **not** change the primary name shown by all
tools.

If primary names are essential and your kernel rejects the rename, applying them
requires a different deployment strategy that names links before they are UP,
or an explicitly scheduled interruption outside this service. This daemon does
not provide that strategy.

## Macvlan and docker-net-dhcp networks

Native Docker `macvlan` networks and
`ghcr.io/claymore666/docker-net-dhcp:<tag>` networks configured with
`mode=macvlan` are supported. The network must specify its host `parent`
interface, for example `enp44s0.20`.

Macvlan has no host-side veth peer. For these networks, the same labels and
`--mode` setting apply to the MAC-matched macvlan interface **inside the
container's network namespace**, not to the shared host parent. The daemon
validates the kernel link type and parent index before changing anything.
It never renames the host VLAN or physical interface.

Primary mode attempts a primary rename without bringing the interface down.
An UP macvlan interface can reject that rename, just like an UP veth; this is
reported as an error, not a skipped endpoint. Use `--mode=alternative` to add
the requested name while retaining `eth0` (or the existing primary name).
Neither mode creates a host-visible per-container interface. Applications or
DHCP clients that depend on the original interface name may be affected by a
successful primary rename; alternative mode avoids changing that name.

## Labels

One bridge-network attachment:

```yaml
services:
  pihole:
    image: pihole/pihole:latest
    labels:
      host-veth-name: veth_pihole
```

Names must be 1-15 ASCII characters using letters, digits, `_`, `-`, or `.`.
`.` and `..` are not allowed. Empty or invalid labels are errors, not silently
ignored. Keep names unique across the entire host, including alternative names.
Compose replicas need distinct labels per container or they will conflict.
Labels belong on the **container**, not the Docker network.

Multiple network attachments:

```yaml
services:
  app:
    image: nginx:alpine
    labels:
      host-veth-name.frontend: veth_app_front
      host-veth-name.backend: veth_app_back
    networks:
      - frontend
      - backend
networks:
  frontend:
    name: frontend
  backend:
    name: backend
```

The suffix must match the **actual Docker network name**, not necessarily the
Compose key. Without `name: frontend`, Compose usually names it
`<project>_frontend`, and the label must be
`host-veth-name.<project>_frontend`.

Network-specific labels override `host-veth-name`; they can also be used alone,
leaving other networks unmanaged. With a base label and multiple network
attachments, names are `<first-8-base-characters>-<6-hex-network-name-hash>`.
This stays within 15 bytes and is stable across recreation of a network with the
same name. Hash collisions are possible and are reported, never silently
resolved. Adding/removing attachments can change base-derived names; use
network-specific labels when attachment-independent names matter.

Existing names on an interface are not removed when labels change or the daemon
stops. In alternative mode, old alternative names can therefore accumulate until
Docker deletes the endpoint. Remove obsolete names explicitly, after checking
their ownership:

```bash
sudo ip link property del dev veth_original altname veth_old
```

## One-line installation (Ubuntu)

Once a release is published in
[mayberryjp/veth-rename](https://github.com/mayberryjp/veth-rename):

```bash
curl -fsSL https://raw.githubusercontent.com/mayberryjp/veth-rename/main/install.sh | bash
```

The installer detects the Debian architecture (`amd64` or `arm64`), resolves the
latest stable GitHub release, downloads its `.deb` and `checksums.txt`, verifies
the SHA-256 digest and package identity, and installs it through `apt-get`.
It uses `sudo` only for package installation and optional service control.
Requires `curl`, `sudo` (unless already root), and standard Ubuntu package tools.
If needed, run `sudo apt-get update` before installing so dependency indexes are
current. No Go toolchain is needed on the target host.

**Installation does not start, enable, or restart the daemon by default.**
To explicitly enable and start it:

```bash
curl -fsSL https://raw.githubusercontent.com/mayberryjp/veth-rename/main/install.sh | bash -s -- --start
```

`--start` enables and restarts the service, including on upgrades, so the newly
installed binary is used. The default naming mode remains **primary**, with the
UP-link limitation described above. Set a systemd override if you prefer
alternative names.

For reproducible installs, pin both the script and package to a release:

```bash
curl -fsSL https://raw.githubusercontent.com/mayberryjp/veth-rename/v0.1.1/install.sh | bash -s -- --version v0.1.1
```

These URLs require the source and a release to be published; the `v0.1.1` example
is not a claim that such a release already exists. The `main` branch URL tracks
the newest installer, while the default package version is the newest stable
release. Explicit `--version` also supports prerelease tags. Forks can use
`--repo OWNER/REPO` with an installer downloaded from their own repository.

Piping a script into Bash executes downloaded code. For greater control,
download and inspect it before running. Checksums detect corrupt or mismatched
assets; because the package and checksums come from the same GitHub release,
they do not protect against a compromised repository or publisher.

### Upgrade and uninstall

Rerun the installer to upgrade. Existing systemd overrides are preserved.
Without `--start`, a running daemon keeps its old process until you explicitly
run `sudo systemctl restart veth-renamer.service`.

```bash
sudo apt-get remove veth-renamer
```

Removal stops and disables the service. Administrator-created overrides are
left alone. Neither removal nor stopping the service restores primary names or
deletes alternative names on existing interfaces.

The package installs the binary in `/usr/sbin` and the unit in
`/usr/lib/systemd/system`. If migrating from an older manual install in
`/etc/systemd/system/veth-renamer.service`, first back up that local unit and
migrate custom settings into a systemd drop-in. Stop the service and remove the
old local unit after backing it up, then run `sudo systemctl daemon-reload` and
retry the installer. It refuses to silently override a local unit. An old
`/usr/local/sbin/veth-renamer` binary can be removed separately after migration.

## Build and preview

Requires Go 1.23+ to build; no Go modules need downloading.
Run these commands on the Ubuntu host:

```bash
sudo apt-get update
sudo apt-get install -y iproute2 util-linux
go test ./...
go vet ./...
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -o bin/veth-renamer .

# Read-only preview: no interface changes.
sudo ./bin/veth-renamer --once --dry-run

# Attempt primary names; a busy/UP link is an explicit error and nonzero exit.
sudo ./bin/veth-renamer --once

# Non-disruptive alternative naming.
sudo ./bin/veth-renamer --once --mode=alternative
```

For cross-compilation, set `GOOS=linux GOARCH=amd64` (or `arm64`) when
building. The executable runs only on Linux and must be in the host network
namespace. It calls the host's `ip` and `nsenter`; it does not require these
commands inside the containers.

## Install as a host service

```bash
sudo install -m 0755 bin/veth-renamer /usr/sbin/veth-renamer
sudo install -m 0644 deploy/veth-renamer.service /etc/systemd/system/veth-renamer.service
sudo systemctl daemon-reload
sudo systemctl enable --now veth-renamer
sudo journalctl -u veth-renamer -f
```

The supplied unit uses **primary mode**. To use alternative names:

```bash
sudo systemctl edit veth-renamer
```

Add this override:

```ini
[Service]
ExecStart=
ExecStart=/usr/sbin/veth-renamer --mode=alternative --mapping-file=/run/veth-renamer/mappings.json
```

Then run `sudo systemctl daemon-reload && sudo systemctl restart veth-renamer`.

The unit deliberately runs on the host as root, with bounded capabilities for
namespace entry and link management. It does not use a privileged container,
mount the Docker socket into a container, or enable a TCP Docker API. Access to
the Docker socket is **root-equivalent**, even though this implementation only
issues GET requests. Systemd hardening does not make the Docker socket safe for
untrusted code. Review the binary and labels as privileged configuration.
Do not enable `PrivateNetwork`: that would hide the host interfaces.

## Operation

- Scans running containers at startup and every 30 seconds.
- Listens for container/network Docker events, coalesces bursts, and reconciles.
- Reconnects after event-stream failures; full scans cover missed events,
  startup/attachment races, Docker restarts, and removals.
- For bridge networks, matches each Docker endpoint's MAC address against `ip -j -d link` **inside
  the container network namespace**, then checks reciprocal peer indices,
  host veth type, and expected bridge membership. No `eth0` assumption or host
  sysfs lookup inside just a network namespace.
- Supports the default bridge, custom Compose bridges, and explicit bridge
  names, plus container-side naming for the macvlan networks described above.
  Host/shared network namespaces are excluded; other drivers and DHCP plugin
  modes (including overlay, ipvlan, and none) are not managed.
- Revalidates the container PID/endpoint and both ends immediately before a
  change, checks primary and alternative-name collisions, and verifies the
  result afterward.
- Refuses all endpoints that request the same name. Does not evict names,
  rename unrelated interfaces, swap names, or bring links down.
- Logs errors as JSON to stderr/journald. Failed endpoints remain visible in
  the mapping snapshot and are retried on later scans. `--once` exits nonzero
  for any discovery, validation, rename, verification, or output error.
- Logs each unchanged skipped endpoint only once per daemon run, rather than
  on every scan. A changed mapping or an endpoint disappearing and returning
  allows a new skip log. Skipped endpoints remain in every mapping snapshot;
  restarting the daemon resets the log history.

Docker and the kernel do not provide a single transaction spanning inspection,
namespace entry, and renaming. Revalidation narrows races but cannot eliminate
the final check-to-operation window during concurrent endpoint destruction.
There is also no exclusive lock against another copy of the daemon or another
network manager. Run only one instance and avoid concurrent interface renamers.

This is for local rootful Docker bridge and supported macvlan networks, not Docker Desktop, rootless
Docker, Swarm overlay networking, remote Docker daemons, or Kubernetes.
Monitoring/firewall/tc rules tied to an original primary name may need adjustment
if a primary rename succeeds.

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `--socket` | `/var/run/docker.sock` | Local Docker Unix socket |
| `--mode` | `primary` | `primary` or `alternative` |
| `--interval` | `30s` | Full scan interval, at least `1s` |
| `--mapping-file` | disabled | Atomic JSON snapshot; parent directory must exist |
| `--once` | false | One scan, JSON to stdout, nonzero on errors |
| `--dry-run` | false | Plan and validate without modifying interfaces |

### Mapping output

The systemd unit writes `/run/veth-renamer/mappings.json`. Each snapshot has
`updated_at`, `mode`, `dry_run`, and a `mappings` array containing:

- Container ID/name, Docker network ID/name, bridge, IPv4, and IPv6.
- Current primary `interface`, `ifindex`, and `requested_name`.
- `namespace`: `host` for bridge veths, `container` for macvlan interfaces.
  Interface names and indices belong to that namespace; macvlan rows have an
  empty `bridge`. The namespace may be absent when discovery fails or a driver
  is unsupported.
- `status`: `applied`, `unchanged`, `would-change`, `skipped`, or `error`.
- An `error` explanation when applicable.

In alternative mode, `interface` is still Docker's primary name;
`requested_name` is the alternative name. Errors before peer discovery have
an empty interface and index zero. An unavailable container inspection creates
an error row with its ID. A complete scan removes rows for stopped/deleted
containers. Top-level discovery failures preserve the previous file: check
`updated_at` and journald for freshness. The snapshot is world-readable in the
supplied unit and exposes container names and addresses; restrict the runtime
directory if that is inappropriate for your host.

## Validation on your Ubuntu host

Unit tests cover label validation, multi-network naming, Docker API/events,
MAC/peer/bridge matching, collisions, restart races, dry runs, primary/alternative
idempotency, command failure, post-change verification, and atomic JSON output.
They do not prove live kernel/Docker behavior.

Before enabling the service on important workloads:

1. Use a disposable labeled container on a test bridge. Preview with `--once
   --dry-run`; compare the mapping's MAC/peer/bridge against
   `docker inspect` and `ip -j -d link`.
2. Maintain a connection or ping to the container while running `--once`.
   On kernels that reject UP renames, expect a nonzero exit, an `error`
   mapping, the original name, and no deliberate link downtime.
3. Run `--once --mode=alternative`. Check `ip -d link show` for the alternative
   name, test `ip link show dev <alternative-name>`, and verify your actual
   packet capture/monitoring tool accepts it.
4. Run the daemon in alternative mode. Attach/detach a second bridge, restart
   and recreate the container, and verify names/mappings converge. Test both
   network-specific labels and base-derived names.
5. Give two disposable containers the same explicit label. Confirm both are
   reported as conflicts and neither is renamed. Remove the conflict and
   verify the next scan succeeds.
6. Stop/delete the test containers and confirm their mapping rows disappear.
   Restart Docker only on a test host and confirm the event stream reconnects.

No live-host networking or Docker tests are automatically run by `go test`.

## Publishing releases

[.goreleaser.yaml](.goreleaser.yaml) builds Linux amd64/arm64 binaries, standalone
archives, Debian packages, and SHA-256 checksums. The package declares
`iproute2`, `util-linux`, and `systemd` dependencies; Docker must already be set
up separately. Package scripts reload systemd but never automatically start,
enable, or restart the service, including during upgrades.

[The GitHub Actions workflow](.github/workflows/release.yml) runs Go tests/vet,
shell syntax checks and ShellCheck, mocked installer tests, a snapshot package
build, and Debian package structure checks before permitting a tagged release.

To publish:

1. Commit and push this project to `mayberryjp/veth-rename`, with `main` as the
   default branch. The source must be published for the raw installer URL to work.
2. Push a semantic version tag, for example `v0.1.1`. The workflow creates the
   GitHub Release and uploads `.deb` packages, archives, `checksums.txt`, and
   `install.sh`. It uses the workflow's `GITHUB_TOKEN`; no personal token is needed.
3. Confirm the workflow passed and the release contains
   `veth-renamer_0.1.1_amd64.deb` and `veth-renamer_0.1.1_arm64.deb` before
   sharing the install command.

Locally, with GoReleaser v2.18.3, Bash, and Debian package tools available:

```bash
go test ./...
go vet ./...
bash tests/installer_test.sh
goreleaser check
goreleaser release --snapshot --clean
bash tests/package_test.sh
```

Snapshot builds require a Git checkout but do not upload or publish anything.
Installer tests stub all downloads, package installation, privilege escalation,
and service control; they never install packages or change host services.
Live package installation/removal and systemd behavior still need verification
on a disposable Ubuntu host.
