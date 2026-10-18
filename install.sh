#!/usr/bin/env bash
set -euo pipefail

repo=mayberryjp/veth-rename
version=latest
start=false

usage() {
    cat <<'EOF'
Usage: bash install.sh [--version vX.Y.Z] [--repo OWNER/REPO] [--start]

Downloads a Debian package from GitHub Releases, verifies its SHA-256 checksum,
and installs it with apt-get. Supports Linux amd64 and arm64.

  --version TAG  Install a specific release (default: latest stable release).
  --repo REPO    GitHub repository (default: mayberryjp/veth-rename).
  --start        Enable and restart the service after installation.
  --help         Show this help.

Without --start, installation neither starts nor restarts the service.
An already-running service continues using its old binary until restarted.
EOF
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

while (($#)); do
    case "$1" in
        --version|--repo)
            (($# >= 2)) && [[ -n "$2" ]] || die "$1 requires a value"
            if [[ "$1" == --version ]]; then version=$2; else repo=$2; fi
            shift 2
            ;;
        --start) start=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

[[ "$repo" =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$ ]] ||
    die "Repository must be OWNER/REPO"
if [[ "$version" != latest ]]; then
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+([.-][A-Za-z0-9]+)*)?$ ]] ||
        die "Version must be a release tag such as v0.1.0 or v0.1.0-rc.1"
fi
[[ "$(uname -s)" == Linux ]] || die "This installer requires a Linux Docker host"
for tool in curl dpkg dpkg-deb sha256sum apt-get systemctl mktemp id; do
    command -v "$tool" >/dev/null || die "Required command is missing: $tool"
done
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64|arm64) ;;
    *) die "Unsupported Debian architecture: $arch (supported: amd64, arm64)" ;;
esac

privilege=()
if [[ "$(id -u)" != 0 ]]; then
    command -v sudo >/dev/null || die "Run as root or install sudo"
    privilege=(sudo)
fi
if [[ -e /etc/systemd/system/veth-renamer.service || -L /etc/systemd/system/veth-renamer.service ]]; then
    die "A local unit exists at /etc/systemd/system/veth-renamer.service and would shadow the packaged unit. Back it up and migrate customizations to veth-renamer.service.d before retrying."
fi

download() {
    curl --fail --silent --show-error --location --retry 3 \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 300 "$@"
}

if [[ "$version" == latest ]]; then
    resolved=$(download --head --output /dev/null --write-out '%{url_effective}' \
        "https://github.com/$repo/releases/latest") ||
        die "Could not resolve the latest release; check that the repository has a published release"
    prefix="https://github.com/$repo/releases/tag/"
    [[ "$resolved" == "$prefix"* ]] || die "Unexpected latest-release URL: $resolved"
    version=${resolved#"$prefix"}
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "Latest release is not a stable vX.Y.Z tag: $version"
fi

asset="veth-renamer_${version#v}_${arch}.deb"
base="https://github.com/$repo/releases/download/$version"
tmp=$(mktemp -d)
cleanup() { rm -f -- "$tmp/$asset" "$tmp/checksums.txt"; rmdir -- "$tmp"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf 'Downloading %s from %s (%s)...\n' "$asset" "$repo" "$version"
download --output "$tmp/$asset" "$base/$asset" || die "Package download failed"
download --output "$tmp/checksums.txt" "$base/checksums.txt" || die "Checksum download failed"

digest=
matches=0
while read -r sum filename remainder; do
    if [[ "$filename" == "$asset" && -z "$remainder" ]]; then
        digest=$sum
        matches=$((matches + 1))
    fi
done < "$tmp/checksums.txt"
[[ "$matches" == 1 && "$digest" =~ ^[A-Fa-f0-9]{64}$ ]] ||
    die "Expected exactly one SHA-256 checksum for $asset"
(
    cd "$tmp"
    printf '%s  %s\n' "$digest" "$asset" | sha256sum --check --status
) || die "Checksum verification failed; nothing was installed"

[[ "$(dpkg-deb --field "$tmp/$asset" Package)" == veth-renamer ]] ||
    die "Downloaded file is not a veth-renamer package"
[[ "$(dpkg-deb --field "$tmp/$asset" Architecture)" == "$arch" ]] ||
    die "Downloaded package architecture does not match $arch"

# Let apt's unprivileged download user read the verified local package.
chmod 0755 "$tmp"
chmod 0644 "$tmp/$asset"
"${privilege[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install --yes "$tmp/$asset"

if "$start"; then
    "${privilege[@]}" systemctl enable veth-renamer.service
    "${privilege[@]}" systemctl restart veth-renamer.service
    "${privilege[@]}" systemctl is-active --quiet veth-renamer.service
    printf 'Installed %s and enabled/restarted veth-renamer.service.\n' "$version"
else
    printf 'Installed %s. The service was not started or restarted.\n' "$version"
    printf 'To enable/start: sudo systemctl enable --now veth-renamer.service\n'
    printf 'If already running, load the new binary: sudo systemctl restart veth-renamer.service\n'
fi
