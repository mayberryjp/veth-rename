#!/usr/bin/env bash
set -euo pipefail

shopt -s nullglob
packages=(dist/*.deb)
[[ ${#packages[@]} == 2 ]] || { echo 'Expected amd64 and arm64 Debian packages' >&2; exit 1; }
seen=' '
for package in "${packages[@]}"; do
    [[ "$(dpkg-deb --field "$package" Package)" == veth-renamer ]]
    arch=$(dpkg-deb --field "$package" Architecture)
    case "$arch" in amd64|arm64) ;; *) echo "Unexpected architecture: $arch" >&2; exit 1 ;; esac
    [[ "$seen" != *" $arch "* ]]
    seen+="$arch "
    depends=$(dpkg-deb --field "$package" Depends)
    for dependency in iproute2 util-linux systemd; do
        [[ "$depends" =~ (^|,)[[:space:]]*$dependency([[:space:],]|$) ]]
    done
    files=$(dpkg-deb --fsys-tarfile "$package" | tar -tf -)
    grep -qx './usr/sbin/veth-renamer' <<< "$files"
    grep -qx './usr/lib/systemd/system/veth-renamer.service' <<< "$files"
    details=$(dpkg-deb --fsys-tarfile "$package" | tar -tvf -)
    grep -Eq '^-rwxr-xr-x .* ./usr/sbin/veth-renamer$' <<< "$details"
    grep -Eq '^-rw-r--r-- .* ./usr/lib/systemd/system/veth-renamer.service$' <<< "$details"
    diff -u deploy/veth-renamer.service \
        <(dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./usr/lib/systemd/system/veth-renamer.service)
    for entry in postinst prerm postrm; do
        case "$entry" in
            postinst) source=packaging/postinstall.sh ;;
            prerm) source=packaging/preremove.sh ;;
            postrm) source=packaging/postremove.sh ;;
        esac
        diff -u "$source" <(dpkg-deb --ctrl-tarfile "$package" | tar -xOf - "./$entry")
    done
    printf 'Validated %s\n' "$package"
done
