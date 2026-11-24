#!/usr/bin/env bash
set -euo pipefail

shopt -s nullglob
packages=(dist/*.deb)
[[ ${#packages[@]} == 2 ]] || { echo 'Expected amd64 and arm64 Debian packages' >&2; exit 1; }
seen=' '
for package in "${packages[@]}"; do
    [[ "$(dpkg-deb --field "$package" Package)" == veth-manager ]]
    arch=$(dpkg-deb --field "$package" Architecture)
    case "$arch" in amd64|arm64) ;; *) echo "Unexpected architecture: $arch" >&2; exit 1 ;; esac
    [[ "$seen" != *" $arch "* ]]
    seen+="$arch "
    depends=$(dpkg-deb --field "$package" Depends)
    for dependency in iproute2 util-linux systemd logrotate; do
        [[ "$depends" =~ (^|,)[[:space:]]*$dependency([[:space:],]|$) ]]
    done
    conflicts=$(dpkg-deb --field "$package" Conflicts)
    for old_package in veth-renamer veth-rename; do
        [[ "$conflicts" =~ (^|,)[[:space:]]*$old_package([[:space:],]|$) ]]
    done
    files=$(dpkg-deb --fsys-tarfile "$package" | tar -tf -)
    grep -qx './usr/sbin/veth-manager' <<< "$files"
    grep -qx './usr/lib/systemd/system/veth-manager.service' <<< "$files"
    grep -qx './etc/logrotate.d/veth-manager' <<< "$files"
    diff -u deploy/veth-manager.logrotate \
        <(dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./etc/logrotate.d/veth-manager)
    grep -qx '/etc/logrotate.d/veth-manager' \
        <(dpkg-deb --ctrl-tarfile "$package" | tar -xOf - ./conffiles)
    for example in ipfix.example.yaml ipfix.conf firewall.example.yaml manual.example.yaml sando.example.yaml firewall.conf; do
        grep -qx "./usr/share/doc/veth-manager/$example" <<< "$files"
        diff -u "deploy/$example" \
            <(dpkg-deb --fsys-tarfile "$package" | tar -xOf - "./usr/share/doc/veth-manager/$example")
    done
    details=$(dpkg-deb --fsys-tarfile "$package" | tar -tvf -)
    grep -Eq '^-rwxr-xr-x .* ./usr/sbin/veth-manager$' <<< "$details"
    grep -Eq '^-rw-r--r-- .* ./usr/lib/systemd/system/veth-manager.service$' <<< "$details"
    diff -u deploy/veth-manager.service \
        <(dpkg-deb --fsys-tarfile "$package" | tar -xOf - ./usr/lib/systemd/system/veth-manager.service)
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
