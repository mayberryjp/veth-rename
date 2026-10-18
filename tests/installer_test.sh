#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
tools=(uname dpkg dpkg-deb id curl sudo apt-get systemctl mktemp)
cleanup() {
    local tool
    for tool in "${tools[@]}"; do rm -f -- "$tmp/bin/$tool"; done
    rm -f -- "$tmp/stub" "$tmp/package" "$tmp/log" "$tmp/output"
    # Failed installers must clean their downloads too.
    if [[ -d "$tmp/download" ]]; then
        rm -f -- "$tmp/download/veth-renamer_1.2.3_amd64.deb" \
            "$tmp/download/veth-renamer_1.2.3_arm64.deb" "$tmp/download/checksums.txt"
        rmdir -- "$tmp/download"
    fi
    rmdir -- "$tmp/bin" "$tmp"
}
trap cleanup EXIT
mkdir "$tmp/bin"
printf 'test Debian package bytes\n' > "$tmp/package"
sum=$(sha256sum "$tmp/package")
export TEST_SUM=${sum%% *}
export TEST_ROOT=$tmp TEST_SCENARIO=ok TEST_ARCH=amd64 TEST_OS=Linux TEST_UID=0

cat > "$tmp/stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
tool=${0##*/}
case "$tool" in
    uname) printf '%s\n' "$TEST_OS" ;;
    dpkg) printf '%s\n' "$TEST_ARCH" ;;
    id) printf '%s\n' "$TEST_UID" ;;
    dpkg-deb)
        case "$3" in
            Package)
                if [[ "$TEST_SCENARIO" == wrong-package ]]; then
                    echo unrelated-package
                else
                    echo veth-renamer
                fi
                ;;
            Architecture)
                if [[ "$TEST_SCENARIO" == wrong-arch ]]; then echo i386; else echo "$TEST_ARCH"; fi
                ;;
            *) exit 99 ;;
        esac
        ;;
    mktemp)
        mkdir "$TEST_ROOT/download"
        printf '%s\n' "$TEST_ROOT/download"
        ;;
    curl)
        out= url=
        while (($#)); do
            case "$1" in
                --output) out=$2; shift 2 ;;
                --write-out|--retry|--proto|--proto-redir|--connect-timeout|--max-time) shift 2 ;;
                --head|--fail|--silent|--show-error|--location|--tlsv1.2) shift ;;
                https://*) url=$1; shift ;;
                *) exit 98 ;;
            esac
        done
        printf 'curl %s\n' "$url" >> "$TEST_ROOT/log"
        case "$url" in
            */releases/latest)
                if [[ "$TEST_SCENARIO" == bad-redirect ]]; then
                    echo https://example.invalid/releases/tag/v1.2.3
                elif [[ "$TEST_SCENARIO" == no-release ]]; then
                    exit 22
                else
                    printf '%s/releases/tag/v1.2.3' "${url%/releases/latest}"
                fi
                ;;
            */checksums.txt)
                [[ "$TEST_SCENARIO" != no-checksums ]] || exit 22
                asset="veth-renamer_1.2.3_${TEST_ARCH}.deb"
                digest=$TEST_SUM
                case "$TEST_SCENARIO" in
                    missing-checksum) asset=another.deb ;;
                    malformed-checksum) digest=not-a-sha256 ;;
                    bad-checksum) digest=$(printf '%064d' 0) ;;
                esac
                printf '%s  %s\n' "$digest" "$asset" > "$out"
                if [[ "$TEST_SCENARIO" == duplicate-checksum ]]; then
                    printf '%s  %s\n' "$digest" "$asset" >> "$out"
                fi
                ;;
            *.deb)
                [[ "$TEST_SCENARIO" != no-package ]] || exit 22
                cp "$TEST_ROOT/package" "$out"
                ;;
            *) exit 97 ;;
        esac
        ;;
    sudo)
        printf 'sudo %s\n' "$*" >> "$TEST_ROOT/log"
        "$@"
        ;;
    apt-get)
        printf 'apt-get %s\n' "$*" >> "$TEST_ROOT/log"
        [[ "$TEST_SCENARIO" != apt-failure ]] || exit 42
        ;;
    systemctl)
        printf 'systemctl %s\n' "$*" >> "$TEST_ROOT/log"
        [[ "$TEST_SCENARIO" != start-failure || "$1" != restart ]] || exit 43
        [[ "$TEST_SCENARIO" != inactive || "$1" != is-active ]] || exit 3
        ;;
    *) exit 96 ;;
esac
EOF
chmod +x "$tmp/stub"
for tool in "${tools[@]}"; do cp "$tmp/stub" "$tmp/bin/$tool"; done
export PATH="$tmp/bin:$PATH"

fail() { printf 'FAIL: %s\n' "$*" >&2; cat "$tmp/output" >&2; exit 1; }
assert_log() { grep -Fq -- "$1" "$tmp/log" || fail "Missing log: $1"; }
assert_no_log() { if grep -Fq -- "$1" "$tmp/log"; then fail "Unexpected log: $1"; fi; }
run_ok() {
    : > "$tmp/log"
    bash "$root/install.sh" "$@" > "$tmp/output" 2>&1 || fail "Expected success: $*"
    [[ ! -d "$tmp/download" ]] || fail "Download directory was not cleaned"
}
run_bad() {
    : > "$tmp/log"
    if bash "$root/install.sh" "$@" > "$tmp/output" 2>&1; then fail "Expected failure: $*"; fi
    [[ ! -d "$tmp/download" ]] || fail "Download directory was not cleaned"
}

run_ok --help
assert_no_log curl
run_ok --version v1.2.3
assert_log '/releases/download/v1.2.3/veth-renamer_1.2.3_amd64.deb'
assert_log 'apt-get install --yes'
assert_no_log systemctl
assert_no_log '/releases/latest'
run_ok
assert_log '/releases/latest'
assert_log '/releases/download/v1.2.3/'
run_ok --version v1.2.3 --start
assert_log 'systemctl enable veth-renamer.service'
assert_log 'systemctl restart veth-renamer.service'
assert_log 'systemctl is-active --quiet veth-renamer.service'
run_ok --version v1.2.3 --repo another/project
assert_log 'https://github.com/another/project/releases/download/'
TEST_ARCH=arm64 run_ok --version v1.2.3
assert_log 'veth-renamer_1.2.3_arm64.deb'
TEST_UID=1000 run_ok --version v1.2.3 --start
assert_log 'sudo env DEBIAN_FRONTEND=noninteractive apt-get'
assert_log 'sudo systemctl restart'

for scenario in bad-checksum missing-checksum duplicate-checksum malformed-checksum \
    no-package no-checksums wrong-package wrong-arch bad-redirect no-release; do
    TEST_SCENARIO=$scenario run_bad
    assert_no_log apt-get
    assert_no_log systemctl
    assert_no_log sudo
done
TEST_SCENARIO=apt-failure run_bad --version v1.2.3 --start
assert_log apt-get
assert_no_log systemctl
TEST_SCENARIO=start-failure run_bad --version v1.2.3 --start
assert_log 'systemctl restart'
assert_no_log 'systemctl is-active'
TEST_SCENARIO=inactive run_bad --version v1.2.3 --start
assert_log 'systemctl is-active'

for args in --unknown --version --repo; do
    run_bad "$args"
    assert_no_log curl
done
run_bad --version v1/evil
assert_no_log curl
run_bad --repo 'owner/repo/extra'
assert_no_log curl
TEST_OS=Darwin run_bad --version v1.2.3
assert_no_log curl
TEST_ARCH=i386 run_bad --version v1.2.3
assert_no_log curl
printf 'Installer tests passed (downloads, checksums, architectures, privilege, startup, and failures).\n'
