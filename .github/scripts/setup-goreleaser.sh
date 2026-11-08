#!/usr/bin/env bash
set -euo pipefail

version=v2.18.3
repo=goreleaser/goreleaser
archive=goreleaser_Linux_x86_64.tar.gz
tool_dir=$(mktemp -d "$RUNNER_TEMP/goreleaser.XXXXXX")
gh api "repos/$repo/releases/tags/$version" > "$tool_dir/release.json"
for name in "$archive" checksums.txt; do
    asset_id=$(jq -er --arg name "$name" --arg version "$version" '
        if .tag_name != $version or .draft != false then
            error("Unexpected release metadata")
        else
            [.assets[] | select(.name == $name)] |
            if length == 1 and (.[0].id | type) == "number" and .[0].id > 0 then
                .[0].id
            else
                error("Expected exactly one valid release asset")
            end
        end
    ' "$tool_dir/release.json")
    gh api "repos/$repo/releases/assets/$asset_id" \
        --header 'Accept: application/octet-stream' > "$tool_dir/$name"
done
cd "$tool_dir"
[[ $(grep -cE "^[[:xdigit:]]{64}  $archive$" checksums.txt) == 1 ]]
grep -E "^[[:xdigit:]]{64}  $archive$" checksums.txt | sha256sum --check --strict
tar -xzf "$archive" goreleaser
rm -f -- "$archive" checksums.txt release.json
printf '%s\n' "$tool_dir" >> "$GITHUB_PATH"
