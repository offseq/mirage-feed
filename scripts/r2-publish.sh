#!/usr/bin/env bash
# Publish a build to R2 as an immutable prefix, then switch readers over with one pointer write.
#   upload OUT  copy every file to builds/<version>/
#   flip OUT    write _meta/published.json, then drop all but the newest KEEP builds
# <version> is the first 16 hex digits of sha256(SHA256SUMS). Needs aws, jq, sha256sum; env BUCKET, R2_ENDPOINT,
# and DAY and GENERATED for flip.
set -euo pipefail
KEEP=3
cmd=$1 out=$2
sums=$(sha256sum "$out/SHA256SUMS" | cut -d' ' -f1)
version=${sums:0:16}
s3() { aws "$@" --endpoint-url "$R2_ENDPOINT"; }

ctype() {
  case "$1" in
    *.csv) echo "text/csv; charset=utf-8" ;;
    *.json) echo "application/json" ;;
    *.gz) echo "application/gzip" ;;
    *.png) echo "image/png" ;;
    *) echo "text/plain; charset=utf-8" ;;
  esac
}
put() { s3 s3 cp "$1" "s3://$BUCKET/$2" --content-type "$(ctype "$2")" --only-show-errors; }

case "$cmd" in
  upload)
    (cd "$out" && find . -type f | sed 's|^\./||' | LC_ALL=C sort) | while read -r key; do
      put "$out/$key" "builds/$version/$key"
    done
    ;;
  flip)
    # The build readers are on until they re-read the pointer is kept too.
    prev=$(s3 s3 cp "s3://$BUCKET/_meta/published.json" - 2> /dev/null | jq -r '.version // empty') || prev=
    meta=$(mktemp)
    jq -n --arg generated "$GENERATED" --arg day "$DAY" --arg sums "$sums" --arg version "$version" \
      '{generated: $generated, day: $day, sha256sums: $sums, version: $version}' > "$meta"
    put "$meta" _meta/published.json
    rm -f "$meta"
    # Newest build first by its latest upload; the current one is always kept.
    s3 s3api list-objects-v2 --bucket "$BUCKET" --prefix builds/ --query 'Contents[].[Key, LastModified]' --output json \
      | jq -r '[.[]? | {v: (.[0] | split("/")[1]), t: .[1]}] | group_by(.v) | map({v: .[0].v, t: (map(.t) | max)})
               | sort_by(.t) | reverse | .[].v' \
      | awk -v keep="$KEEP" -v cur="$version" -v prev="$prev" '++n > keep && $0 != cur && $0 != prev' \
      | while read -r old; do
          if [[ "$old" =~ ^[0-9a-f]{16}$ ]]; then s3 s3 rm "s3://$BUCKET/builds/$old/" --recursive --only-show-errors; fi
        done
    ;;
  *) echo "usage: $0 upload|flip OUT" >&2; exit 2 ;;
esac
