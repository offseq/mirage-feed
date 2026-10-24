#!/usr/bin/env bash
# Check a Mirage feed mirror end to end: signature, SHA-256 of every file but the /ip lookup shards, freshness and
# list format. Needs curl, minisign and sha256sum or shasum; runs nft -c as root.
# Usage: scripts/check-feed.sh [base URL of any mirror]
set -euo pipefail
base=${1:-https://feeds.offseq.com/mirage-feed} && base=${base%/}
key=RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA
max_age=$((36 * 3600))
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"

fail() { echo "FAIL $*" >&2; exit 1; }
get() { curl -fsSL --retry 3 --proto =https --create-dirs -o "$1" "$base/$1"; }

get SHA256SUMS
get SHA256SUMS.minisig
comment=$(minisign -VQm SHA256SUMS -P "$key") || fail "minisign signature on SHA256SUMS"
# The signed comment carries the build time, so an old signed set replayed by a mirror shows its age.
[[ "$comment" =~ ^mirage-feed\ [0-9]{4}-[0-9]{2}-[0-9]{2}\ generated\ ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)$ ]] ||
  fail "unexpected trusted comment: $comment"
gen=${BASH_REMATCH[1]}
grep -v '  latest/lookup/' SHA256SUMS > sums.main
while read -r _ path; do
  [[ "$path" =~ ^[A-Za-z0-9._/-]+$ && "$path" != *..* && "$path" != /* ]] || fail "unexpected path $path"
  get "$path"
done < sums.main
if command -v sha256sum > /dev/null; then sums=(sha256sum); else sums=(shasum -a 256); fi
"${sums[@]}" -c --quiet sums.main || fail "checksums"

grep -q "^  \"generated\": \"$gen\",\$" feed.json || fail "feed.json is not the build the signature names"
ts=$(date -u -d "$gen" +%s 2> /dev/null || date -u -j -f %Y-%m-%dT%H:%M:%SZ "$gen" +%s)
age=$(($(date +%s) - ts))
((age < max_age)) || fail "feed is $((age / 3600)) h old"

for f in latest/ipv4-*.txt latest/ipv6-7d.txt latest/anonymizers-7d.txt; do
  [[ -f $f && $f != *cidr32* ]] || continue
  awk -v f="$f" '
    function bad(why) { printf "%s:%d: %s: %s\n", f, NR, why, $0; err = 1 }
    /:/ {
      if ($0 !~ /^[0-9a-f:]+\/64$/) bad("not an IPv6 /64")
      else if ($0 ~ /^(f[c-f]|2001:db8:|::)/) bad("private or reserved")
      next
    }
    $0 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { bad("not one IPv4 address"); next }
    {
      split($0, o, "."); a = o[1] + 0; b = o[2] + 0
      if (a > 255 || b > 255 || o[3] + 0 > 255 || o[4] + 0 > 255) bad("not an IPv4 address")
      else if (a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && b >= 64 && b < 128) ||
               (a == 169 && b == 254) || (a == 172 && b >= 16 && b < 32) || (a == 192 && b == 168)) bad("private or reserved")
    }
    END { exit err }' "$f" || fail "format of $f"
done

if command -v nft > /dev/null; then
  if [ "$(id -u)" = 0 ]; then nft -c -f latest/nft/mirage.nft
  elif sudo -n true 2> /dev/null; then sudo -n nft -c -f latest/nft/mirage.nft
  else echo "skipping nft -c: needs root"; fi || fail "nft -c rejects latest/nft/mirage.nft"
fi
echo "ok: $base ($(wc -l < SHA256SUMS | tr -d ' ') files, $((age / 3600)) h old)"
