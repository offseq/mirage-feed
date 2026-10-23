#!/usr/bin/env bash
# Check a Mirage feed mirror end to end: minisign signature, SHA-256 of every file, freshness and list format.
# Needs curl, minisign and sha256sum (or shasum); nft -c runs when nft and root are available.
# Usage: scripts/check-feed.sh [base URL]
set -euo pipefail
base=${1:-https://feeds.offseq.com/mirage-feed}
base=${base%/}
key=RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA
max_age=$((36 * 3600))
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"

fail() { echo "FAIL $*" >&2; exit 1; }
get() { curl -fsSL --retry 3 --proto =https --create-dirs -o "$1" "$base/$1"; }

get SHA256SUMS
get SHA256SUMS.minisig
minisign -Vqm SHA256SUMS -P "$key" || fail "minisign signature on SHA256SUMS"
while read -r _ path; do
  [[ "$path" =~ ^[A-Za-z0-9._/-]+$ && "$path" != *..* && "$path" != /* ]] || fail "unexpected path $path"
  get "$path"
done < SHA256SUMS
if command -v sha256sum > /dev/null; then sums=(sha256sum); else sums=(shasum -a 256); fi
"${sums[@]}" -c --quiet SHA256SUMS || fail "checksums"

age=$(curl -fsSI --proto =https "$base/feed.json" | tr -d '\r' |
  awk -F': *' 'tolower($1) == "x-mirage-feed-age" { print $2 }')
[[ "$age" =~ ^[0-9]+$ ]] || fail "missing x-mirage-feed-age header"
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
