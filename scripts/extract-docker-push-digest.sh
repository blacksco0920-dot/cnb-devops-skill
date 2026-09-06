#!/usr/bin/env bash
set -euo pipefail

digest="$({
  awk '
    $1 == "digest:" && NF >= 2 { print $2; matches += 1; next }
    $2 == "digest:" && NF >= 3 { print $3; matches += 1; next }
    END { if (matches != 1) exit 1 }
  '
})"

digest_hex="${digest#sha256:}"
[[ "$digest" == "sha256:$digest_hex" ]] || exit 1
[[ "${#digest_hex}" -eq 64 ]] || exit 1
[[ ! "$digest_hex" =~ [^0-9a-f] ]] || exit 1

printf '%s\n' "$digest"
