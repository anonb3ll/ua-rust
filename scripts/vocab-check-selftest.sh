#!/usr/bin/env bash
# Regression test for the allowlist scoping in scripts/vocab-check.sh: an entry
# written for one pattern class must never silence a finding of the other class
# on the same line (task #2754).
#
# Usage: scripts/vocab-check-selftest.sh
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

case_run() { # name want_exit path line
  local name=$1 want=$2 path=$3 line=$4 dir code
  dir="$tmp/$name"
  mkdir -p "$dir/$(dirname "$path")" "$dir/scripts"
  cp "$root/scripts/vocab-check.sh" "$root/scripts/vocab-allowlist.txt" "$dir/scripts/"
  printf '%s\n' "$line" >"$dir/$path"
  (
    cd "$dir"
    git init -q
    git config user.email selftest@example.com
    git config user.name selftest
    git add -A
    git commit -qm selftest
  )
  set +e
  (cd "$dir" && bash scripts/vocab-check.sh >out.log 2>&1)
  code=$?
  set -e
  if [[ $code -eq $want ]]; then
    pass=$((pass + 1))
    printf 'ok   %s (exit %s)\n' "$name" "$code"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: expected exit %s, got %s\n' "$name" "$want" "$code" >&2
    sed 's/^/     /' "$dir/out.log" >&2
  fi
}

# Fixtures are assembled at run time. Written out in full they would be the very
# literals the checker looks for, so this file would fail its own gate.
role="ste""ward"
host="100.""64.1.5"
ssrf="http://100.""64.0.1/"

# A private address on a line that also carries allowlisted role vocabulary in
# an allowlisted path is still reported. This is the bug: the role rule used to
# grant the whole line immunity, so the address shipped in a public export.
case_run role-line-does-not-hide-address 1 \
  crates/ua-tools/tests/policy.rs \
  "// the $role note lives at $host"

# The plain case, unchanged: an address with no allowlist coverage is reported.
case_run bare-address 1 \
  crates/ua-tools/tests/policy.rs \
  "// unrelated host $host"

# The intended exception still passes.
case_run allowed-role-vocabulary 0 \
  crates/ua-tools/tests/policy.rs \
  "// compatible with the $role profile name"

# An intended SSRF fixture address still passes.
case_run allowed-private-fixture 0 \
  crates/ua-tools/tests/web.rs \
  "let url = \"$ssrf\";"

# The inverse direction: a private-shape entry must not silence role vocabulary.
case_run private-entry-does-not-hide-role 1 \
  crates/ua-tools/tests/web.rs \
  "let url = \"$ssrf\"; // the $role profile"

if ((fail > 0)); then
  echo "vocab-check selftest: $fail failed, $pass passed" >&2
  exit 1
fi
echo "vocab-check selftest: $pass passed"
