#!/usr/bin/env bash
# Regression test for the allowlist scoping in scripts/vocab-check.sh: an entry
# written for one pattern class must never silence a finding of the other class
# on the same line, and every allowlist form must parse as written (task #2754).
#
# Usage: scripts/vocab-check-selftest.sh
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

note_ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }

case_run() { # name want_exit path line [extra_allowlist_line]
  local name=$1 want=$2 path=$3 line=$4 extra=${5:-} dir code
  dir="$tmp/$name"
  mkdir -p "$dir/$(dirname "$path")" "$dir/scripts"
  cp "$root/scripts/vocab-check.sh" "$root/scripts/vocab-allowlist.txt" "$dir/scripts/"
  [[ -n $extra ]] && printf '%s\n' "$extra" >>"$dir/scripts/vocab-allowlist.txt"
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
    note_ok "$name (exit $code)"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: expected exit %s, got %s\n' "$name" "$want" "$code" >&2
    sed 's/^/     /' "$dir/out.log" >&2
  fi
}

parse_run() { # name allowlist_line expected_parse_line
  local name=$1 line=$2 want=$3 dir got
  dir="$tmp/parse-$name"
  mkdir -p "$dir/scripts"
  cp "$root/scripts/vocab-check.sh" "$dir/scripts/"
  printf '%s\n' "$line" >"$dir/scripts/vocab-allowlist.txt"
  (
    cd "$dir"
    git init -q
    git config user.email selftest@example.com
    git config user.name selftest
    git add -A
    git commit -qm selftest
  )
  got=$(cd "$dir" && bash scripts/vocab-check.sh --parse-allowlist)
  if [[ $got == "$want" ]]; then
    note_ok "parse-$name"
  else
    fail=$((fail + 1))
    printf 'FAIL parse-%s\n     want: %q\n     got:  %q\n' "$name" "$want" "$got" >&2
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

# "<path> <class>" with no line regex: that class in that file, any line. It
# must not decay into an unscoped rule whose regex is the class word.
case_run path-class-silences-own-class 0 \
  crates/ua-tools/tests/private_only.rs \
  "let url = \"$ssrf\";" \
  "crates/ua-tools/tests/private_only.rs private"

case_run path-class-keeps-other-class 1 \
  crates/ua-tools/tests/private_only.rs \
  "// the $role profile" \
  "crates/ua-tools/tests/private_only.rs private"

# Every form parses as written, including one with trailing whitespace.
parse_run regex-only 'docs/a.md `100\.64\.0\.0/10`' \
  $'docs/a.md\t-\t`100\\.64\\.0\\.0/10`'
parse_run classed-regex 'docs/a.md `100\.64\.0\.0/10` private' \
  $'docs/a.md\tprivate\t`100\\.64\\.0\\.0/10`'
parse_run classed-regex-trailing-space 'docs/a.md `100\.64\.0\.0/10` private   ' \
  $'docs/a.md\tprivate\t`100\\.64\\.0\\.0/10`'
parse_run class-only 'docs/a.md private' \
  $'docs/a.md\tprivate\t-'
parse_run path-only 'docs/a.md' \
  $'docs/a.md\t-\t-'

if ((fail > 0)); then
  echo "vocab-check selftest: $fail failed, $pass passed" >&2
  exit 1
fi
echo "vocab-check selftest: $pass passed"
