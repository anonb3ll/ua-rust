#!/usr/bin/env bash
# Fail when a tracked file carries team-specific vocabulary or a personal
# identifier (private-network addresses, home directories, mail addresses).
#
# Usage: scripts/vocab-check.sh            (from anywhere inside the repo)
#
# Intended mentions (compatibility aliases, SSRF test addresses) are listed in
# scripts/vocab-allowlist.txt, one per line: a path glob, then optionally
# whitespace and an extended regex the matching line must also match. A path
# alone allows every match in that file.
#
# Only generic shapes live here (home directories, private-network addresses,
# tailnet host names, the legacy role names). Identifiers of any particular
# team or person (agent labels, handles, mail domains, internal tool names)
# belong in VOCAB_DENYLIST: newline-separated extended regexes, matched
# case-insensitively, supplied from a private CI secret. They are never
# printed, and the allowlist does not apply to them. In CI (CI set) without
# VOCAB_DENYLIST, a ::warning:: line says the private list was not applied;
# the exit status is unchanged, so fork PRs (which get no secrets) still pass.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
allowlist=scripts/vocab-allowlist.txt
self=scripts/vocab-check.sh

# Case-sensitive patterns.
sensitive=(
  '/home/[a-z]'
  '/Users/[a-z]'
)
# Case-insensitive patterns.
insensitive=(
  'chief-of-staff'
  '\bsteward\b'
  '\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]+\.[0-9]+'
  '\.ts\.net\b'
)

allow_paths=()
allow_res=()
if [[ -f $allowlist ]]; then
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z ${line//[[:space:]]/} || $line == \#* ]] && continue
    path=${line%%[[:space:]]*}
    re=""
    if [[ $line =~ ^[^[:space:]]+[[:space:]]+(.+)$ ]]; then
      re=${BASH_REMATCH[1]}
    fi
    allow_paths+=("$path")
    allow_res+=("$re")
  done <"$allowlist"
fi

allowed() { # path content
  local i
  for i in "${!allow_paths[@]}"; do
    # shellcheck disable=SC2053 # the allowlist path is a glob
    if [[ $1 == ${allow_paths[$i]} ]]; then
      if [[ -z ${allow_res[$i]} ]] || grep -qE -- "${allow_res[$i]}" <<<"$2"; then
        return 0
      fi
    fi
  done
  return 1
}

# git grep prints path:line:content for each hit in tracked text files.
search() { # case(-i or -I) pattern
  git grep -nIE "$1" -e "$2" -- . ":(exclude)$self" ":(exclude)$allowlist" || true
}

failures=0
report() { # case(-i or -I) pattern
  local hit path rest lineno content
  while IFS= read -r hit; do
    [[ -z $hit ]] && continue
    path=${hit%%:*}
    rest=${hit#*:}
    lineno=${rest%%:*}
    content=${rest#*:}
    if ! allowed "$path" "$content"; then
      printf '%s:%s: matches %s\n' "$path" "$lineno" "$2"
      failures=$((failures + 1))
    fi
  done < <(search "$1" "$2")
}

# -I (skip binary files) stands in for "no extra flag" in the sensitive pass.
for p in "${sensitive[@]}"; do report "-I" "$p"; done
for p in "${insensitive[@]}"; do report "-i" "$p"; done

if [[ -z ${VOCAB_DENYLIST:-} && -n ${CI:-} ]]; then
  # A fork PR gets no secrets, so this must not fail the job; say loudly that
  # only the generic patterns ran.
  echo "::warning title=vocab-check::VOCAB_DENYLIST is empty: the private denylist was NOT applied; only the generic patterns were checked."
fi

if [[ -n ${VOCAB_DENYLIST:-} ]]; then
  while IFS= read -r p || [[ -n $p ]]; do
    [[ -z ${p//[[:space:]]/} ]] && continue
    files=$(git grep -lIiE -e "$p" -- . || true)
    if [[ -n $files ]]; then
      sed 's/$/: matches a VOCAB_DENYLIST pattern/' <<<"$files"
      failures=$((failures + $(wc -l <<<"$files")))
    fi
  done <<<"$VOCAB_DENYLIST"
fi

if ((failures > 0)); then
  echo "vocab-check: $failures match(es). Use neutral names and placeholders (CONTRIBUTING.md, Privacy)," >&2
  echo "or list an intended compatibility mention in $allowlist." >&2
  exit 1
fi
echo "vocab-check: clean"
