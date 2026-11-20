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
# VOCAB_DENYLIST adds patterns: newline-separated extended regexes, matched
# case-insensitively (for example from a private CI secret). They are not
# printed, and the allowlist does not apply to them.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
allowlist=scripts/vocab-allowlist.txt
self=scripts/vocab-check.sh

# Case-sensitive patterns.
sensitive=(
  'Desktop_[A-Z]'
  '/home/[a-z]'
  '/Users/[a-z]'
)
# Case-insensitive patterns.
insensitive=(
  'cloud_t3tots'
  'chief-of-staff'
  '\bsteward\b'
  '\bcockpit\b'
  '@gmail\.com'
  '\b100\.[0-9]+\.[0-9]+\.[0-9]+'
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
