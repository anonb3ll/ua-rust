#!/usr/bin/env bash
# Run CI for one exact commit on Google Cloud Build and post GitHub commit
# statuses for it.
#
#   scripts/cloud-ci.sh [--allow-fork] [--default-sa] <pr-number | branch | sha>
#   scripts/cloud-ci.sh --reconcile <build-id> <pr-number | branch | sha>
#
# The build runs as UA_CI_SERVICE_ACCOUNT (an email or full resource name);
# without it the run refuses unless --default-sa accepts the project's default
# build account. A pull request from a fork is refused unless --allow-fork: the
# head's own code runs with the build's credentials. A sha is run as given;
# only pass one you have reviewed.
#
# A fresh run uploads a one-commit checkout of the resolved head (nothing else
# from this machine), submits deploy/cloudbuild/ci.yaml from THIS checkout with
# _SOURCE_SHA set to that head, and waits for the build. Every step re-checks
# that it is testing that SHA. The statuses it posts, pending and then success
# or failure, each name the build and link to its log:
#   CI / vocab, CI / check, CI / full-verification
# They are posted from this machine with the operator's `gh` login; no GitHub
# credential enters the build.
#
# --reconcile re-attaches to a build an earlier run submitted, for example
# after the watcher was interrupted, and submits nothing. It refuses unless the
# build's _SOURCE_SHA is the resolved head, waits while the build is
# unfinished, then posts the final statuses from that build's step results.
#
# Statuses are last-write-wins per context, so an older build must never
# overwrite a newer run's result. Which run is newer is decided by build
# createTime, never by status order. A fresh run notes the newest status id on
# the head before submitting; before its first write and again before its final
# writes it refuses when any later status on its contexts comes from a run it
# cannot prove older (a status naming no build, or a build whose createTime
# cannot be read). --reconcile applies that test to the whole history.
#
# Env: UA_CI_GCP_PROJECT is required (no default project is ever assumed).
# UA_CI_GCP_REGION defaults to us-central1; UA_CI_REPO defaults to the current
# GitHub repository. UA_CI_NO_STATUS=1 posts nothing (the build still runs and
# is billed). Needs git, gh, gcloud and GNU coreutils `timeout`.
set -euo pipefail
# ASCII matching for build ids and context names, whatever the caller's locale.
export LC_ALL=C
# A prompt would block the watcher with statuses left pending.
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

# Bash reads a script file lazily. Capture the whole program before anything
# is billed, so editing or checking out this file during polling cannot change
# what runs. BASH_SOURCE is empty inside the -c invocation.
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    program="$(cat -- "${BASH_SOURCE[0]}")"
    exec "$BASH" -c "$program" "$0" "$@"
fi

usage="usage: scripts/cloud-ci.sh [--allow-fork] [--default-sa] [--reconcile <build-id>] <pr-number|branch|sha>"
attach=""
allow_fork=0
default_sa=0
while [ $# -gt 0 ]; do
    case "$1" in
        --reconcile)
            attach="${2:-}"
            # Cloud Build ids are UUIDs; the id is also matched inside status text.
            if ! [[ "$attach" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]]; then
                echo "$usage" >&2
                exit 2
            fi
            shift 2
            ;;
        --allow-fork) allow_fork=1; shift ;;
        --default-sa) default_sa=1; shift ;;
        -*) echo "$usage" >&2; exit 2 ;;
        *) break ;;
    esac
done
ref="${1:?$usage}"
project="${UA_CI_GCP_PROJECT:?set UA_CI_GCP_PROJECT to the intended GCP project}"
region="${UA_CI_GCP_REGION:-us-central1}"
repo="${UA_CI_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
root="$(git rev-parse --show-toplevel)"
config="$root/deploy/cloudbuild/ci.yaml"
dry_run="${UA_CI_NO_STATUS:-0}"

# The build's identity. The head's own code runs in the build and can use
# whatever this account can reach, so a fresh run needs a least-privilege
# account (CONTRIBUTING.md, Cloud Build CI) unless the operator explicitly
# accepts the project's default build account.
sa=""
if [ -z "$attach" ]; then
    sa="${UA_CI_SERVICE_ACCOUNT:-}"
    if [ -n "$sa" ]; then
        [[ "$sa" == projects/* ]] || sa="projects/$project/serviceAccounts/$sa"
        if ! [[ "$sa" =~ ^projects/[a-z0-9.:-]+/serviceAccounts/[A-Za-z0-9._@-]+$ ]]; then
            echo "UA_CI_SERVICE_ACCOUNT is not a service account email or resource name." >&2
            exit 2
        fi
    elif [ "$default_sa" = "1" ]; then
        echo "WARNING: --default-sa: the build runs as $project's default Cloud Build service" \
            "account, with all of its permissions, and the commit's own code can use them." >&2
    else
        echo "Set UA_CI_SERVICE_ACCOUNT to the CI's least-privilege service account, or pass" \
            "--default-sa to accept the project's default build account. Nothing was submitted." >&2
        exit 2
    fi
fi

# Each context and the build step that settles it. full-verification also
# requires the whole build to have succeeded.
contexts=("CI / vocab" "CI / check" "CI / full-verification")
steps=(vocab check full-verification)

# Every external call during recovery has a deadline.
bounded() { timeout -k 5 30 "$@"; }
describe() { # build-id format [gcloud flag...]
    bounded gcloud builds describe "$1" --project="$project" --region="$region" --format="$2" \
        "${@:3}" </dev/null
}

git -C "$root" fetch -q origin
if [[ "$ref" =~ ^[0-9]+$ ]]; then
    read -r sha cross < <(gh pr view "$ref" -R "$repo" --json headRefOid,isCrossRepository \
        -q '.headRefOid + " " + (.isCrossRepository | tostring)') || true
    # A fork's head is code nobody with push access wrote; running it with the
    # build's credentials needs an explicit decision. A --reconcile runs no code.
    if [ -z "$attach" ] && [ "${cross:-}" != "false" ] && [ "$allow_fork" != "1" ]; then
        if [ "${cross:-}" = "true" ]; then
            echo "Refusing: PR #$ref comes from a fork. Review its head, then pass --allow-fork" \
                "to run it. Nothing was submitted." >&2
        else
            echo "Could not tell whether PR #$ref comes from a fork; nothing was submitted." >&2
        fi
        exit 1
    fi
    git -C "$root" fetch -q origin "pull/$ref/head"
elif git -C "$root" rev-parse -q --verify "origin/$ref^{commit}" >/dev/null; then
    sha="$(git -C "$root" rev-parse "origin/$ref^{commit}")"
else
    sha="$(git -C "$root" rev-parse --verify "$ref^{commit}")"
fi
if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || ! git -C "$root" cat-file -e "$sha^{commit}"; then
    echo "Could not resolve '$ref' to a commit; nothing was submitted." >&2
    exit 1
fi
short="${sha:0:8}"

build_id=""
url=""
src=""
finalized=0
errored=0
build_url() { url="https://console.cloud.google.com/cloud-build/builds;region=$region/$build_id?project=$project"; }

post() { # context state description
    if [ "$dry_run" = "1" ]; then
        echo "  [dry-run] $1: $2"
        return 0
    fi
    local _
    for _ in 1 2; do
        if bounded gh api -X POST "repos/$repo/statuses/$sha" -f state="$2" -f context="$1" \
            -f description="$3" -f target_url="$url" >/dev/null; then
            return 0
        fi
    done
    echo "Could not post $1=$2 for $sha." >&2
    return 1
}

# A status names a build when its description starts `cloud-build <id>:` or
# `cloud-build <id> `. Contexts compare as on GitHub: without case or
# surrounding whitespace.
names_build() {
    case "$1" in
        "cloud-build $build_id "* | "cloud-build $build_id:"*) return 0 ;;
    esac
    return 1
}
context_key() { # context; sets key
    key="${1,,}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
}
ours=()
for c in "${contexts[@]}"; do
    context_key "$c"
    ours+=("$key")
done

# Sets max_id (newest status id on the head) and foreign: the descriptions of
# other runs' statuses on this run's contexts, newer than baseline_id for a
# fresh run, the whole history for a --reconcile.
baseline_id=0
max_id=0
foreign=()
read_statuses() {
    local listed id ctx desc k
    listed="$(bounded gh api --paginate "repos/$repo/commits/$sha/statuses?per_page=100" \
        --jq '.[] | [.id, .context, (.description // "")] | @tsv')" || return 1
    max_id=0
    foreign=()
    while IFS=$'\t' read -r id ctx desc; do
        [[ "$id" =~ ^[0-9]+$ ]] || continue
        if ((id > max_id)); then max_id="$id"; fi
        context_key "$ctx"
        for k in "${ours[@]}"; do
            [ "$key" = "$k" ] || continue
            if ! names_build "$desc" && { [ -n "$attach" ] || ((id > baseline_id)); }; then
                # A leading `|` keeps an empty description as an entry.
                foreign+=("|$desc")
            fi
        done
    done <<<"$listed"
}

# Build createTime as fixed-width UTC text, so text order is time order.
declare -A created=()
build_created() { # build-id; sets ctime
    if [ -z "${created[$1]+x}" ]; then
        local t re='^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.([0-9]{1,9}))?Z$'
        t="$(describe "$1" 'value(createTime)')" || return 1
        [[ "$t" =~ $re ]] || return 1
        local frac="${BASH_REMATCH[3]}000000000"
        created[$1]="${BASH_REMATCH[1]}.${frac:0:9}"
    fi
    ctime="${created[$1]}"
}
older_than_ours() { # description; true only for a build provably created before ours
    local re='^cloud-build ([A-Za-z0-9][A-Za-z0-9-]*)[ :]' theirs
    [[ "$1" =~ $re ]] || return 1
    build_created "${BASH_REMATCH[1]}" || return 1
    theirs="$ctime"
    build_created "$build_id" || return 1
    [[ "$theirs" < "$ctime" ]]
}
superseded() {
    local d
    for d in "${foreign[@]}"; do
        d="${d#|}"
        older_than_ours "$d" && continue
        echo "Refusing: $sha holds a status from another run that is not older than" \
            "build $build_id (\"$d\"). No result was posted." >&2
        return 0
    done
    return 1
}
# True when this run must not settle its contexts now: a newer run wrote one,
# or the statuses cannot be read to tell. A fresh dry run posts nothing.
must_not_settle() {
    [ -n "$attach" ] || [ "$dry_run" != "1" ] || return 1
    if ! read_statuses; then
        echo "Could not re-read the statuses on $sha; nothing was posted." >&2
        errored=1
        return 0
    fi
    superseded
}

error_contexts() {
    local c
    errored=1
    for c in "${contexts[@]}"; do
        post "$c" error "cloud-build $build_id: watcher interrupted; rerun with --reconcile" || true
    done
}

# Post the final statuses from a finished build's own step results. A step
# that is missing or did not succeed reads as a failure.
reconcile() {
    local status listing id st i ok=1 all_ok=1
    declare -A step_state=()
    if ! status="$(describe "$build_id" 'value(status)')" \
        || ! listing="$(describe "$build_id" 'value(steps.id,steps.status)' --flatten=steps)"; then
        error_contexts
        return 1
    fi
    case "$status" in
        SUCCESS | FAILURE | INTERNAL_ERROR | TIMEOUT | CANCELLED | EXPIRED) ;;
        *)
            error_contexts
            return 1
            ;;
    esac
    while IFS=$'\t' read -r id st; do
        [ -n "$id" ] && step_state["$id"]="${st:-MISSING}"
    done <<<"$listing"
    for i in "${!contexts[@]}"; do
        local c="${contexts[$i]}" s="${steps[$i]}"
        st="${step_state[$s]:-MISSING}"
        if [ "$s" = "full-verification" ]; then
            if [ "$all_ok" = "1" ] && [ "$st" = "SUCCESS" ] && [ "$status" = "SUCCESS" ]; then
                post "$c" success "cloud-build $build_id: all checks passed" || ok=0
            else
                st="$status"
                [ "$st" != "SUCCESS" ] || st=FAILURE
                post "$c" failure "cloud-build $build_id: $st" || true
                ok=0
            fi
        elif [ "$st" = "SUCCESS" ]; then
            post "$c" success "cloud-build $build_id: $s passed" || ok=0
        else
            all_ok=0
            ok=0
            post "$c" failure "cloud-build $build_id: $s $st" || true
        fi
        printf '  %-24s %s\n' "$c" "$st"
    done
    [ "$ok" = "1" ]
}

finish() {
    local result=$?
    trap - EXIT
    trap '' INT TERM HUP
    if [ -n "$build_id" ] && [ "$finalized" = "0" ]; then
        build_url
        if must_not_settle; then
            echo "Leaving the statuses on $sha unchanged." >&2
        else
            echo "Watcher exited; reconciling build $build_id (no resubmission)." >&2
            reconcile || true
        fi
        [ "$result" != "0" ] || result=1
    fi
    if [ "$errored" = "1" ]; then
        # Re-attach to the same build later instead of billing another one.
        echo "Statuses for $short are not final. Once build $build_id finishes, re-attach with:" >&2
        printf '  UA_CI_GCP_PROJECT=%q UA_CI_GCP_REGION=%q UA_CI_REPO=%q scripts/cloud-ci.sh --reconcile %q %q\n' \
            "$project" "$region" "$repo" "$build_id" "$sha" >&2
    fi
    [ -z "$src" ] || rm -rf -- "$src"
    exit "$result"
}

if [ -n "$attach" ]; then
    build_id="$attach"
    if ! built="$(describe "$build_id" 'value(substitutions._SOURCE_SHA)')"; then
        echo "Could not read build $build_id in $project/$region; nothing was posted." >&2
        exit 1
    fi
    if [ "$built" != "$sha" ]; then
        echo "Refusing: build $build_id tested _SOURCE_SHA=${built:-<none>}, not $sha. Nothing was posted." >&2
        exit 1
    fi
    if ! read_statuses; then
        echo "Could not list the statuses on $sha; nothing was posted." >&2
        exit 1
    fi
    superseded && exit 1
    trap finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    build_url
    echo "re-attaching to build $build_id for $short; nothing is submitted"
    echo "$url"
else
    for f in "$config" "$root/deploy/cloudbuild/ci-step.sh" "$root/scripts/vocab-check.sh"; do
        if [ ! -f "$f" ]; then
            echo "This checkout has no ${f#"$root/"}; nothing was submitted." >&2
            exit 1
        fi
    done
    # The vocab step runs THIS checkout's checker against the head's allowlist.
    # An allowlist entry may declare a pattern class (a trailing `vocab` or
    # `private`), which a checker that predates classes would read as part of
    # the regex: every intended exception would fail with bogus matches. Refuse
    # with the fix instead of submitting a run that cannot pass.
    head_allowlist=$(git -C "$root" show "$sha:scripts/vocab-allowlist.txt" 2>/dev/null || true)
    if [ -n "$head_allowlist" ] &&
        grep -qE '[[:space:]](vocab|private)[[:space:]]*$' <<<"$head_allowlist" &&
        ! grep -q 'insensitive_class' "$root/scripts/vocab-check.sh"; then
        echo "$short declares allowlist pattern classes, but this checkout's" >&2
        echo "scripts/vocab-check.sh predates them. Update the checkout (git pull)" >&2
        echo "and re-run; nothing was submitted." >&2
        exit 1
    fi
    # The newest status id before submitting; anything later from another
    # build is a newer run. This also fails, before billing, for a commit
    # GitHub does not have.
    if [ "$dry_run" != "1" ]; then
        if ! read_statuses; then
            echo "Could not list the statuses on $sha in $repo; nothing was submitted." >&2
            exit 1
        fi
        baseline_id="$max_id"
    fi
    trap finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    src="$(mktemp -d)"
    # A one-commit shallow checkout keeps the exact source identity (and
    # `git grep` for the vocab check) without uploading local branches,
    # credentials or history.
    git init -q --template= "$src/repo"
    git -C "$src/repo" fetch -q --depth=1 "$root" "$sha"
    git -C "$src/repo" -c core.logAllRefUpdates=false checkout -q --detach "$sha"
    # FETCH_HEAD names a local path; the build does not need it.
    rm -f -- "$src/repo/.git/FETCH_HEAD"
    # gcloud's generated ignore file would drop .git; this one ignores nothing.
    printf '# Upload the exact checkout, including its Git metadata.\n' >"$src/.gcloudignore"
    # The step script and the vocab check come from THIS checkout, not the
    # commit under test: the private denylist is only ever handed to code the
    # operator runs, never to the head's own scripts.
    cp -- "$root/deploy/cloudbuild/ci-step.sh" "$src/ci-step.sh"
    cp -- "$root/scripts/vocab-check.sh" "$src/vocab-check.sh"
    echo "cloud CI for $short in $project ($region) as ${sa:-the default build account}"
    build_id="$(gcloud builds submit "$src" --project="$project" --region="$region" \
        --config="$config" --substitutions="_SOURCE_SHA=$sha,_CI_SA=$sa" --async --format='value(id)')"
    if ! [[ "$build_id" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]]; then
        echo "gcloud returned no usable build id ('$build_id')." >&2
        build_id=""
        exit 1
    fi
    build_url
    echo "build $build_id"
    echo "$url"
    # Pending over a newer run's result would hide it, so check before the
    # first write too. The build keeps running either way.
    if [ "$dry_run" != "1" ]; then
        if ! read_statuses; then
            echo "Could not list the statuses on $sha before the first write; nothing was posted." >&2
            errored=1
            finalized=1
            exit 1
        fi
        if superseded; then
            finalized=1
            exit 1
        fi
    fi
    for c in "${contexts[@]}"; do post "$c" pending "cloud-build $build_id running" || true; done
fi

# The run deadline starts once the build leaves the queue and outlasts
# ci.yaml's `timeout`; the queue has its own bound (its `queueTtl`). A failed
# or slow describe is retried until the deadline, not treated as the end.
queue_allow=7800
run_allow=3900
[[ "${UA_CI_QUEUE_DEADLINE_S:-}" =~ ^[0-9]+$ ]] && queue_allow=$UA_CI_QUEUE_DEADLINE_S
[[ "${UA_CI_RUN_DEADLINE_S:-}" =~ ^[0-9]+$ ]] && run_allow=$UA_CI_RUN_DEADLINE_S
queue_deadline=$((SECONDS + queue_allow))
run_deadline=""
while :; do
    status="$(describe "$build_id" 'value(status)')" || status=""
    case "$status" in
        SUCCESS | FAILURE | INTERNAL_ERROR | TIMEOUT | CANCELLED | EXPIRED) break ;;
        WORKING)
            [ -n "$run_deadline" ] || run_deadline=$((SECONDS + run_allow))
            limit=$run_deadline
            ;;
        *) limit=${run_deadline:-$queue_deadline} ;;
    esac
    if ((SECONDS >= limit)); then
        echo "Timed out waiting for build $build_id (${status:-unreadable}); inspect it before retrying." >&2
        exit 1
    fi
    sleep 30
done
echo "build status: $status"

# A newer run may have started on this head while this build ran. GitHub
# statuses have no compare-and-set, so a newer run can still post in the few
# seconds between this check and the writes below; its own final statuses,
# posted after its build, then win.
if must_not_settle; then
    finalized=1
    exit 1
fi
if reconcile; then
    finalized=1
else
    finalized=1
    exit 1
fi
