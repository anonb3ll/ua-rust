#!/usr/bin/env bash
# One step of the Cloud Build CI (deploy/cloudbuild/ci.yaml).
#
#   ci-step.sh check | vocab
#
# scripts/cloud-ci.sh uploads a one-commit checkout of the commit under test
# at /workspace/repo and this script beside it. Scratch lives in /workspace/.ci,
# outside the tree the checks read. Each step mirrors the job of the same name
# in .github/workflows/ci.yml.
set -euo pipefail

NEXTEST_VERSION=0.9.152
NEXTEST_SHA256=d039b43c3e0958441b6ad0a39c8884d018b3d2e8fb9928f209074b1100b5e17a
DENYLIST_SECRET=ua-rust-vocab-denylist
CI_UID=1000
ci=/workspace/.ci

verify_head() {
    local head
    head="$(git rev-parse HEAD)"
    if [ "$head" != "${UA_CI_SOURCE_SHA:?exact source SHA required}" ]; then
        echo "checkout is at $head, not the requested $UA_CI_SOURCE_SHA" >&2
        exit 1
    fi
    echo "testing $head"
}

step="${1:?usage: ci-step.sh check|vocab}"
case "$step" in
vocab)
    # Runs as root in the gcloud image, which has git. The checkout's owner can
    # differ from root; trust this one path for git only.
    export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/workspace/repo
    cd /workspace/repo
    verify_head
    mkdir -p "$ci"
    err="$ci/vocab-secret.err"
    # Private patterns (the VOCAB_DENYLIST secret on GitHub) come from Secret
    # Manager when the secret exists in the build's project. The value is only
    # ever held in this variable; it is never echoed or written to disk.
    if denylist="$(gcloud secrets versions access latest --secret="$DENYLIST_SECRET" 2>"$err")"; then
        rm -f "$err"
        echo "vocab: private patterns loaded from Secret Manager secret $DENYLIST_SECRET"
        VOCAB_DENYLIST="$denylist" scripts/vocab-check.sh
    elif grep -qE 'NOT_FOUND|SERVICE_DISABLED|has not been used in project' "$err"; then
        rm -f "$err"
        echo "vocab: no Secret Manager secret $DENYLIST_SECRET in this project (not found," \
            "or the Secret Manager API is not enabled); checking generic patterns only"
        env -u VOCAB_DENYLIST scripts/vocab-check.sh
    else
        # The secret may exist but cannot be read: fail rather than silently
        # skip the private patterns. gcloud's error holds no secret payload.
        echo "vocab: could not read Secret Manager secret $DENYLIST_SECRET:" >&2
        cat "$err" >&2
        rm -f "$err"
        exit 1
    fi
    ;;
check)
    if [ "$(id -u)" = "0" ]; then
        # Root only adds the toolchain components and a private copy of the
        # checkout. The checks run as an unprivileged user (uid 1000), as on a
        # GitHub runner: permission-sensitive tests mean nothing as root.
        rustup component add rustfmt clippy
        user="$(getent passwd "$CI_UID" | cut -d: -f1 || true)"
        if [ -z "$user" ]; then
            useradd --uid "$CI_UID" --create-home --shell /bin/bash ci
            user=ci
        fi
        home="$(getent passwd "$user" | cut -d: -f6)"
        mkdir -p "$ci/check"
        cp -a /workspace/repo "$ci/check/repo"
        cp -a "$0" "$ci/check/ci-step.sh"
        chown -R "$CI_UID:$CI_UID" "$ci/check"
        exec runuser -u "$user" -- env HOME="$home" PATH="$PATH" RUSTUP_HOME="${RUSTUP_HOME:-}" \
            UA_CI_SOURCE_SHA="${UA_CI_SOURCE_SHA:-}" bash "$ci/check/ci-step.sh" check
    fi
    cd "$ci/check/repo"
    verify_head
    export CARGO_HOME="$ci/check/cargo-home"
    export CARGO_TERM_COLOR=always
    export RUSTFLAGS="-D warnings"
    bin="$ci/check/bin"
    mkdir -p "$bin"
    export PATH="$bin:$PATH"
    curl -fsSL -o "$ci/check/nextest.tar.gz" \
        "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$NEXTEST_VERSION/cargo-nextest-$NEXTEST_VERSION-x86_64-unknown-linux-gnu.tar.gz"
    echo "$NEXTEST_SHA256  $ci/check/nextest.tar.gz" | sha256sum -c -
    tar -xzf "$ci/check/nextest.tar.gz" -C "$bin"
    rustc --version
    cargo fmt --all --check
    cargo clippy --workspace --all-targets
    cargo nextest run --workspace --no-tests=pass
    cargo test --workspace --doc
    ;;
*)
    echo "unknown step: $step" >&2
    exit 2
    ;;
esac
