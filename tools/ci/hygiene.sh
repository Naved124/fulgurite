#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 MD Naved Raja Khan
# SPDX-License-Identifier: Apache-2.0

# Pull-request hygiene, run by .github/workflows/hygiene.yml:
#
#   1. the branch is named `type/short-description` (lowercase);
#   2. no blocked word appears in the branch name, the PR title or body, any
#      commit's message, author or committer, any added or renamed file path,
#      or any added line.
#
# The blocked words come from the BLOCKED_WORDS secret (an extended regular
# expression, matched case-insensitively) so that the list is not published.
# Failures name the field (and file and line), never the matched text, because
# the logs of a public repository are public.
#
# Environment: BRANCH, TITLE, BODY, BASE (base commit), HEAD_SHA, BLOCKED_WORDS.
# Locally: BRANCH=... TITLE=... BODY= BASE=main HEAD_SHA=HEAD BLOCKED_WORDS='...' tools/ci/hygiene.sh

set -euo pipefail

fail=0
problem() {
    echo "::error::$1"
    fail=1
}

types='feat|fix|docs|test|ci|build|refactor|perf|chore|license|release'
if [[ ! "$BRANCH" =~ ^($types)/[a-z0-9][a-z0-9._-]*$ ]]; then
    problem "branch '$BRANCH' is not named type/short-description (types: ${types//|/, }; lowercase letters, digits, '.', '_', '-')"
fi

if [[ -z "${BLOCKED_WORDS:-}" ]]; then
    problem "the BLOCKED_WORDS secret is not set, so attribution cannot be checked"
    exit 1
fi

# blocked TEXT: whether TEXT contains a blocked word. Text is passed as an
# argument, not piped, so an early exit of grep cannot hide a match.
blocked() {
    grep -q -i -E -e "$BLOCKED_WORDS" <<<"$1"
}

if blocked "$BRANCH"; then problem "the branch name contains a blocked word"; fi
if blocked "$TITLE"; then problem "the pull request title contains a blocked word"; fi
if blocked "${BODY:-}"; then problem "the pull request body contains a blocked word"; fi

base=$(git merge-base "$BASE" "$HEAD_SHA")
for c in $(git rev-list "$base..$HEAD_SHA"); do
    if blocked "$(git log -1 --format='%an%n%ae%n%cn%n%ce%n%B' "$c")"; then
        problem "commit ${c:0:12}: its message, author or committer contains a blocked word"
    fi
done

while IFS= read -r path; do
    if blocked "$path"; then problem "an added or renamed file's path contains a blocked word"; fi
done < <(git diff --name-only --diff-filter=ACR "$base" "$HEAD_SHA")

# Added lines, reported as file:line.
while IFS=$'\t' read -r where text; do
    if blocked "$text"; then
        problem "$where: an added line contains a blocked word"
    fi
done < <(git diff --unified=0 --no-color --diff-filter=ACMR "$base" "$HEAD_SHA" | awk '
    /^\+\+\+ / { file = substr($0, 7); next }
    /^@@ / { split($3, a, ","); line = substr(a[1], 2) + 0; next }
    /^\+/ { print file ":" line "\t" substr($0, 2); line++ }
')

if [[ $fail -ne 0 ]]; then
    exit 1
fi
echo "branch name and attribution: ok"
