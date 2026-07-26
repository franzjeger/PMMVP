#!/usr/bin/env bash
# Compile both Apple schemes, unsigned, and report compiler diagnostics by count.
#
# The point of the count: this Swift is written on Linux and the macOS runner is
# the only compiler it ever meets, so "the log was empty" is the only evidence
# anyone has that it is clean — and an empty log looks identical whether the
# build was quiet, the diagnostics were filtered, or nothing was compiled at all.
# Printing a number turns silence into an assertion.
#
# It matters most for SWIFT_STRICT_CONCURRENCY, which both project.yml files set
# to `complete`. Under the Swift 5 language mode its findings are warnings;
# switching SWIFT_VERSION to 6.0 turns the same set into errors. The count here
# is what says whether that switch is a formality or a project.
#
# Full xcodebuild output goes to a file; only `file:line: warning|error` lines
# reach the console, plus the tail of a failing log.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS="${RUNNER_TEMP:-/tmp}"
failed=0
total=0

build() {
    local dir="$1" scheme="$2" destination="$3"
    local log="$LOGS/$scheme.log" diag="$LOGS/$scheme.diag"
    local status=0 count

    echo "==> $scheme ($destination)"
    # No -quiet: the full log is wanted in the file. Only the filtered lines and
    # the count are printed, so the console stays readable either way.
    ( cd "$ROOT/$dir" \
        && xcodegen generate \
        && xcodebuild -scheme "$scheme" -destination "$destination" \
            CODE_SIGNING_ALLOWED=NO -derivedDataPath build build ) \
        > "$log" 2>&1 || status=$?

    # A compiler diagnostic is  /path/To/File.swift:12:5: warning: message
    # sort -u because a header included from several files repeats its warnings.
    grep -hE '^/.+:[0-9]+:[0-9]+: (warning|error): ' "$log" | sort -u > "$diag" || true
    count=$(wc -l < "$diag" | tr -d ' ')
    total=$(( total + count ))

    echo "    $count distinct compiler diagnostics"
    if [ "$count" -gt 0 ]; then
        sed 's/^/    /' "$diag"
    fi

    if [ "$status" -ne 0 ]; then
        echo "    BUILD FAILED (exit $status). Last 60 lines:"
        tail -60 "$log" | sed 's/^/    /'
        failed=1
    fi
    return 0
}

build apps/macos ArcaHost "platform=macOS"
build apps/ios   Arca     "generic/platform=iOS Simulator"

echo
echo "==> $total compiler diagnostics across both schemes"
exit "$failed"
