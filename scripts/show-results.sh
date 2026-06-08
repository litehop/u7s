#!/usr/bin/env bash
# Display JUnit XML test results from a sonobuoy run directory.
# Usage: scripts/show-results.sh [path/to/junit_01.xml | path/to/e2e-dir]
#
# Accepts either:
#   - a JUnit XML file directly
#   - a sonobuoy result directory (auto-locates junit_01.xml beneath it)
#
# Prints: Ran / Passed / Failed counts and detail for each failed test.
# Requires: grep, sed, awk (always available); xmllint preferred for accuracy.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the XML file
# ---------------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <junit_01.xml | sonobuoy-result-dir>" >&2
    exit 1
fi

INPUT="$1"

if [[ -f "$INPUT" ]]; then
    XML="$INPUT"
elif [[ -d "$INPUT" ]]; then
    XML=$(find "$INPUT" -name "junit_01.xml" | head -1)
    if [[ -z "$XML" ]]; then
        echo "Error: no junit_01.xml found under $INPUT" >&2
        exit 1
    fi
else
    echo "Error: $INPUT is not a file or directory" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Parse summary counts from the <testsuites> element
# ---------------------------------------------------------------------------

# Extract attributes from the first <testsuites ...> line.
# The line looks like:
#   <testsuites tests="7598" disabled="7575" errors="0" failures="2" time="0.619">
HEADER=$(grep -m1 '<testsuites' "$XML")

extract_attr() {
    # $1 = attribute name, $2 = line text
    # Returns the value of the attribute, e.g. extract_attr "tests" "$HEADER"
    printf '%s' "$2" | sed -n "s/.*[[:space:]]$1=\"\([^\"]*\)\".*/\1/p"
}

TOTAL=$(extract_attr "tests"    "$HEADER")
DISABLED=$(extract_attr "disabled" "$HEADER")
ERRORS=$(extract_attr "errors"   "$HEADER")
FAILURES=$(extract_attr "failures" "$HEADER")
DURATION=$(extract_attr "time"     "$HEADER")

# Fall back to testsuite skipped= if disabled is absent or zero and skipped present
if [[ -z "$DISABLED" || "$DISABLED" == "0" ]]; then
    SKIPPED_LINE=$(grep -m1 '<testsuite ' "$XML" || true)
    DISABLED_MAYBE=$(extract_attr "skipped" "$SKIPPED_LINE")
    if [[ -n "$DISABLED_MAYBE" && "$DISABLED_MAYBE" != "0" ]]; then
        DISABLED="$DISABLED_MAYBE"
    fi
fi

DISABLED="${DISABLED:-0}"
ERRORS="${ERRORS:-0}"
FAILURES="${FAILURES:-0}"

RAN=$(( TOTAL - DISABLED ))
PASSED=$(( RAN - FAILURES - ERRORS ))

printf "Results: Ran=%s  Passed=%s  Failed=%s  (wall-clock: %ss)\n" \
    "$RAN" "$PASSED" "$FAILURES" "$DURATION"

# If no failures, we are done
if [[ "$FAILURES" == "0" && "$ERRORS" == "0" ]]; then
    exit 0
fi

printf "\n"

# ---------------------------------------------------------------------------
# Print details for each failed test
# ---------------------------------------------------------------------------
# Strategy: use xmllint --xpath when available for reliable parsing;
# fall back to awk-based grep when it is not.

if command -v xmllint &>/dev/null; then
    _show_failures_xmllint() {
        local xml="$1"
        # xmllint doesn't support XPath 2.0, so we extract with --shell is awkward.
        # Instead use xpath to pull each failed testcase's name and time, then
        # pull failure text separately.
        #
        # Count of failed testcases:
        local count
        count=$(xmllint --xpath "count(//testcase[@status='failed'])" "$xml" 2>/dev/null || echo 0)

        if [[ "$count" == "0" ]]; then
            return
        fi

        local i=1
        while [[ $i -le $count ]]; do
            local name time msg
            name=$(xmllint --xpath "string(//testcase[@status='failed'][$i]/@name)" "$xml" 2>/dev/null || true)
            time=$(xmllint --xpath  "string(//testcase[@status='failed'][$i]/@time)" "$xml" 2>/dev/null || true)
            # Get raw failure text; &#xA; entities appear as literal newlines after xmllint normalises them
            msg=$(xmllint --xpath  "string(//testcase[@status='failed'][$i]/failure)" "$xml" 2>/dev/null || true)
            # First non-empty line of the failure message
            first_line=$(printf '%s' "$msg" | grep -m1 '.' || true)

            printf "FAILED [%ss] %s\n" "$time" "$name"
            printf "       %s\n" "$first_line"
            printf "\n"
            i=$(( i + 1 ))
        done
    }
    _show_failures_xmllint "$XML"
else
    # Fallback: awk-based parsing. Works when each <testcase .../> or
    # opening <testcase ...> and its <failure> are on adjacent lines,
    # which is the format sonobuoy/ginkgo produces.
    awk '
    /status="failed"/ {
        # Extract name=
        n = $0
        sub(/.*name="/, "", n); sub(/".*/, "", n)
        # Extract time=
        t = $0
        sub(/.*time="/, "", t); sub(/".*/, "", t)
        # Remove trailing > or />
        testname = n
        testtime = t
        in_failure = 1
        next
    }
    in_failure && /<failure/ {
        # Extract content of failure element from the message attribute or element body
        msg = $0
        # Try message="" attribute first
        if (msg ~ /message="[^"]+/) {
            sub(/.*message="/, "", msg); sub(/".*/, "", msg)
        } else {
            # Strip the opening tag and get body text
            sub(/.*<failure[^>]*>/, "", msg)
            sub(/<\/failure>.*/, "", msg)
        }
        # Decode &#xA; as space for display (just show first logical line)
        gsub(/&#xA;.*/, "", msg)
        gsub(/&amp;/, "\\&", msg)
        gsub(/&lt;/, "<", msg)
        gsub(/&gt;/, ">", msg)
        printf "FAILED [%ss] %s\n", testtime, testname
        printf "       %s\n\n", msg
        in_failure = 0
        next
    }
    ' "$XML"
fi
