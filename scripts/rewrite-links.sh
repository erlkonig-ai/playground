#!/usr/bin/env bash
set -euo pipefail

# Rewrite all wiki: and files: links in wiki fragments to use full-length hex IDs.
# Uses wiki.rs fix-truncated for batch expansion (one pile open per fragment).
# Ambiguous prefixes are left unchanged and collected for manual review.

PILE="${PILE:-./self.pile}"
WIKI="PILE=$PILE rust-script faculties/wiki.rs"

echo "Collecting fragment IDs..."
FRAGMENTS=$(eval "$WIKI" list --all 2>/dev/null | grep "^[a-f0-9]" | awk '{print $1}')
TOTAL=$(echo "$FRAGMENTS" | wc -l | tr -d ' ')
echo "Found $TOTAL fragments"

COUNT=0
CHANGED=0
SKIPPED=0
ALL_AMBIGUOUS=""

for frag_id in $FRAGMENTS; do
    COUNT=$((COUNT + 1))

    # Export content
    original=$(eval "$WIKI" export "$frag_id" 2>/dev/null) || continue

    # Check if it has any short prefixes worth fixing
    if ! echo "$original" | grep -qE '(wiki|files):[0-9a-fA-F]{4,31}([^0-9a-fA-F]|$)'; then
        # No short wiki: prefixes. Check files: too
        if ! echo "$original" | grep -qE 'files:[0-9a-fA-F]{4,63}([^0-9a-fA-F]|$)'; then
            continue  # Nothing to fix
        fi
    fi

    # Fix truncated prefixes (one pile open for all prefixes in this fragment)
    tmpfile="/tmp/rewrite-links-${frag_id:0:8}.typ"
    echo "$original" > "$tmpfile"
    fixed=$(eval "$WIKI" fix-truncated "@$tmpfile" 2>/tmp/rewrite-stderr.txt) || {
        echo "  ERROR on $frag_id"
        SKIPPED=$((SKIPPED + 1))
        continue
    }

    # Collect ambiguities
    ambig=$(cat /tmp/rewrite-stderr.txt | grep "^AMBIGUOUS:" || true)
    if [[ -n "$ambig" ]]; then
        ALL_AMBIGUOUS="${ALL_AMBIGUOUS}${ambig}\n"
    fi

    # Check if anything changed
    if [[ "$original" != "$fixed" ]]; then
        echo "$fixed" > "$tmpfile"
        eval "$WIKI" edit "$frag_id" "@$tmpfile" 2>/dev/null
        CHANGED=$((CHANGED + 1))
        echo "  [$COUNT/$TOTAL] $frag_id — updated"
    fi

    if [[ $((COUNT % 50)) -eq 0 ]]; then
        echo "  [$COUNT/$TOTAL] processed ($CHANGED changed, $SKIPPED errors)"
    fi
done

echo
echo "Done: $COUNT fragments processed, $CHANGED updated, $SKIPPED errors"

if [[ -n "$ALL_AMBIGUOUS" ]]; then
    echo
    echo "=== AMBIGUOUS PREFIXES (need manual resolution) ==="
    echo -e "$ALL_AMBIGUOUS" | sort -u
fi
