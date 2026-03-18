#!/usr/bin/env bash
set -euo pipefail

# Rewrite all wiki: and files: links in wiki fragments to use full-length hex IDs.
# wiki: links → 32 hex chars (128-bit entity IDs)
# files: links → 64 hex chars (256-bit Blake3 hashes)
#
# Uses wiki.rs resolve for wiki: prefixes.
# For files: prefixes, searches the archive directly.
#
# Fails fast on any ambiguous or unresolvable prefix.

PILE="${PILE:-../personas/operator/pile/self.pile}"
WIKI="PILE=$PILE rust-script faculties/wiki.rs"
FILES="PILE=$PILE rust-script faculties/files.rs"

# Cache resolved prefixes to avoid repeated lookups
declare -A WIKI_CACHE
declare -A FILES_CACHE

resolve_wiki() {
    local prefix="$1"
    if [[ ${#prefix} -eq 32 ]]; then
        echo "$prefix"
        return
    fi
    if [[ -n "${WIKI_CACHE[$prefix]:-}" ]]; then
        echo "${WIKI_CACHE[$prefix]}"
        return
    fi
    local full
    full=$(eval "$WIKI" resolve "$prefix" 2>&1) || {
        echo "FAIL: wiki:$prefix → $full" >&2
        return 1
    }
    WIKI_CACHE[$prefix]="$full"
    echo "$full"
}

resolve_files() {
    local prefix="$1"
    if [[ ${#prefix} -eq 64 ]]; then
        echo "$prefix"
        return
    fi
    if [[ -n "${FILES_CACHE[$prefix]:-}" ]]; then
        echo "${FILES_CACHE[$prefix]}"
        return
    fi
    local full
    full=$(eval "$FILES" resolve "$prefix" 2>&1) || {
        echo "FAIL: files:$prefix → $full" >&2
        return 1
    }
    FILES_CACHE[$prefix]="$full"
    echo "$full"
}

# Get all fragment IDs
echo "Collecting fragment IDs..."
FRAGMENTS=$(eval "$WIKI" list --all 2>/dev/null | grep "^[a-f0-9]" | awk '{print $1}')
TOTAL=$(echo "$FRAGMENTS" | wc -l | tr -d ' ')
echo "Found $TOTAL fragments"

COUNT=0
CHANGED=0
FAILED=0

for frag_id in $FRAGMENTS; do
    COUNT=$((COUNT + 1))

    # Export content
    content=$(eval "$WIKI" export "$frag_id" 2>/dev/null) || continue

    # Find all wiki: and files: references that are shorter than full length
    new_content="$content"
    needs_update=false

    # Process wiki: links (need 32 chars)
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        prefix="${match#wiki:}"
        if [[ ${#prefix} -lt 32 ]]; then
            full=$(resolve_wiki "$prefix") || { FAILED=$((FAILED + 1)); continue 2; }
            new_content="${new_content//$match/wiki:$full}"
            needs_update=true
        fi
    done < <(echo "$content" | grep -oE 'wiki:[0-9a-fA-F]+' | sort -u)

    # Process files: links (need 64 chars)
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        prefix="${match#files:}"
        if [[ ${#prefix} -lt 64 ]]; then
            full=$(resolve_files "$prefix") || { FAILED=$((FAILED + 1)); continue 2; }
            new_content="${new_content//$match/files:$full}"
            needs_update=true
        fi
    done < <(echo "$content" | grep -oE 'files:[0-9a-fA-F]+' | sort -u)

    if $needs_update; then
        # Save and edit back
        tmpfile="/tmp/rewrite-links-${frag_id:0:8}.typ"
        echo "$new_content" > "$tmpfile"
        eval "$WIKI" edit "$frag_id" "@$tmpfile" 2>/dev/null
        CHANGED=$((CHANGED + 1))
        echo "  [$COUNT/$TOTAL] $frag_id — updated"
    fi

    if [[ $((COUNT % 50)) -eq 0 ]]; then
        echo "  [$COUNT/$TOTAL] processed ($CHANGED changed, $FAILED failed)"
    fi
done

echo
echo "Done: $COUNT fragments processed, $CHANGED updated, $FAILED failed"
