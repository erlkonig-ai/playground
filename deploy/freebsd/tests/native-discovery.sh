#!/bin/sh
# Optional real-native check of the runbook's exact MCP exchange, without
# FreeBSD, a compiler, model execution, or existing pile/key material.
set -eu
umask 077
native_binary=${FACULTIES_HTTP_BINARY:?set FACULTIES_HTTP_BINARY to an absolute native HTTP binary}
case "$native_binary" in /*) ;; *) echo 'native binary path must be absolute' >&2; exit 1 ;; esac
test_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture_root=$(mktemp -d /tmp/playground-native-discovery.XXXXXXXX)
native_pid=
cleanup()
{
	if [ -n "$native_pid" ]; then
		kill "$native_pid" 2>/dev/null || :
		wait "$native_pid" 2>/dev/null || :
	fi
	# Only files owned by this invocation; never remove a pile/key on failure.
	rm -f "$fixture_root/internal.token" "$fixture_root/native.log" "$fixture_root/check.sh"
	rmdir "$fixture_root"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
openssl rand -hex 32 > "$fixture_root/internal.token"
env -i PATH=/usr/local/bin:/usr/bin:/bin PERSONA=runbook-fixture \
    "$native_binary" mcp --pile "$fixture_root/absent.pile" \
    --key "$fixture_root/absent.key" --http-listen 127.0.0.1:0 \
    --http-token-file "$fixture_root/internal.token" \
    </dev/null > "$fixture_root/native.log" 2>&1 &
native_pid=$!

fixture_attempt=0
check_url=
while [ "$fixture_attempt" -lt 100 ]; do
	check_url=$(sed -n 's|^faculties MCP HTTP: \(http://127\.0\.0\.1:[0-9][0-9]*/\) .*|\1|p' "$fixture_root/native.log")
	[ -z "$check_url" ] || break
	kill -0 "$native_pid" 2>/dev/null || {
		echo 'native server exited before listening' >&2
		exit 1
	}
	fixture_attempt=$((fixture_attempt + 1))
	sleep 0.1
done
[ -n "$check_url" ] || { echo 'native server did not start within 10 seconds' >&2; exit 1; }

# Keep the operator recipe as the source of truth. Substitute only the
# isolated URL and token path; all HTTP messages and assertions stay intact.
awk '
  /^## Check readiness privately$/ { section = 1; next }
  section && /^## / { exit }
  section && /^```sh$/ { copying = 1; next }
  copying && /^```$/ { exit }
  copying {
    if ($0 ~ /^  check_url=/) print "  check_url=${RUNBOOK_CHECK_URL:?}"
    else if ($0 ~ /^  key_file=/) print "  key_file=${RUNBOOK_KEY_FILE:?}"
    else print
  }
' "$test_source/../native-workers.md" > "$fixture_root/check.sh"
[ -s "$fixture_root/check.sh" ] || { echo 'runbook exchange not found' >&2; exit 1; }
env -i PATH=/usr/local/bin:/usr/bin:/bin \
    RUNBOOK_CHECK_URL="$check_url" RUNBOOK_KEY_FILE="$fixture_root/internal.token" \
    sh "$fixture_root/check.sh"
[ ! -e "$fixture_root/absent.pile" ] && [ ! -e "$fixture_root/absent.key" ] || {
	echo "discovery unexpectedly created pile/key material; inspect $fixture_root" >&2
	exit 1
}
printf 'PASS: real native initialize, initialized, tools/list, DELETE; pile/key remain absent\n'
