#!/bin/sh
# Public-edge smoke test for https://mcp.bultmann.eu.
#
# Required:
#   PLAYGROUND_TOKEN=<static bearer token> ./smoke.sh
#
# Private preflight before enabling the public edge (loopback HTTP only):
#   PLAYGROUND_TOKEN=... PLAYGROUND_BASE_URL=http://127.0.0.1:8377 \
#     PLAYGROUND_PRIVATE_HTTP=YES ./smoke.sh
#
# The default pass proves certificate/hostname validation, unauthenticated
# rejection, authenticated MCP initialization, the advertised seven-tool
# surface, a tenant-scoped open_session, and synchronous exec.
#
# Optional FreeBSD cancellation proof (run as root in the dedicated parent
# jail, after the normal pass is known-good):
#   PLAYGROUND_TOKEN=... PLAYGROUND_FREEBSD_JOB_SMOKE=YES ./smoke.sh
#
# That opt-in test creates an unrelated sentinel in the tenant jail, starts a
# job containing a daemonized TERM-ignoring descendant, cancels the job, and
# proves both that the descendant died and the unrelated sentinel survived.
# It does not destroy the persistent tenant jail or either pile.

set -eu

die()
{
	printf 'playground smoke: %s\n' "$*" >&2
	exit 1
}

need()
{
	command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

need curl
need jq

: "${PLAYGROUND_TOKEN:?set PLAYGROUND_TOKEN to a provisioned tenant bearer token}"

BASE_URL=${PLAYGROUND_BASE_URL:-https://mcp.bultmann.eu}
BASE_URL=${BASE_URL%/}
MCP_URL=$BASE_URL/mcp
case "$BASE_URL" in
	https://*) CURL_PROTO='=https' ;;
	http://127.0.0.1|http://127.0.0.1:*)
		[ "${PLAYGROUND_PRIVATE_HTTP:-NO}" = YES ] || \
			die "loopback HTTP requires PLAYGROUND_PRIVATE_HTTP=YES"
		CURL_PROTO='=http'
		;;
	*) die "PLAYGROUND_BASE_URL must use https or opted-in loopback HTTP" ;;
esac

TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/playground-smoke.XXXXXX") || exit 1
BOX=
SID=
JOB_ID=
SENTINEL_STARTED=0
SENTINEL_PID_FILE=

cleanup()
{
	# A failed opt-in run must not leave its test job running until the 60s
	# command timeout. Cancellation is retry-safe, so this is harmless after a
	# successful terminal result too.
	if [ -n "$JOB_ID" ] && [ -n "$SID" ]; then
		cancel_payload=$(jq -cn --arg job_id "$JOB_ID" \
			'{jsonrpc:"2.0",id:99,method:"tools/call",params:{name:"job_cancel",arguments:{job_id:$job_id}}}')
		curl --silent --max-time 10 --proto "$CURL_PROTO" \
			-H "Authorization: Bearer $PLAYGROUND_TOKEN" \
			-H "Mcp-Session-Id: $SID" -H 'Content-Type: application/json' \
			--data-binary "$cancel_payload" "$MCP_URL" >/dev/null 2>&1 || true
	fi
	if [ "$SENTINEL_STARTED" -eq 1 ] && [ -n "$BOX" ] && [ -n "$SENTINEL_PID_FILE" ]; then
		jexec "$BOX" /bin/sh -c \
			"test ! -s '$SENTINEL_PID_FILE' || kill \"\$(cat '$SENTINEL_PID_FILE')\" 2>/dev/null || true; rm -f '$SENTINEL_PID_FILE'" \
			>/dev/null 2>&1 || true
	fi
	# Release the provider's sandbox handle before deleting the MCP transport.
	# The sandbox itself is persistent: close_session only decrements this
	# client's reference. Skipping it would leak one refcount on every smoke.
	if [ -n "$BOX" ] && [ -n "$SID" ]; then
		close_payload=$(jq -cn --arg session "$BOX" \
			'{jsonrpc:"2.0",id:98,method:"tools/call",params:{name:"close_session",arguments:{session:$session}}}')
		curl --silent --max-time 10 --proto "$CURL_PROTO" \
			-H "Authorization: Bearer $PLAYGROUND_TOKEN" \
			-H "Mcp-Session-Id: $SID" -H 'Content-Type: application/json' \
			--data-binary "$close_payload" "$MCP_URL" >/dev/null 2>&1 || true
	fi
	# DELETE releases only the short-lived MCP transport session. The tenant's
	# persistent sandbox and its piles remain available for reconnection.
	if [ -n "$SID" ]; then
		curl --silent --max-time 10 --proto "$CURL_PROTO" -X DELETE \
			-H "Authorization: Bearer $PLAYGROUND_TOKEN" \
			-H "Mcp-Session-Id: $SID" "$MCP_URL" >/dev/null 2>&1 || true
	fi
	rm -rf "$TMP_ROOT"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

INITIALIZE='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"playground-deploy-smoke","version":"1"}}}'

# curl verifies the public CA chain and hostname by default. --proto prevents a
# typo or redirect from silently turning the TLS proof into an HTTP request.
UNAUTH_STATUS=$(curl --silent --show-error \
	--proto "$CURL_PROTO" --connect-timeout 10 --max-time 30 \
	-D "$TMP_ROOT/unauth.headers" -o "$TMP_ROOT/unauth.body" \
	-w '%{http_code}' -H 'Content-Type: application/json' \
	--data-binary "$INITIALIZE" "$MCP_URL") || die "TLS/public endpoint request failed"
[ "$UNAUTH_STATUS" = 401 ] || die "unauthenticated initialize returned HTTP $UNAUTH_STATUS, expected 401"
grep -Eiq '^www-authenticate:[[:space:]]*Bearer' "$TMP_ROOT/unauth.headers" || \
	die "401 response did not carry a Bearer challenge"

AUTH_STATUS=$(curl --silent --show-error \
	--proto "$CURL_PROTO" --connect-timeout 10 --max-time 60 \
	-D "$TMP_ROOT/init.headers" -o "$TMP_ROOT/init.body" \
	-w '%{http_code}' -H "Authorization: Bearer $PLAYGROUND_TOKEN" \
	-H 'Content-Type: application/json' --data-binary "$INITIALIZE" "$MCP_URL") || \
	die "authenticated initialize request failed"
[ "$AUTH_STATUS" = 200 ] || {
	cat "$TMP_ROOT/init.body" >&2
	die "authenticated initialize returned HTTP $AUTH_STATUS, expected 200"
}
jq -e '.result.protocolVersion == "2025-06-18"' "$TMP_ROOT/init.body" >/dev/null || {
	cat "$TMP_ROOT/init.body" >&2
	die "initialize response was not a successful MCP handshake"
}
SID=$(awk 'tolower($1) == "mcp-session-id:" { gsub("\\r", "", $2); value=$2 } END { print value }' \
	"$TMP_ROOT/init.headers")
[ -n "$SID" ] || die "initialize response omitted Mcp-Session-Id"

NOTIFY_STATUS=$(curl --silent --show-error \
	--proto "$CURL_PROTO" --connect-timeout 10 --max-time 30 \
	-o "$TMP_ROOT/notify.body" -w '%{http_code}' \
	-H "Authorization: Bearer $PLAYGROUND_TOKEN" \
	-H "Mcp-Session-Id: $SID" -H 'Content-Type: application/json' \
	--data-binary '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$MCP_URL") || \
	die "MCP initialized notification failed"
[ "$NOTIFY_STATUS" = 202 ] || die "initialized notification returned HTTP $NOTIFY_STATUS, expected 202"

mcp_post()
{
	payload=$1
	status=$(curl --silent --show-error \
		--proto "$CURL_PROTO" --connect-timeout 10 --max-time 90 \
		-o "$TMP_ROOT/response.body" -w '%{http_code}' \
		-H "Authorization: Bearer $PLAYGROUND_TOKEN" \
		-H "Mcp-Session-Id: $SID" -H 'Content-Type: application/json' \
		--data-binary "$payload" "$MCP_URL") || die "MCP request failed"
	[ "$status" = 200 ] || {
		cat "$TMP_ROOT/response.body" >&2
		die "MCP request returned HTTP $status, expected 200"
	}
	cat "$TMP_ROOT/response.body"
}

tool_call()
{
	tool_name=$1
	arguments=$2
	payload=$(jq -cn --arg name "$tool_name" --argjson arguments "$arguments" \
		'{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:$name,arguments:$arguments}}')
	reply=$(mcp_post "$payload")
	printf '%s' "$reply" | jq -e \
		'.result.isError == false and (.result.content[0].text | type == "string")' >/dev/null || {
		printf '%s\n' "$reply" >&2
		die "$tool_name returned an MCP tool error"
	}
	printf '%s' "$reply" | jq -r '.result.content[0].text'
}

TOOLS=$(mcp_post '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')
for tool in open_session exec job_exec job_poll job_cancel close_session destroy_session; do
	printf '%s' "$TOOLS" | jq -e --arg tool "$tool" \
		'.result.tools | any(.name == $tool)' >/dev/null || die "tools/list omitted $tool"
done

BOX=$(tool_call open_session '{}')
[ -n "$BOX" ] || die "open_session returned an empty sandbox id"

EXEC_ARGS=$(jq -cn --arg session "$BOX" \
	--arg command "printf 'PLAYGROUND_SMOKE_OK\\n'" \
	'{session:$session,command:$command,timeout_ms:30000}')
EXEC_TEXT=$(tool_call exec "$EXEC_ARGS")
printf '%s' "$EXEC_TEXT" | grep -q 'PLAYGROUND_SMOKE_OK' || die "exec output omitted its marker"
printf '%s' "$EXEC_TEXT" | grep -q '\[exit 0\]' || die "exec did not report exit 0"

printf 'playground smoke: TLS, Bearer auth, MCP handshake, tools, and exec: ok\n'

[ "${PLAYGROUND_FREEBSD_JOB_SMOKE:-NO}" = YES ] || exit 0

[ "$(uname -s)" = FreeBSD ] || die "PLAYGROUND_FREEBSD_JOB_SMOKE=YES must run on FreeBSD"
[ "$(id -u)" -eq 0 ] || die "FreeBSD job smoke must run as root in the parent jail"
need jls
need jexec
case "$BOX" in
	playground-*) ;;
	*) die "refusing host-side test for non-playground session id: $BOX" ;;
esac
ACTUAL_JAIL=$(jls -j "$BOX" name 2>/dev/null) || die "session jail is not running: $BOX"
[ "$ACTUAL_JAIL" = "$BOX" ] || die "jail provenance check returned '$ACTUAL_JAIL', expected '$BOX'"

TAG="playground-smoke-$$-$(date +%s)"
SENTINEL_PID_FILE="/tmp/$TAG.sentinel.pid"
DESCENDANT_PID_FILE="/tmp/$TAG.descendant.pid"

# This process is deliberately outside the MCP job's descendant tree. Exact
# job cancellation must leave it alive; a jail-wide cleanup will fail the test.
SENTINEL_SCRIPT="rm -f '$SENTINEL_PID_FILE'; nohup /bin/sleep 86400 </dev/null >/dev/null 2>&1 & echo \$! > '$SENTINEL_PID_FILE'"
jexec "$BOX" /bin/sh -c "$SENTINEL_SCRIPT" || die "could not start unrelated jail sentinel"
SENTINEL_STARTED=1
jexec "$BOX" /bin/sh -c \
	"test -s '$SENTINEL_PID_FILE' && kill -0 \"\$(cat '$SENTINEL_PID_FILE')\"" || \
	die "unrelated jail sentinel did not stay alive"

# daemon(8) detaches the child from the launching shell. Both that descendant
# and the foreground shell ignore TERM, forcing FreeBSD timeout(1)'s descendant
# reaper/KILL path to demonstrate that no escaped process survives.
JOB_COMMAND=$(printf '%s\n' \
	"rm -f '$DESCENDANT_PID_FILE'" \
	"/usr/sbin/daemon -f /bin/sh -c 'trap \"\" TERM HUP; echo \$\$ > \"$DESCENDANT_PID_FILE\"; while :; do sleep 60; done'" \
	"i=0; while [ ! -s '$DESCENDANT_PID_FILE' ] && [ \$i -lt 50 ]; do sleep 1; i=\$((i + 1)); done" \
	"test -s '$DESCENDANT_PID_FILE' || exit 70" \
	"echo CANCELLATION_READY" \
	"trap '' TERM HUP" \
	"while :; do sleep 60; done")
JOB_ARGS=$(jq -cn --arg session "$BOX" --arg command "$JOB_COMMAND" \
	'{session:$session,command:$command,timeout_ms:60000}')
JOB_STARTED=$(tool_call job_exec "$JOB_ARGS")
JOB_ID=$(printf '%s' "$JOB_STARTED" | jq -er '.job_id') || die "job_exec returned no job id"

cursor=0
ready=0
i=0
while [ "$i" -lt 15 ]; do
	POLL_ARGS=$(jq -cn --arg job_id "$JOB_ID" --argjson cursor "$cursor" \
		'{job_id:$job_id,cursor:$cursor}')
	POLL=$(tool_call job_poll "$POLL_ARGS")
	printf '%s' "$POLL" | jq -e . >/dev/null || die "job_poll text was not JSON"
	if printf '%s' "$POLL" | jq -r '.chunks[].text' | grep -q CANCELLATION_READY; then
		ready=1
		break
	fi
	cursor=$(printf '%s' "$POLL" | jq -er '.next_cursor') || die "job_poll omitted next_cursor"
	state=$(printf '%s' "$POLL" | jq -er '.state') || die "job_poll omitted state"
	[ "$state" != terminal ] || die "cancellation fixture exited before cancellation"
	i=$((i + 1))
	sleep 1
done
[ "$ready" -eq 1 ] || die "cancellation fixture never became ready"
jexec "$BOX" /bin/sh -c \
	"test -s '$DESCENDANT_PID_FILE' && kill -0 \"\$(cat '$DESCENDANT_PID_FILE')\"" || \
	die "detached descendant was not alive before cancellation"

CANCEL_ARGS=$(jq -cn --arg job_id "$JOB_ID" '{job_id:$job_id}')
CANCELLED=$(tool_call job_cancel "$CANCEL_ARGS")
printf '%s' "$CANCELLED" | jq -e \
	'.state == "cancelling" or .state == "terminal"' >/dev/null || die "job_cancel returned an unexpected state"

terminal=0
i=0
while [ "$i" -lt 20 ]; do
	POLL_ARGS=$(jq -cn --arg job_id "$JOB_ID" --argjson cursor "$cursor" \
		'{job_id:$job_id,cursor:$cursor}')
	POLL=$(tool_call job_poll "$POLL_ARGS")
	cursor=$(printf '%s' "$POLL" | jq -er '.next_cursor') || die "job_poll omitted next_cursor"
	state=$(printf '%s' "$POLL" | jq -er '.state') || die "job_poll omitted state"
	has_more=$(printf '%s' "$POLL" | jq -r '.has_more') || die "job_poll omitted has_more"
	case "$has_more" in
		true|false) ;;
		*) die "job_poll returned invalid has_more: $has_more" ;;
	esac
	if [ "$state" = terminal ] && [ "$has_more" = false ]; then
		terminal=1
		break
	fi
	i=$((i + 1))
	sleep 1
done
[ "$terminal" -eq 1 ] || die "cancelled job did not reach a drained terminal state"
printf '%s' "$POLL" | jq -e '.terminal.kind == "cancelled"' >/dev/null || {
	printf '%s\n' "$POLL" >&2
	die "cancelled job reported a non-cancelled terminal result"
}

if jexec "$BOX" /bin/sh -c \
	"test -s '$DESCENDANT_PID_FILE' && kill -0 \"\$(cat '$DESCENDANT_PID_FILE')\"" 2>/dev/null; then
	die "detached TERM-ignoring descendant survived job_cancel"
fi
jexec "$BOX" /bin/sh -c \
	"test -s '$SENTINEL_PID_FILE' && kill -0 \"\$(cat '$SENTINEL_PID_FILE')\"" || \
	die "unrelated jail sentinel died during job_cancel"
jexec "$BOX" /bin/sh -c "rm -f '$DESCENDANT_PID_FILE'"

printf 'playground smoke: exact FreeBSD job cancellation and unrelated-jail survival: ok\n'
