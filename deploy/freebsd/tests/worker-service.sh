#!/bin/sh
# Linux shell fixtures for the FreeBSD launch contract. Runs no jail, daemon,
# faculty, or pile operation; does NOT establish real rc/FreeBSD behavior.
set -eu
umask 077
test_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
fixture_root=$(mktemp -d /tmp/playground-worker-test.XXXXXXXX)
case "$fixture_root" in /tmp/playground-worker-test.*) ;; *) exit 1 ;; esac
trap 'rm -rf -- "$fixture_root"' EXIT HUP INT TERM
mkdir "$fixture_root/bin" "$fixture_root/config" "$fixture_root/run" "$fixture_root/log"
jq_binary=$(command -v jq)

# Transform only this temporary copy. Production has no command injection or
# guard-bypass knobs for tests; absolute commands stay absolute on FreeBSD.
sed "s|@FIXTURE_ROOT@|$fixture_root|g" "$test_source/worker-command.fixture" > "$fixture_root/bin/command"
chmod 0700 "$fixture_root/bin/command"
for fixture_command in id sysctl stat playground jexec daemon; do
	ln -s command "$fixture_root/bin/$fixture_command"
done
sed "s|@FIXTURE_ROOT@|$fixture_root|g" "$test_source/rc.subr.fixture" > "$fixture_root/rc.subr"
sed -e "s|\. /etc/rc.subr|. $fixture_root/rc.subr|" \
    -e "s|/usr/bin/id|$fixture_root/bin/id|g" \
    -e "s|/sbin/sysctl|$fixture_root/bin/sysctl|g" \
    -e "s|/usr/bin/stat|$fixture_root/bin/stat|g" \
    -e "s|/usr/local/bin/playground|$fixture_root/bin/playground|g" \
    -e "s|/usr/sbin/jexec|$fixture_root/bin/jexec|g" \
    -e "s|/usr/sbin/daemon|$fixture_root/bin/daemon|g" \
    -e "s|/usr/local/bin/jq|$jq_binary|g" \
    -e "s|worker_config=\"/usr/local/etc/playground-workers/|worker_config=\"$fixture_root/config/|" \
    -e "s|pidfile=\"/var/run/|pidfile=\"$fixture_root/run/|" \
    -e "s|worker_log=\"/var/log/|worker_log=\"$fixture_root/log/|" \
    "$test_source/../playground_faculties" > "$fixture_root/service"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_line() { grep -F -x -- "$1" "$2" >/dev/null || fail "missing argv: $1"; }
clear_calls()
{
	rm -f "$fixture_root/attach.args" "$fixture_root/staged.token" "$fixture_root/daemon.args"
}
write_valid()
{
	printf "worker_tenant='pilot'\nworker_manifest='%s/workers.json'\nworker_dataset_parent='pool/children'\nworker_pile_root='/var/db/piles'\nworker_jail_prefix='playground'\n" \
	    "$fixture_root" > "$fixture_root/config/playground_faculties_fixture.conf"
	printf 'local-internal-token-with-at-least-32-characters\r\n' > "$fixture_root/pilot.token"
	jq -n '{workers:[{tenant:"pilot", address:"127.0.0.1:8401", token_file:"pilot.token"}]}' \
	    > "$fixture_root/workers.json"
	chmod 0600 "$fixture_root/config/playground_faculties_fixture.conf" "$fixture_root/pilot.token" "$fixture_root/workers.json"
	clear_calls
}
rewrite_manifest()
{
	jq "$1" "$fixture_root/workers.json" > "$fixture_root/next.json"
	mv "$fixture_root/next.json" "$fixture_root/workers.json"
}
expect_refusal()
{
	clear_calls
	if sh "$fixture_root/service" "${2-start}" > "$fixture_root/stdout" 2> "$fixture_root/stderr"; then
		fail "$1 unexpectedly started"
	fi
	[ ! -e "$fixture_root/attach.args" ] || fail "$1 touched the jail"
	[ ! -e "$fixture_root/staged.token" ] || fail "$1 staged a token"
	[ ! -e "$fixture_root/daemon.args" ] || fail "$1 launched daemon"
}

write_valid
DRIVE_ENDPOINT=fixture-parent-drive TRIBLESPACE_KEY=fixture-parent-key \
    DISCORD_TOKEN=fixture-parent-discord WIKI_COLLECTION=fixture-parent-collection \
    sh "$fixture_root/service" start
cmp "$fixture_root/pilot.token" "$fixture_root/staged.token" || fail 'bearer bytes changed'
for fixture_arg in attach pilot --jail-local --jail-external-rctl pool/children /var/db/piles; do
	assert_line "$fixture_arg" "$fixture_root/attach.args"
done
for fixture_arg in -P "$fixture_root/run/playground_faculties_fixture.pid" -R 10 \
    -l -U root -d / playground-pilot-hash -i 'PERSONA=pilot assistant' \
    PILE=/pile/self.pile TRIBLESPACE_KEY=/pile/self.key \
    /opt/faculties/faculties mcp --http-listen 127.0.0.1:8401 \
    --http-token-file /var/run/faculties-mcp/token; do
	assert_line "$fixture_arg" "$fixture_root/daemon.args"
done
if grep -E 'fixture-parent|--tokens|--oauth-state|local-internal-token' \
    "$fixture_root/attach.env" "$fixture_root/attach.args" \
    "$fixture_root/daemon.env" "$fixture_root/daemon.args"; then
	fail 'operator environment or bearer leaked into launcher argv/env'
fi

touch "$fixture_root/running"
for fixture_action in start faststart forcestart; do
	expect_refusal 'existing supervisor' "$fixture_action"
done
rm "$fixture_root/running"
touch "$fixture_root/unsafe-parent"
expect_refusal 'unsafe parent' forcestart
rm "$fixture_root/unsafe-parent"

write_valid
chmod 0644 "$fixture_root/config/playground_faculties_fixture.conf"
expect_refusal 'public config'
write_valid
chmod 0644 "$fixture_root/workers.json"
expect_refusal 'public manifest'
write_valid
chmod 0644 "$fixture_root/pilot.token"
expect_refusal 'public bearer'
write_valid
mv "$fixture_root/pilot.token" "$fixture_root/token-real"
ln -s token-real "$fixture_root/pilot.token"
expect_refusal 'symlink bearer'
rm "$fixture_root/pilot.token"

write_valid
rewrite_manifest '.workers[0].tenant = "pil*"'
expect_refusal 'nonexact tenant'
write_valid
rewrite_manifest '.workers += .workers'
expect_refusal 'duplicate tenant/address'
write_valid
rewrite_manifest '.workers += [{tenant:"other",address:"127.0.0.1:8401",token_file:"other.token"}]'
expect_refusal 'duplicate address'
write_valid
rewrite_manifest '.workers[0].extra = true'
expect_refusal 'unknown manifest field'
write_valid
printf '{}\n' >> "$fixture_root/workers.json"
expect_refusal 'multiple manifest objects'
for fixture_address in 0.0.0.0:8401 192.0.2.1:8401 localhost:8401 127.0.0.1:0 127.0.0.1:65536; do
	write_valid
	rewrite_manifest ".workers[0].address = \"$fixture_address\""
	expect_refusal "invalid address $fixture_address"
done
write_valid
rewrite_manifest '.workers[0].address = "[::1]:8402"'
sh "$fixture_root/service" start
assert_line '[::1]:8402' "$fixture_root/daemon.args"

for fixture_token_case in empty short double_lf double_crlf newline_middle; do
	write_valid
	case "$fixture_token_case" in
	empty) : > "$fixture_root/pilot.token" ;;
	short) printf short > "$fixture_root/pilot.token" ;;
	double_lf) printf 'local-internal-token-with-at-least-32-characters\n\n' > "$fixture_root/pilot.token" ;;
	double_crlf) printf 'local-internal-token-with-at-least-32-characters\r\n\r\n' > "$fixture_root/pilot.token" ;;
	newline_middle) printf 'local-internal-token-with\nat-least-32-characters' > "$fixture_root/pilot.token" ;;
	esac
	expect_refusal "invalid token $fixture_token_case"
done
write_valid
touch "$fixture_root/attach-fails"
if sh "$fixture_root/service" start > "$fixture_root/stdout" 2> "$fixture_root/stderr"; then
	fail 'failed attach started worker'
fi
[ ! -e "$fixture_root/staged.token" ] && [ ! -e "$fixture_root/daemon.args" ] || fail 'attach failure passed through'
rm "$fixture_root/config/playground_faculties_fixture.conf" "$fixture_root/workers.json"
sh "$fixture_root/service" stop
assert_line "$fixture_root/run/playground_faculties_fixture.pid" "$fixture_root/status.args"
assert_line "$fixture_root/bin/daemon" "$fixture_root/status.args"
printf 'PASS: worker launch contract, refusal paths, byte transfer, clean environment, and config-independent stop\n'
