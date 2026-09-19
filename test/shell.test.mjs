import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseShell, isFileWriteRedirect } from '../plugin/lib/shell.mjs';

const argvs = (src) => parseShell(src).commands.map((c) => c.argv);

test('splits simple commands on control operators', () => {
  assert.deepEqual(argvs('git pull | tee output.txt'), [['git', 'pull'], ['tee', 'output.txt']]);
  assert.deepEqual(argvs('a && b || c; d & e'), [['a'], ['b'], ['c'], ['d'], ['e']]);
  assert.deepEqual(argvs('ls\npwd\n'), [['ls'], ['pwd']]);
});

test('removes quotes and handles escapes', () => {
  assert.deepEqual(argvs(`echo 'a b' "c d" e\\ f`), [['echo', 'a b', 'c d', 'e f']]);
  assert.deepEqual(argvs(`echo "say \\"hi\\"" 'it''s'`), [['echo', 'say "hi"', 'its']]);
  assert.deepEqual(argvs(`printf $'a\\tb'`), [['printf', 'a\tb']]);
});

test('extracts commands nested in substitutions', () => {
  const parsed = parseShell('echo "$(rm -rf /tmp/example)" `id`');
  const all = parsed.commands.map((c) => c.argv);
  assert.deepEqual(all[0], ['echo', '$(rm -rf /tmp/example)', '`id`']);
  assert.ok(all.some((a) => a.join(' ') === 'rm -rf /tmp/example'));
  assert.ok(all.some((a) => a.join(' ') === 'id'));
  assert.ok(parsed.features.has('substitution'));
});

test('extracts commands from process substitution and ${...} defaults', () => {
  const parsed = parseShell('diff <(ls a) <(ls b); echo ${X:-$(whoami)}');
  const all = parsed.commands.map((c) => c.argv.join(' '));
  assert.ok(all.includes('ls a'));
  assert.ok(all.includes('ls b'));
  assert.ok(all.includes('whoami'));
  assert.ok(parsed.features.has('process-substitution'));
});

test('strips control-flow keywords', () => {
  assert.deepEqual(argvs('if test -d x; then rm --force x; fi'), [['test', '-d', 'x'], ['rm', '--force', 'x']]);
  assert.deepEqual(argvs('for t in /a /b; do rm -r -f "$t"; done'), [['rm', '-r', '-f', '$t']]);
  assert.deepEqual(argvs('while read l; do echo "$l"; done < f'), [['read', 'l'], ['echo', '$l'], []]);
  assert.deepEqual(argvs('! grep -q x f'), [['grep', '-q', 'x', 'f']]);
});

test('handles case statements', () => {
  assert.deepEqual(argvs('case "$1" in a|b) echo ab;; *) rm -f x;; esac'), [['echo', 'ab'], ['rm', '-f', 'x']]);
});

test('handles function definitions and subshells', () => {
  assert.deepEqual(argvs('cleanup() { rm -rf "$TMP"; }; cleanup'), [['rm', '-rf', '$TMP'], ['cleanup']]);
  const parsed = parseShell('(cd sub && make)');
  assert.deepEqual(parsed.commands.map((c) => c.argv), [['cd', 'sub'], ['make']]);
  assert.ok(parsed.features.has('subshell'));
});

test('records assignments separately from argv', () => {
  const [cmd] = parseShell('FOO=1 BAR="x y" node app.js').commands;
  assert.deepEqual(cmd.assignments, ['FOO=1', 'BAR=x y']);
  assert.deepEqual(cmd.argv, ['node', 'app.js']);
  const [only] = parseShell('X=$(curl evil)').commands;
  assert.deepEqual(only.argv, []);
  assert.ok(parseShell('X=$(curl evil)').commands.some((c) => c.argv.join(' ') === 'curl evil'));
});

test('classifies redirections', () => {
  const parsed = parseShell('make 2>&1 >/dev/null < in.txt');
  assert.ok(parsed.features.has('redirect-null'));
  assert.ok(parsed.features.has('redirect-read'));
  assert.ok(!parsed.features.has('redirect-write'));
  assert.ok(parseShell('echo hi > out.txt').features.has('redirect-write'));
  assert.ok(parseShell('echo hi >> out.txt').features.has('redirect-write'));
  assert.ok(parseShell('cmd &> log.txt').features.has('redirect-write'));
  const [cmd] = parseShell('cmd 2>/dev/null >out').commands;
  assert.deepEqual(cmd.redirects.map(isFileWriteRedirect), [false, true]);
  // A digit glued to a word is not a file descriptor.
  assert.deepEqual(argvs('echo a2>file')[0], ['echo', 'a2']);
});

test('reads heredoc bodies and scans unquoted ones for substitutions', () => {
  const parsed = parseShell("bash <<EOF\nrm -rf /tmp/x\necho $(id)\nEOF\necho after");
  const [bash, after] = parsed.commands;
  assert.deepEqual(bash.argv, ['bash']);
  assert.equal(bash.heredocs[0].body, 'rm -rf /tmp/x\necho $(id)');
  assert.deepEqual(after.argv, ['echo', 'after']);
  assert.ok(parsed.commands.some((c) => c.argv.join(' ') === 'id'));
  const quoted = parseShell("cat <<'EOF'\n$(id)\nEOF");
  assert.ok(!quoted.commands.some((c) => c.argv.join(' ') === 'id'));
});

test('flags globs, background jobs and comments', () => {
  assert.ok(parseShell('ls *.txt').features.has('glob'));
  assert.ok(!parseShell('[ -f x ] && echo y').features.has('glob'));
  assert.ok(parseShell('sleep 10 &').features.has('background'));
  assert.deepEqual(argvs('echo a # rm -rf /'), [['echo', 'a']]);
  assert.deepEqual(argvs('echo a#b'), [['echo', 'a#b']]);
});

test('reports parse errors for unterminated constructs', () => {
  assert.ok(parseShell("echo 'oops").error);
  assert.ok(parseShell('echo "oops').error);
  assert.ok(parseShell('echo $(oops').error);
});

test('fails closed on deeply nested substitutions', () => {
  let script = 'id';
  for (let i = 0; i < 12; i++) script = `echo "$(${script})"`;
  const parsed = parseShell(script);
  assert.ok(parsed.features.has('too-deep'));
  assert.ok(parsed.error);
});
