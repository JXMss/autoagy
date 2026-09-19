import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeCommandLine,
  findDangerousCommand,
  isKnownSafeCommandLine,
  executableName,
  unwrapCommand,
  shellScriptOf,
} from '../plugin/lib/command-safety.mjs';
import { MAX_NESTING_DEPTH } from '../plugin/lib/shell.mjs';

const shq = (s) => `'${s.replace(/'/g, `'\\''`)}'`;
const kind = (cmd) => findDangerousCommand(cmd)?.kind ?? null;

// Cases ported from codex-rs/shell-command/src/command_safety/is_dangerous_command.rs
test('forced rm is dangerous (Codex parity)', () => {
  for (const cmd of [
    'rm -rf /',
    'rm -f /',
    '/bin/rm -fr /tmp/example',
    'rm -r -f /tmp/example',
    'rm --force /tmp/example',
    'rm /tmp/example -f',
    'sudo rm -rf /tmp/example',
    'env TARGET=/tmp/example rm -rf /tmp/example',
  ]) {
    assert.equal(kind(cmd), 'forced-rm', cmd);
  }
});

test('forced rm in complex shell syntax is dangerous (Codex parity)', () => {
  const scripts = [
    'printf x | rm -rf /tmp/example',
    'if test -d /tmp/example; then rm --force /tmp/example; fi',
    'rm -rf "$TARGET" >/dev/null',
    'for target in /tmp/a /tmp/b; do rm -r -f "$target"; done',
    'echo "$(rm -rf /tmp/example)"',
    "bash -c 'rm -rf /tmp/example'",
    "trap 'rm -rf /tmp/example' EXIT",
    `for a in '-C5a25KeRr' '--' '--json' '--bogus'; do HOME=$(mktemp -d) MDE_URL=http://127.0.0.1:1 MDE_TOKEN=x node cli/mde.cjs ls "$a" >/tmp/mde-review-out 2>/tmp/mde-review-err; code=$?; printf '%s\\t%s\\t%s\\n' "$a" "$code" "$(tr '\\n' ' ' </tmp/mde-review-err)"; rm -rf "$HOME"; done`,
  ];
  for (const script of scripts) {
    assert.equal(kind(script), 'forced-rm', script);
    // The same script wrapped the way Codex receives it.
    assert.equal(kind(`bash -lc ${shq(script)}`), 'forced-rm', `bash -lc ${script}`);
  }
});

test('non-forced or non-literal rm is not dangerous (Codex parity)', () => {
  for (const cmd of [
    'rm -r /tmp/example',
    'rm -- -f',
    `bash -lc ${shq("echo 'rm -rf /tmp/example'")}`,
    'cmd=rm; $cmd -rf /tmp/example',
    'env TARGET=/tmp/example rm -r /tmp/example',
    `trap ${shq('echo rm -rf /tmp/example')} EXIT`,
  ]) {
    assert.equal(kind(cmd), null, cmd);
  }
});

test('deeply nested command wrappers fail closed (Codex parity)', () => {
  const wrap = (n) => `${'env '.repeat(n)}rm -rf /tmp/example`;
  assert.equal(kind(wrap(MAX_NESTING_DEPTH)), 'forced-rm');
  assert.equal(kind(wrap(MAX_NESTING_DEPTH + 1)), 'too-deep');
});

test('destructive git commands are flagged (Antigravity sandbox does not protect .git)', () => {
  for (const cmd of [
    'git reset --hard HEAD~1',
    'git -C repo reset --hard',
    'git clean -fdx',
    'git clean --force',
    'git checkout -- src/app.js',
    'git checkout .',
    'git restore src/app.js',
    'git restore --staged --worktree x',
    'git stash drop',
    'git stash clear',
    'git branch -D feature',
    'git reflog expire --expire=now --all',
    'git gc --prune=now',
    'git filter-branch --tree-filter x',
    'git push --force origin main',
    'git push origin :old-branch',
  ]) {
    assert.equal(kind(cmd), 'git-destructive', cmd);
  }
  for (const cmd of ['git status', 'git checkout -b feature', 'git checkout main', 'git restore --staged x', 'git stash', 'git branch -d merged', 'git push origin feature', 'git commit -am wip']) {
    assert.equal(kind(cmd), null, cmd);
  }
});

test('other destructive tools are flagged', () => {
  assert.equal(kind('find . -name "*.o" -delete'), 'find-delete');
  assert.equal(kind('find . -name x -exec rm -f {} ;'), 'forced-rm');
  assert.equal(kind('ls | xargs rm -f'), 'forced-rm');
  assert.equal(kind('shred -u secret.txt'), 'disk-destructive');
  assert.equal(kind('dd if=/dev/zero of=disk.img bs=1M count=1'), 'dd-write');
  assert.equal(kind('mkfs.ext4 /dev/sdb1'), 'disk-destructive');
  assert.equal(kind('truncate -s 0 app.log'), 'truncate');
  assert.equal(kind('timeout 10 nohup rm -rf build'), 'forced-rm');
  assert.equal(kind("sh -c 'cd /tmp && rm -rf x'"), 'forced-rm');
  assert.equal(kind('bash <<EOF\nrm -rf /tmp/x\nEOF'), 'forced-rm');
  assert.equal(kind("bash <<< 'rm -rf /tmp/x'"), 'forced-rm');
  assert.equal(kind('eval "rm -rf /tmp/x"'), 'forced-rm');
});

test('Windows removal commands are flagged', () => {
  assert.equal(kind('Remove-Item -Recurse -Force .\\build'), 'forced-rm');
  assert.equal(kind('rd /s /q build'), 'forced-rm');
  assert.equal(kind('del /f file.txt'), 'forced-rm');
});

test('known-safe read-only command lines', () => {
  for (const cmd of [
    'ls -la',
    'git status',
    'git log --oneline -10',
    'git diff HEAD~1 -- src',
    'git -C sub status',
    'git branch --show-current',
    'git branch -a',
    'git remote -v',
    'cat README.md | wc -l',
    'ls && pwd',
    'echo hi 2>/dev/null',
    'grep -rn TODO src 2>&1',
    'find . -name "*.js" -type f',
    'rg -n hello',
    'sed -n 1,5p file.txt',
    "sed -n '10p' file.txt",
    'head -n 20 a.txt; tail -n 5 b.txt',
    'node --version',
    'python3 --version',
    'env',
    'timeout 5 ls',
    "bash -lc 'ls && git status'",
    'cd src && ls',
  ]) {
    assert.equal(isKnownSafeCommandLine(cmd), true, cmd);
  }
});

test('commands that are not known-safe', () => {
  for (const cmd of [
    'find . -name file.txt -exec rm {} ;',
    'find . -delete',
    'find . -fprint out.txt',
    'rg --pre pwned files',
    'rg --search-zip x',
    'git -c core.pager=evil log',
    'git push',
    'git branch newbranch',
    'git branch -d old',
    'git diff --output=/tmp/x',
    'git config user.name x',
    'sed -i s/a/b/ f',
    'sed -n 1p a b c d',
    'echo hi > out.txt',
    'ls $(pwd)',
    'ls; rm x',
    'node app.js',
    'python3 script.py',
    'curl https://example.com',
    'sort -o out.txt in.txt',
    'uniq in.txt out.txt',
    'FOO=1 ls',
    '$CMD',
    'sleep 5 &',
    'npm install',
    'awk \'{print > "f"}\' x',
    "bash -lc 'ls; rm -f x'",
  ]) {
    assert.equal(isKnownSafeCommandLine(cmd), false, cmd);
  }
});

test('helpers', () => {
  assert.equal(executableName('/usr/bin/git'), 'git');
  assert.equal(executableName('C:\\Windows\\System32\\cmd.exe'), 'cmd');
  assert.deepEqual(unwrapCommand(['sudo', '-u', 'root', 'ls', '-l']), ['ls', '-l']);
  assert.deepEqual(unwrapCommand(['env', '-i', 'A=1', 'B=2', 'node', 'x']), ['node', 'x']);
  assert.deepEqual(unwrapCommand(['timeout', '-s', 'KILL', '30', 'make']), ['make']);
  assert.equal(unwrapCommand(['ls']), null);
  assert.equal(shellScriptOf(['bash', '-lc', 'echo hi']), 'echo hi');
  assert.equal(shellScriptOf(['bash', 'script.sh']), null);
  assert.equal(shellScriptOf(['zsh', '-x', '-c', 'id']), 'id');
  const analysis = analyzeCommandLine("sudo bash -c 'git status && rm -rf x'");
  const argvs = analysis.segments.map((s) => s.argv.join(' '));
  assert.ok(argvs.includes('git status'));
  assert.ok(argvs.includes('rm -rf x'));
});
