import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeCommandLine,
  findDangerousCommand,
  isKnownSafeCommandLine,
  executableName,
  unwrapCommand,
  shellScriptOf,
  printsEnvironment,
  printedVariableNames,
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

// GNU getopt_long and git's parse-options accept clustered short flags and any
// unambiguous prefix of a long option. The table compared exact strings, so the
// everyday `git rm -rf src` and the deliberate `rm --forc -r src` both ran
// inside the sandbox without a review, as did the rest of this list.
test('a destructive flag is found however it is clustered or abbreviated', () => {
  for (const [cmd, expected] of [
    ['rm --forc -r src', 'forced-rm'],
    ['rm --f x', 'forced-rm'],
    ['git rm -rf src', 'git-destructive'],
    ['git reset --har', 'git-destructive'],
    ['git clean --forc', 'git-destructive'],
    ['git branch -df old', 'git-destructive'],
    ['git branch --del --forc old', 'git-destructive'],
    ['git push -fu origin main', 'git-destructive'],
    ['git switch -fc topic', 'git-destructive'],
    ['git checkout -fq main', 'git-destructive'],
    ['git restore --work f', 'git-destructive'],
    ['git gc --pru=now', 'git-destructive'],
    ['truncate --siz 0 app.log', 'truncate'],
    ['truncate -cs 0 app.log', 'truncate'],
    // Value-taking options that run a command, in the same spellings.
    ['su -lc "rm -rf /x"', 'forced-rm'],
    ['su --comm="rm -rf /x"', 'forced-rm'],
    ["script -qc 'rm -rf /x' /dev/null", 'forced-rm'],
    ["script --command='rm -rf /x' /dev/null", 'forced-rm'],
  ]) {
    assert.equal(kind(cmd), expected, cmd);
  }
  // And nothing that was not destructive becomes so.
  for (const cmd of [
    'git push --force-with-lease',
    'git push origin main',
    'git restore --sta f',
    'git reset --mixed',
    'git branch -d merged',
    'git checkout -b feature',
    'git clean -n',
    'rm -r build',
    "script -c 'ls' /dev/null",
  ]) {
    assert.equal(kind(cmd), null, cmd);
  }
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
    'timeout 5 ls',
    "bash -lc 'ls && git status'",
    'cd src && ls',
    'env -i ls',
    // `ps` and `jq` stay read-only, but only in the argument shapes that cannot
    // print the environment.
    'ps -ef',
    'ps aux',
    'ps -eo pid,cmd',
    'jq . data.json',
    "jq -r '.vendor' data.json",
    "jq -r '.environment' data.json",
    'Get-ChildItem C:\\Users',
    'Get-Content README.md',
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
    // These are read-only, but this list is what runs unreviewed where
    // autoagy's own sandbox is not in force, and the hook inherits agy's
    // environment — the user's exported API keys. There is no `--clearenv`
    // there, so printing the environment, or naming a value the line does not
    // spell out, must go to the reviewer.
    'env',
    'printenv',
    'echo $GEMINI_API_KEY',
    'echo "$HOME"',
    'cat $FILE',
    // The same environment, printed by a read-only tool whose argument asks for
    // it. `ps -ef` above is "every process", which is why these are word
    // matches rather than a search for the letter `e`.
    'ps auxe',
    'ps eww',
    'ps -E',
    'ps -o env',
    'ps -eo pid,environ',
    'jq -n env',
    "jq -n 'env|keys'",
    "jq -r 'env.SECRET' data.json",
    // `$ENV` is the same environment spelled in capitals — and single quotes
    // make it a literal, so the variable rule above does not see it.
    "jq -rn '$ENV'",
    "jq -n '$ENV.SECRET'",
    // PowerShell names the environment as a provider, with no variable at all.
    'Get-ChildItem Env:',
    'Get-ChildItem -Path Env:',
    'Get-ChildItem env*',
    'Get-Content Env:PATH',
  ]) {
    assert.equal(isKnownSafeCommandLine(cmd), false, cmd);
  }
});

// Where nothing confines a command, this list is what runs unreviewed, so it
// has to run nothing the workspace controls — and a workspace file is edited
// without review. `node help` and `python3 version` execute a file of that name
// (measured), `make help` a Makefile target, `cargo check` the crate's
// `build.rs`, and each of the others starts from a project file or names a
// program to run.
test('probes that run workspace content are not known-safe', () => {
  for (const cmd of [
    'node help', 'python3 version', 'ruby help', 'php version', 'java help',
    'make help', 'gradle help', 'gradle --version', 'mvn --version',
    'cargo check', 'cargo --version', 'rustc --version', 'dotnet --version',
    'yarn --version', 'yarn version', 'pnpm ls',
    'go env -w GOFLAGS=-toolexec=./x', 'go env -u GOFLAGS', 'go vet -vettool=./x ./...', 'go list -export -toolexec=./x ./...',
  ]) {
    assert.equal(isKnownSafeCommandLine(cmd), false, cmd);
  }
  for (const cmd of ['node --version', 'python3 -V', 'make --version', 'git --version', 'go version', 'go help', 'go env GOPATH', 'go vet ./...', 'docker version', 'npm help', 'npm ls', 'gh help']) {
    assert.equal(isKnownSafeCommandLine(cmd), true, cmd);
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

test('commands that hand over the process environment', () => {
  const says = (cmd) => Boolean(printsEnvironment(analyzeCommandLine(cmd).segments[0].argv));
  for (const cmd of ['printenv', 'printenv PATH', 'env', 'env -u FOO', 'ps auxe', 'ps eww', 'ps -E', 'ps -o pid,env', 'jq env', "jq -rn '$ENV'"]) {
    assert.equal(says(cmd), true, cmd);
  }
  // Read-only uses of the same tools, and the forms that run something else or
  // start from an empty environment, are not.
  for (const cmd of ['env -i', 'env -i ls', 'env A=1 ls', 'ls', 'ps -ef', 'ps aux', 'jq . file.json', 'jq .environment x']) {
    assert.equal(says(cmd), false, cmd);
  }
});

test('routes to the environment that name no $NAME at all', () => {
  // Each of these dumps or reads the environment without the shell expanding
  // anything, so the variable rule in the policy cannot see them: `busybox env`
  // is one word as far as `executableName` is concerned, the builtins print what
  // is already in the shell, and the interpreters read it from inside their own
  // argument.
  const says = (cmd) => Boolean(printsEnvironment(analyzeCommandLine(cmd).segments[0].argv));
  const reads = [
    'declare -x', 'declare -p', 'typeset -x', 'typeset -xp',
    'export -p', 'export', 'set', 'compgen -e', 'compgen -v',
    'busybox env', 'busybox printenv', 'toybox env',
    'node -p process.env.OPENAI_API_KEY', "node -e 'console.log(process.env.X)'", 'node --eval="getenv(\'X\')"',
    'python3 -c "import os;print(os.environ)"', 'python3 -c "import os;print(os.getenv(\'X\'))"',
    "ruby -e 'puts ENV.to_h'", "perl -e 'print $ENV{OPENAI_API_KEY}'", "php -r 'echo getenv(\"X\");'",
    "awk 'BEGIN{print ENVIRON[\"OPENAI_API_KEY\"]}'",
  ];
  for (const cmd of reads) assert.equal(says(cmd), true, cmd);

  // What must keep working: setting one variable is not reading the
  // environment, and neither is a version probe, a word that merely contains
  // "env", or an option that prints something else entirely.
  const silent = [
    'export FOO=bar', 'declare -i x=1', 'set -e', 'compgen -c', 'ls',
    'node --version', 'node -e "const ENV=1"', "node -e \"process.env.NODE_ENV='test'\"",
    "python3 -c \"os.environ['X']='1'\"", "python3 -c \"print('environment')\"",
    'awk -F, "{print $1}" f.csv', "ruby -e 'puts 1'", "perl -e 'print 1'",
  ];
  for (const cmd of silent) assert.equal(says(cmd), false, cmd);
});

test('a multi-call binary is unwrapped, so the applet is what gets judged', () => {
  // `busybox` is one binary with the applet as its first argument, so every
  // consumer that only looks at the command name sees nothing. Unwrapping is
  // what makes the applet reachable — but deliberately only for the analysis,
  // not for `isKnownSafeCommandLine`: widening the allowlist is not the point.
  const argv = (cmd) => analyzeCommandLine(cmd).segments.map((s) => s.argv.join(' '));
  assert.deepEqual(argv('busybox rm -rf /'), ['busybox rm -rf /', 'rm -rf /']);
  assert.ok(findDangerousCommand(analyzeCommandLine('busybox rm -rf /')), 'the applet reaches the dangerous table');
  assert.ok(findDangerousCommand(analyzeCommandLine('busybox sh -c "rm -rf /"')), 'and through a shell the applet starts');
  assert.equal(findDangerousCommand(analyzeCommandLine('busybox ls -l')), null);
  assert.equal(isKnownSafeCommandLine('busybox ls -l'), false, 'an applet is not waved through by name');
});

test('the variables a command line expands are collected through every nesting', () => {
  const names = (cmd) => [...analyzeCommandLine(cmd).variables].sort();
  // A nested script hides the reference from the outer line; the analysis follows it.
  assert.deepEqual(names(`bash -c 'echo $SECRET'`), ['SECRET']);
  assert.deepEqual(names(`sudo env A=1 sh -c "printf %s ${'${SECRET}'}"`), ['SECRET']);
  assert.deepEqual(names('cat <<EOF\n$SECRET\nEOF\n'), ['SECRET']);
  assert.deepEqual(names('echo hello'), []);
});

test('a builtin asked to print one variable names it as a bare argument', () => {
  const names = (cmd) => printedVariableNames(analyzeCommandLine(cmd).segments[0].argv);
  // `declare -p NAME` prints `declare -x NAME="<value>"`, and nothing on the
  // line is a `$NAME` for the variable rule to see.
  assert.deepEqual(names('declare -p OPENAI_API_KEY'), ['OPENAI_API_KEY']);
  assert.deepEqual(names('typeset -p OPENAI_API_KEY'), ['OPENAI_API_KEY']);
  assert.deepEqual(names('export -p OPENAI_API_KEY'), ['OPENAI_API_KEY']);
  assert.deepEqual(names('declare -px A B'), ['A', 'B']);
  // Without `-p` they only declare, and the no-argument forms dump everything
  // and are `printsEnvironment`'s business rather than this one's.
  assert.deepEqual(names('declare OPENAI_API_KEY'), []);
  assert.deepEqual(names('export OPENAI_API_KEY'), []);
  assert.deepEqual(names('export FOO=bar'), []);
  assert.deepEqual(names('declare -p'), []);
  assert.deepEqual(names('ls -p'), []);
});
