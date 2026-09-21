import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { detectOwnSandbox, confinedCommandLine, scrubbedCommandLine, probeBwrap, readOnlyPaths, readSandboxCheck, removeControlPlaceholders, sandboxEnv, lockQuiescent, workspaceLockFile, flockPath, envBinaryPath, sandboxStartCheck } from '../plugin/lib/confine.mjs';
import { seccompProgram, seccompSupported } from '../plugin/lib/seccomp.mjs';
import { HookContext, PROTECTED_WORKSPACE_DIRS, findNestedGitPaths } from '../plugin/lib/context.mjs';
import { handlePreToolUse, handlePostToolUse, handlePostInvocation } from '../plugin/lib/hook.mjs';
import { parseShell } from '../plugin/lib/shell.mjs';
import { classify } from '../plugin/lib/policy.mjs';
import { readState, updateState } from '../plugin/lib/state.mjs';
import { readDecisions } from '../plugin/lib/log.mjs';
import { installExecutor, executorPath, tokenDir } from '../plugin/lib/tokens.mjs';
import { makeSandboxDirs, configWith, payloadFor, contextFor, linuxOnly } from './helpers.mjs';

const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

const okProbe = () => ({ ok: true, bwrap: '/usr/bin/bwrap', detail: 'test' });
const failProbe = () => ({ ok: false, detail: 'no user namespaces' });
const cliHost = (flags = {}) => ({ kind: 'cli', cwd: dirs.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [], ...flags } });

function grant(on) {
  const settings = { enableTerminalSandbox: true, toolPermission: 'proceed-in-sandbox' };
  if (on) settings.permissions = { allow: ['command(*)'] };
  fs.writeFileSync(path.join(dirs.appData, 'settings.json'), JSON.stringify(settings));
}

function ctxFor(args, { ownSandbox = 'on', probe = okProbe, tempRoots = [dirs.tmp], env = dirs.env } = {}) {
  return new HookContext(payloadFor(dirs, 'run_command', args), {
    config: configWith({ ownSandbox }),
    env,
    home: dirs.home,
    host: cliHost(),
    tempRoots,
    bwrapProbe: probe,
  });
}

/** Runs a command line through /bin/sh and returns the result. */
function runLine(line, env) {
  return spawnSync('/bin/sh', ['-c', line], { cwd: dirs.workspace, encoding: 'utf8', env });
}

test('own sandbox activation: auto needs Linux, bubblewrap and the command grant', () => {
  const detect = (config, extra = {}) =>
    detectOwnSandbox({ config: configWith(config), host: cliHost(), appDataDir: dirs.appData, autoagyHome: dirs.env.AUTOAGY_HOME, platform: 'linux', probe: okProbe, ...extra });
  grant(false);
  assert.equal(detect({ ownSandbox: 'auto' }).active, false);
  assert.match(detect({ ownSandbox: 'auto' }).detail, /command\(\*\) is not granted/);
  assert.equal(detect({ ownSandbox: 'auto' }, { host: cliHost({ skipPermissions: true }) }).active, true);
  grant(true);
  assert.equal(detect({ ownSandbox: 'auto' }).active, true);
  assert.equal(detect({ ownSandbox: 'off' }).active, false);
  assert.equal(detect({ ownSandbox: 'auto' }, { platform: 'darwin' }).active, false);
  assert.deepEqual(
    [detect({ ownSandbox: 'auto' }, { probe: failProbe }).active, detect({ ownSandbox: 'auto' }, { probe: failProbe }).required],
    [false, false],
  );
  grant(false);
  // "on" does not wait for the grant, and fails closed without bubblewrap.
  assert.equal(detect({ ownSandbox: 'on' }).active, true);
  const unavailable = detect({ ownSandbox: 'on' }, { probe: failProbe });
  assert.deepEqual([unavailable.active, unavailable.required], [false, true]);
});

test('a required but unavailable own sandbox makes commands count as unsandboxed', { skip: linuxOnly }, () => {
  const ctx = ctxFor({ CommandLine: 'ls' }, { probe: failProbe });
  assert.equal(ctx.sandbox.active, false);
  assert.match(ctx.sandbox.detail, /ownSandbox is "on" but unavailable: no user namespaces/);
  assert.equal(ctxFor({ CommandLine: 'ls' }).sandbox.source, 'autoagy');
});

test('the confined command mounts read-only paths over writable roots and keeps the command intact', { skip: linuxOnly }, () => {
  const original = `echo "it's $HOME" && printf '%s\\n' 'a b' > out.txt; cat <<'EOF'\n$(not run)\nEOF`;
  const ctx = ctxFor({ CommandLine: original });
  const line = confinedCommandLine(ctx, original);
  const parsed = parseShell(line);
  assert.equal(parsed.error, null);
  const argv = parsed.commands[0].argv;
  assert.equal(argv[0], 'exec');
  // The chain starts with an empty environment: bwrap stays in the sandbox as
  // PID 1, and --clearenv never reaches it.
  assert.deepEqual(argv.slice(1, 3), [envBinaryPath(), '-i']);
  // The command holds a shared lock on the workspace while bwrap runs, so a
  // reclamation knows whether anything is still alive. See lockQuiescent. Only
  // where a root-owned flock exists; without one bwrap follows directly.
  let at = 3;
  if (flockPath()) {
    assert.equal(argv[3], flockPath());
    assert.equal(argv[4], '-s');
    assert.match(argv[5], /\/state\/ws-[0-9a-f]{16}\.lock$/);
    at = 6;
  }
  assert.equal(argv[at], '/usr/bin/bwrap');
  assert.ok(argv.includes('--unshare-net'));
  assert.deepEqual(argv.slice(-2), ['-c', original], 'the original command is passed through byte for byte');
  const mountIndex = (flag, p) => argv.findIndex((a, i) => a === flag && argv[i + 1] === p && argv[i + 2] === p);
  const workspaceRw = mountIndex('--bind-try', dirs.workspace);
  const gitRo = mountIndex('--ro-bind-try', path.join(dirs.workspace, '.git'));
  const logsRo = mountIndex('--ro-bind-try', path.dirname(dirs.transcriptPath));
  const artifactRw = mountIndex('--bind-try', dirs.brain);
  assert.ok(workspaceRw > 0 && gitRo > workspaceRw, '.git is read-only on top of the workspace');
  assert.ok(artifactRw > 0 && logsRo > artifactRw, 'conversation logs are read-only on top of the artifact dir');
  assert.ok(readOnlyPaths(ctx).includes(dirs.env.AUTOAGY_HOME));
  // Credential stores in the home directory are hidden, after everything else.
  const ssh = argv.findIndex((a, i) => a === '--tmpfs' && argv[i + 1] === path.join(dirs.home, '.ssh'));
  assert.ok(ssh > logsRo, 'the credential store is hidden on top of the other mounts');
});

test('inside the own sandbox a command naming a credential store needs no review: the store is hidden', { skip: linuxOnly }, () => {
  assert.equal(classify(ctxFor({ CommandLine: 'cat ~/.ssh/id_ed25519' })).category, 'sandboxed-command');
  assert.equal(classify(ctxFor({ CommandLine: 'cat ~/.ssh/id_ed25519', BypassSandbox: true })).category, 'sandbox-escalation');
});

test('allowed sandboxed commands are rewritten into the own sandbox; escalations and denials are not', { skip: linuxOnly }, async () => {
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  const run = (args, mock = 'allow') => {
    const config = { ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: mock } } };
    fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify(config));
    return handlePreToolUse(payloadFor(dirs, 'run_command', args), { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe });
  };
  const sandboxed = await run({ CommandLine: 'npm test' });
  assert.equal(sandboxed.decision, 'allow');
  assert.equal(sandboxed.overwrite.BypassSandbox, true);
  const launcher = [envBinaryPath(), '-i', ...(flockPath() ? [flockPath(), '-s'] : [])].map((a) => `'${a}'`).join(' ');
  assert.ok(sandboxed.overwrite.CommandLine.startsWith(`exec ${launcher} `), sandboxed.overwrite.CommandLine.slice(0, 120));
  assert.match(sandboxed.overwrite.CommandLine, flockPath() ? /^\S+ \S+ '-i' \S+ '-s' '\S+ws-[0-9a-f]{16}\.lock' '\/usr\/bin\/bwrap' / : /^\S+ \S+ '-i' '\/usr\/bin\/bwrap' /);
  // Reviewed inside the sandbox (forced rm), approved, and still confined.
  const reviewed = await run({ CommandLine: 'rm -rf build' });
  assert.equal(reviewed.decision, 'allow');
  assert.ok(reviewed.overwrite);
  // An escalation the reviewer approves runs as requested, outside any sandbox.
  const escalated = await run({ CommandLine: 'npm install', BypassSandbox: true });
  assert.equal(escalated.decision, 'allow');
  assert.equal(escalated.overwrite, undefined);
  const denied = await run({ CommandLine: 'rm -rf build' }, 'deny');
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.overwrite, undefined);

  // What the nested-repository walk cost is recorded with the rest of the
  // command's facts. It was computed and returned from the moment the walk got a
  // time bound, and read by nothing — so a truncated scan, which is the state a
  // slow filesystem is permanently in, left the protection partial with no way to
  // find out. `autoagy status` reports it from here.
  const scan = readState(dirs.env.AUTOAGY_HOME, dirs.conversationId).nestedScan;
  assert.equal(typeof scan.visited, 'number');
  assert.ok(scan.visited > 0, 'the walk that built the mount list is the one reported');
  assert.equal(typeof scan.truncated, 'boolean');
  assert.match(scan.at, /^\d{4}-\d\d-\d\dT/);
  fs.rmSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'));
});

const real = process.platform === 'linux' ? probeBwrap(dirs.env.AUTOAGY_HOME) : { ok: false };

test('bubblewrap enforces the policy', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
  const script = [
    'echo ok > file.txt && echo WORKSPACE=rw',
    'echo x > .git/hooks/pre-push 2>/dev/null && echo GIT=rw || echo GIT=ro',
    `echo x >> ${JSON.stringify(dirs.transcriptPath)} 2>/dev/null && echo LOG=rw || echo LOG=ro`,
    `touch ${JSON.stringify(path.join(dirs.brain, 'task.md'))} 2>/dev/null && echo ARTIFACT=rw || echo ARTIFACT=ro`,
    `touch ${JSON.stringify(path.join(dirs.env.AUTOAGY_HOME, 'x'))} 2>/dev/null && echo SELF=rw || echo SELF=ro`,
    `touch ${JSON.stringify(path.join(dirs.home, 'x'))} 2>/dev/null && echo HOME=rw || echo HOME=ro`,
    `touch ${JSON.stringify(path.join(dirs.tmp, 'x'))} 2>/dev/null && echo TMP=rw || echo TMP=ro`,
    '(exec 3<>/dev/tcp/1.1.1.1/53) 2>/dev/null && echo NET=open || echo NET=closed',
    `printf '%s' "it's" > quoted.txt`,
    `test -e ${JSON.stringify(path.join(dirs.home, '.ssh', 'id_ed25519'))} && echo CRED=visible || echo CRED=hidden`,
  ].join('; ');
  fs.writeFileSync(path.join(dirs.home, '.ssh', 'id_ed25519'), 'placeholder');
  fs.mkdirSync(path.join(dirs.workspace, '.git', 'hooks'), { recursive: true });
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(dirs.transcriptPath, '');
  const placeholders = [];
  const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, script, { placeholders })], { cwd: dirs.workspace, encoding: 'utf8' });
  removeControlPlaceholders(placeholders);
  assert.equal(res.status, 0, res.stderr);
  const got = Object.fromEntries(res.stdout.trim().split('\n').map((l) => l.split('=')));
  assert.deepEqual(got, { WORKSPACE: 'rw', GIT: 'ro', LOG: 'ro', ARTIFACT: 'rw', SELF: 'ro', HOME: 'ro', TMP: 'rw', NET: 'closed', CRED: 'hidden' });
  assert.equal(fs.readFileSync(path.join(dirs.workspace, 'quoted.txt'), 'utf8'), "it's");
  assert.equal(fs.readFileSync(dirs.transcriptPath, 'utf8'), '');
});

test('self-check: when agy ignores the rewrite, the own sandbox is switched off for that build, with one notice', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  const configure = (config) => fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(config));
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const pre = (args, stepIdx) => handlePreToolUse(payloadFor(dirs, 'run_command', args, { stepIdx }), opts);
  const post = (args, stepIdx) => handlePostToolUse(payloadFor(dirs, 'run_command', args, { stepIdx }), opts);
  grant(true);
  configure({ ownSandbox: 'auto' });

  // agy ran exactly what autoagy asked for.
  const first = await pre({ CommandLine: 'npm test' }, 10);
  assert.deepEqual(post(first.overwrite, 10), {});
  assert.deepEqual([readSandboxCheck(home).status, readSandboxCheck(home).verified], ['verified', 1]);

  // agy ignored the rewrite and ran the original command.
  const second = await pre({ CommandLine: 'npm test' }, 12);
  assert.ok(second.overwrite);
  post({ CommandLine: 'npm test' }, 12);
  assert.equal(readSandboxCheck(home).status, 'broken');
  assert.match(readSandboxCheck(home).detail, /original command/);

  // The next command is refused once with an explanation; after that, Antigravity's sandbox without a rewrite.
  const notice = await pre({ CommandLine: 'npm test' }, 14);
  assert.equal(notice.decision, 'deny');
  assert.match(notice.reason, /self-check/);
  assert.deepEqual(await pre({ CommandLine: 'npm test' }, 16), { decision: 'allow' });

  // With ownSandbox "on", the failure fails closed: commands are no longer treated as sandboxed.
  configure({ ownSandbox: 'on', reviewer: { backend: 'none' } });
  assert.equal((await pre({ CommandLine: 'npm test' }, 18)).decision, 'force_ask');

  // Another agy build (after an update) is checked again.
  const other = detectOwnSandbox({ config: configWith({ ownSandbox: 'on' }), host: cliHost(), appDataDir: dirs.appData, autoagyHome: home, build: 'another-build', platform: 'linux', probe: okProbe });
  assert.equal(other.active, true);
  // Commands the agent escalated itself are never rewritten, so they are not checked.
  configure({ ownSandbox: 'auto' });
  assert.deepEqual(post({ CommandLine: 'npm install', BypassSandbox: true }, 20), {});

  fs.rmSync(path.join(home, 'state', 'own-sandbox-check.json'));
  fs.rmSync(path.join(home, 'config.json'));
  grant(false);
});

test('the seccomp filter is assembled for this architecture and denies with EPERM', () => {
  assert.equal(seccompSupported(), true, `no filter for ${process.arch}`);
  const program = seccompProgram();
  assert.equal(program.length % 8, 0);
  const instructions = [];
  for (let i = 0; i < program.length; i += 8) {
    instructions.push({ code: program.readUInt16LE(i), jt: program.readUInt8(i + 2), jf: program.readUInt8(i + 3), k: program.readUInt32LE(i + 4) });
  }
  // cBPF jump offsets are one byte, so the program has to stay well under 255.
  assert.ok(instructions.length < 255, `${instructions.length} instructions`);
  const returns = instructions.filter((i) => i.code === 0x06).map((i) => i.k).sort();
  assert.deepEqual(
    returns,
    [0x7fff0000 | 0, 0x00050000 | 1, 0x80000000].map((v) => v >>> 0).sort(),
    'default allow, EPERM for a denied call, kill for another architecture',
  );
  const loaded = new Set(instructions.filter((i) => i.code === 0x20).map((i) => i.k));
  assert.deepEqual([...loaded].sort((a, b) => a - b), [0, 4, 16], 'syscall number, arch, and socket domain');
  const compared = instructions.filter((i) => i.code === 0x15).map((i) => i.k);
  assert.ok(compared.includes(0xc000003e), 'guard on the audit architecture');
  assert.ok(compared.includes(41) && compared.includes(53), 'socket and socketpair are argument-checked');
  assert.ok(compared.includes(101) && compared.includes(310), 'ptrace and process_vm_readv are denied outright');
  assert.ok(compared.includes(46), 'sendmsg is denied: an unconnected datagram socket takes its destination in the message header');
  // The x32 ABI on x86-64 is marked by bit 30 of the syscall *number*, not by
  // the arch field, so an equality table never sees it and the call is allowed
  // — `socket(AF_INET)` was measured returning a descriptor inside a real bwrap.
  // The refusal is therefore a bit test, and it belongs to x86-64 alone.
  const x64 = seccompProgram('x64');
  const x64Instr = [];
  for (let i = 0; i < x64.length; i += 8) x64Instr.push({ code: x64.readUInt16LE(i), k: x64.readUInt32LE(i + 4) });
  assert.ok(x64Instr.some((i) => i.code === 0x45 && i.k === 0x40000000), 'x86-64 refuses the x32 syscall-number bit');
  const arm = seccompProgram('arm64');
  const armInstr = [];
  for (let i = 0; i < arm.length; i += 8) armInstr.push({ code: arm.readUInt16LE(i), k: arm.readUInt32LE(i + 4) });
  assert.ok(!armInstr.some((i) => i.code === 0x45), 'aarch64 has no x32 ABI to refuse');
  assert.ok(armInstr.some((i) => i.code === 0x15 && i.k === 211), 'the syscall tables are per architecture (aarch64 sendmsg)');
  assert.throws(() => seccompProgram('s390x'), /no seccomp filter/);
});

test('the x32 alias and sendmsg are refused inside the real sandbox', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // Measured, not reasoned: with this filter in place a 64-bit syscall is
  // refused and the same call with bit 30 set used to be *allowed* — one
  // `ctypes` call away from any command the sandbox was supposed to bound.
  // `sendmsg` was refused only after it was added to the deny list; `sendto`
  // was already there, so the pair is what the test pins.
  const probe = path.join(dirs.tmp, 'rawsyscalls.py');
  fs.writeFileSync(
    probe,
    [
      'import ctypes',
      'libc = ctypes.CDLL(None, use_errno=True)',
      'X32 = 0x40000000',
      'def call(nr, *a):',
      '    ctypes.set_errno(0)',
      '    r = libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(x) if isinstance(x, int) else x for x in a])',
      '    return r, ctypes.get_errno()',
      "fd, _ = call(41, 1, 1, 0)  # AF_UNIX, SOCK_STREAM: allowed by the filter",
      "sa = ctypes.create_string_buffer(b'/nonexistent-autoagy-probe\\x00', 30)",
      "print('X32_SOCKET', call(X32 | 41, 2, 1, 0)[1])",
      "print('X32_CONNECT', call(X32 | 42, fd, sa, 30)[1])",
      "print('X64_SOCKET', call(41, 2, 1, 0)[1])",
      'class IOV(ctypes.Structure): _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]',
      'class MSG(ctypes.Structure):',
      '    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint), ("iov", ctypes.POINTER(IOV)), ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t), ("flags", ctypes.c_int)]',
      'fd2, _ = call(41, 1, 2, 0)  # AF_UNIX, SOCK_DGRAM',
      'buf = ctypes.create_string_buffer(b"x")',
      'iov = IOV(ctypes.cast(buf, ctypes.c_void_p), 1)',
      'msg = MSG(ctypes.cast(sa, ctypes.c_void_p), 26, ctypes.pointer(iov), 1, None, 0, 0)',
      "print('SENDMSG', call(46, fd2, ctypes.byref(msg), 0)[1])",
      '',
    ].join('\n'),
  );
  if (spawnSync('python3', ['-c', 'pass']).status !== 0) {
    return; // no interpreter on this host that can make a raw syscall
  }
  const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
  const line = confinedCommandLine(ctx, `python3 ${JSON.stringify(probe)}`);
  const res = spawnSync('/bin/sh', ['-c', line], { cwd: dirs.workspace, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  const got = Object.fromEntries(res.stdout.trim().split('\n').map((l) => l.split(' ')));
  // EPERM is 1 both for the syscall the filter names and for the x32 alias of
  // one it does not: the point is that the second number was not a way around it.
  assert.deepEqual(got, { X32_SOCKET: '1', X32_CONNECT: '1', X64_SOCKET: '1', SENDMSG: '1' });
});

test('the own sandbox denies reaching a socket, which the read-only root bind does not', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
  const script = path.join(dirs.tmp, 'listen.mjs');
  fs.writeFileSync(
    script,
    `import net from 'node:net';\nconst s = net.createServer();\ns.on('error', (e) => { console.log('LISTEN=' + e.code); process.exit(0); });\ns.listen(${JSON.stringify(path.join(dirs.tmp, 'probe.sock'))}, () => { console.log('LISTEN=ok'); process.exit(0); });\n`,
  );
  const line = confinedCommandLine(ctx, `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`);
  assert.match(line, /'--seccomp' '3'/);
  assert.match(line, /'--unshare-ipc'/);
  assert.match(line, /'--new-session'/);
  const res = spawnSync('/bin/sh', ['-c', line], { cwd: dirs.workspace, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.trim(), 'LISTEN=EPERM');
});

test('a protected directory that does not exist cannot be created in the sandbox', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
  const target = path.join(dirs.workspace, '.agents');
  for (const d of PROTECTED_WORKSPACE_DIRS) fs.rmSync(path.join(dirs.workspace, d), { recursive: true, force: true });
  assert.equal(fs.existsSync(target), false);

  const placeholders = [];
  const line = confinedCommandLine(ctx, `mkdir ${JSON.stringify(target)} 2>/dev/null && echo MADE=yes || echo MADE=no`, { placeholders });
  assert.ok(placeholders.includes(target), `expected a mount point for ${target}`);
  const res = spawnSync('/bin/sh', ['-c', line], { cwd: dirs.workspace, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.trim(), 'MADE=no');
  assert.equal(fs.existsSync(target), true, 'the mount point is there for the command');

  // ...and taken away afterwards.
  removeControlPlaceholders(placeholders);
  assert.equal(fs.existsSync(target), false);
  fs.mkdirSync(path.join(dirs.workspace, '.git'), { recursive: true });
});

test('a program writing to a pipe keeps its output in the own sandbox', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // Denying the socket queries (`getsockopt`, `getsockname`, `getpeername`)
  // makes node drop everything it writes to a non-blocking pipe, which is how
  // libuv hands stdout to a child process and how a test runner reports its
  // results. The loss is silent, so it is checked here rather than trusted.
  const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
  const script = path.join(dirs.tmp, 'pipe.mjs');
  fs.writeFileSync(script, `process.stdout.write('PIPED-OUTPUT\\n');\nconsole.log('CONSOLE-LINE');\n`);
  const line = confinedCommandLine(ctx, `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`);
  const res = spawnSync('/bin/sh', ['-c', line], { cwd: dirs.workspace, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout, 'PIPED-OUTPUT\nCONSOLE-LINE\n');
});

test('the sandbox environment is an allowlist, and clears before it sets', () => {
  const env = {
    PATH: '/usr/bin:/bin',
    HOME: '/home/someone',
    OPENAI_API_KEY: 'sk-not-a-real-secret',
    SSH_AUTH_SOCK: '/run/ssh-agent.sock',
    NODE_OPTIONS: '--require /tmp/evil.js',
    LC_ALL: 'C.UTF-8',
    MY_APP_TOKEN: 'x',
  };
  assert.deepEqual(sandboxEnv(env).map(([name]) => name), ['HOME', 'LC_ALL', 'PATH']);
  assert.deepEqual(sandboxEnv(env, { passThrough: ['MY_APP_*'] }).map(([name]) => name), ['HOME', 'LC_ALL', 'MY_APP_TOKEN', 'PATH']);

  const argv = parseShell(confinedCommandLine(ctxFor({ CommandLine: 'true' }), 'true')).commands[0].argv;
  const clear = argv.indexOf('--clearenv');
  assert.ok(clear > 0, '--clearenv is passed');
  // bwrap applies these in order, so a later --clearenv would wipe the values.
  assert.ok(argv.every((a, i) => a !== '--setenv' || i > clear), '--clearenv comes before every --setenv');
  assert.ok(!argv.some((a) => a.includes('sk-not-a-real-secret') || a.includes('ssh-agent.sock')), 'no secret value reaches the command line');
});

test('PATH reaches the sandbox unchanged, including entries inside a writable root', () => {
  // Filtering those entries buys nothing here: the workspace is bound
  // read-write with exec unrestricted, so a sandboxed command runs any file in
  // it by path anyway — while dropping them breaks .venv/bin and
  // node_modules/.bin workflows and can pick the wrong interpreter.
  const mine = path.join(dirs.workspace, 'node_modules', '.bin');
  const pathVar = ['/usr/bin', mine, '/bin'].join(path.delimiter);
  assert.equal(sandboxEnv({ PATH: pathVar })[0][1], pathVar);
  const argv = parseShell(confinedCommandLine(ctxFor({ CommandLine: 'true' }), 'true')).commands[0].argv;
  const set = argv.findIndex((a, i) => a === '--setenv' && argv[i + 1] === 'PATH');
  assert.ok(set > 0);
  assert.equal(argv[set + 2], dirs.env.PATH, 'the hook\'s PATH is passed through verbatim');
});

test('a sandboxed command does not inherit the hook environment', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const out = path.join(dirs.workspace, 'canary-out');
  fs.rmSync(out, { force: true });
  const env = { ...dirs.env, AUTOAGY_CANARY_SECRET: 'leaked-value' };
  const script = `printf 'CANARY=%s\\n' "\${AUTOAGY_CANARY_SECRET:-unset}"; printf 'PATHOK=%s\\n' "$(command -v touch)"; touch ${JSON.stringify(out)}`;
  const res = runLine(confinedCommandLine(ctxFor({ CommandLine: 'true' }, { probe: () => real, env }), script), env);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /CANARY=unset/, 'the canary variable does not reach the sandbox');
  assert.match(res.stdout, /PATHOK=\/.*touch/, 'an external binary still resolves through the surviving PATH');
  assert.equal(fs.existsSync(out), true);
});

// `--clearenv` rebuilds the command's environment and nothing else. With
// `--unshare-pid` bwrap stays in the sandbox as PID 1, and the fresh /proc
// shows the command whatever bwrap itself was started with — which is agy's
// environment, every exported key included. The test above could not see that:
// it only asked the command about its own environment.
test('nothing in the sandbox\'s /proc carries the hook environment, PID 1 included', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const env = { ...dirs.env, AUTOAGY_CANARY_SECRET: 'leaked-value' };
  const script = [
    `printf 'PID1=%s\\n' "$(tr '\\0' ' ' < /proc/1/cmdline | cut -c1-200)"`,
    `printf 'PID1BYTES=%s\\n' "$(wc -c < /proc/1/environ)"`,
    `n=0; for f in /proc/[0-9]*/environ; do if tr '\\0' '\\n' < "$f" 2>/dev/null | grep -q AUTOAGY_CANARY_SECRET; then n=$((n+1)); fi; done; printf 'LEAKS=%s\\n' "$n"`,
  ].join('\n');
  const res = runLine(confinedCommandLine(ctxFor({ CommandLine: 'true' }, { probe: () => real, env }), script), env);
  assert.equal(res.status, 0, res.stderr);
  // Otherwise the rest of this proves nothing about the process that leaked.
  assert.match(res.stdout, /PID1=\S*bwrap /, 'PID 1 in the sandbox is bwrap itself');
  assert.match(res.stdout, /PID1BYTES=0\n/, 'bwrap was started with an empty environment');
  assert.match(res.stdout, /LEAKS=0\n/, 'no process the command can see holds the canary');
});

/**
 * Starts a process that holds the workspace's shared lock, as a live command
 * would. Detached, so it can be killed as a group: `flock -c` runs the command
 * as a child that inherits the locked descriptor, and killing only `flock`
 * would leave the lock held by the grandchild.
 */
function holdLock(lock) {
  return spawn(flockPath(), ['-s', lock, '-c', 'sleep 30'], { stdio: 'ignore', detached: true });
}

/** Waits until the workspace lock reports the given state, or gives up. */
async function untilQuiescent(probe, want, ms = 3000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (probe() === want) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

test('mount points are reclaimed only once no sandboxed command is running', { skip: linuxOnly || (flockPath() ? false : 'no trusted flock on this host') }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: 'allow' } } }));
  // Its own conversation: the state below is per-conversation and must not leak.
  const bg = { conversationId: '99999999-0000-4000-8000-ba6c6700d001', stepIdx: 40 };
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const target = path.join(dirs.workspace, '.agents');
  fs.rmSync(target, { recursive: true, force: true });
  const probe = () => lockQuiescent(ctxFor({ CommandLine: 'ls' }));
  const lock = workspaceLockFile(ctxFor({ CommandLine: 'ls' }));

  // IsDaemon is how agy marks a command expected to run indefinitely, and its
  // own tool description says not to combine it with WaitMsBeforeAsync — so a
  // dev server is exactly the case a wait-value check would miss.
  const started = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'npm run dev', IsDaemon: true }, bg), opts);
  assert.equal(started.decision, 'allow');
  assert.equal(fs.existsSync(target), true, 'created for the command');

  const holder = holdLock(lock);
  try {
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(probe(), false, 'the lock sees a command running');
    // Neither the tool call returning nor reaching PostInvocation is evidence
    // that it finished — the lock is, and it is still held.
    assert.deepEqual(handlePostToolUse(payloadFor(dirs, 'run_command', started.overwrite, bg), opts), {});
    assert.equal(fs.existsSync(target), true, 'kept while a command runs');
    handlePostInvocation({ conversationId: bg.conversationId }, opts);
    assert.equal(fs.existsSync(target), true, 'still kept at PostInvocation');
  } finally {
    try {
      process.kill(-holder.pid, 'SIGKILL');
    } catch {
      // already gone
    }
  }
  assert.equal(await untilQuiescent(probe, true), true, 'the lock is free again');
  handlePostInvocation({ conversationId: bg.conversationId }, opts);
  assert.equal(fs.existsSync(target), false, 'reclaimed once nothing is running');
  fs.rmSync(path.join(home, 'config.json'));
});

test('a daemon command is noted as possibly still running even without WaitMsBeforeAsync', async () => {
  // The lock is the precise signal; this flag is what remains on a host with no
  // trusted flock, so it still has to notice the documented daemon case.
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: 'allow' } } }));
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const cases = [
    [1, { CommandLine: 'npm run dev', IsDaemon: true }],
    [2, { CommandLine: 'npm test', Blocking: false }],
    [3, { CommandLine: 'npm test', WaitMsBeforeAsync: 5000 }],
  ];
  for (const [n, args] of cases) {
    const conversationId = `99999999-0000-4000-8000-daem0n00000${n}`;
    const out = await handlePreToolUse(payloadFor(dirs, 'run_command', args, { conversationId, stepIdx: 60 + n }), opts);
    assert.equal(out.decision, 'allow', args.CommandLine);
    assert.equal(readState(home, conversationId).backgroundSuspected, true, `${args.CommandLine} ${JSON.stringify(args)}`);
  }
  // WaitMsBeforeAsync: 0 is not a signal — agy's own examples send it for a
  // plain terminating run.
  const plain = '99999999-0000-4000-8000-daem0n000009';
  await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'npm test', WaitMsBeforeAsync: 0 }, { conversationId: plain, stepIdx: 70 }), opts);
  assert.equal(readState(home, plain).backgroundSuspected, false);
  fs.rmSync(path.join(home, 'config.json'));
});

test('a mount point a command wrote into is kept and marks the conversation untrusted', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: 'allow' } } }));
  const conversationId = '99999999-0000-4000-8000-d1r7y0000001';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const target = path.join(dirs.workspace, '.agents');
  fs.rmSync(target, { recursive: true, force: true });

  const pre = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'ls' }, { conversationId, stepIdx: 50 }), opts);
  assert.equal(pre.decision, 'allow');
  // bwrap mounts the tmpfs inside the child's namespace, so the host directory
  // stays empty while the command runs. Anything here means the command reached
  // the real directory the mount was supposed to hide.
  fs.mkdirSync(path.join(target, 'planted'));

  assert.deepEqual(handlePostToolUse(payloadFor(dirs, 'run_command', pre.overwrite, { conversationId, stepIdx: 50 }), opts), {});
  assert.equal(fs.existsSync(path.join(target, 'planted')), true, 'kept as evidence');
  assert.equal(readState(home, conversationId).untrusted?.reason, 'protected-path-written');

  fs.rmSync(target, { recursive: true, force: true });
  fs.rmSync(path.join(home, 'config.json'));
});

test('a protected directory reclaimed before the command starts still protects it', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // The line is built while `.agents` exists, so a single `--ro-bind-try` would
  // be all there is — and it silently skips a missing path. Another step
  // reclaiming the mount point before bwrap starts would then let the command
  // write the real directory.
  const target = path.join(dirs.workspace, '.agents');
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target);
  const ctx = ctxFor({ CommandLine: 'true' }, { probe: () => real });
  const line = confinedCommandLine(ctx, 'mkdir -p .agents 2>/dev/null; touch .agents/planted && echo WROTE || echo refused');
  fs.rmSync(target, { recursive: true, force: true });
  const res = runLine(line, dirs.env);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /refused/);
  assert.equal(fs.existsSync(path.join(target, 'planted')), false, 'nothing reached the host');
  fs.rmSync(target, { recursive: true, force: true });
});

test('a protected directory that exists stays readable inside the sandbox', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // The fix must not turn an existing `.git` into an empty mount: the real
  // directory is what the command reads.
  const target = path.join(dirs.workspace, '.agents');
  fs.rmSync(target, { recursive: true, force: true });
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, 'rules.md'), 'agent rules\n');
  const ctx = ctxFor({ CommandLine: 'true' }, { probe: () => real });
  const res = runLine(confinedCommandLine(ctx, 'cat .agents/rules.md 2>&1; touch .agents/x 2>&1 | head -1'), dirs.env);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /agent rules/, 'the real directory is bound, not shadowed');
  assert.match(res.stdout, /Read-only file system/, 'and it is still read-only');
  fs.rmSync(target, { recursive: true, force: true });
});

test('the mount points for missing protected directories exist only while the command runs', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: 'allow' } } }));
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const target = path.join(dirs.workspace, '.agents');
  fs.rmSync(target, { recursive: true, force: true });
  assert.equal(fs.existsSync(target), false);

  const pre = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'ls' }, { stepIdx: 30 }), opts);
  assert.equal(pre.decision, 'allow');
  assert.match(pre.overwrite.CommandLine, new RegExp(`'--tmpfs' '${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`));
  assert.equal(fs.existsSync(target), true, 'created for the command');

  assert.deepEqual(handlePostToolUse(payloadFor(dirs, 'run_command', pre.overwrite, { stepIdx: 30 }), opts), {});
  assert.equal(fs.existsSync(target), false, 'removed after the command');
  fs.rmSync(path.join(home, 'config.json'));
});

test('the env scrub runs the command under env -i with the sandbox allowlist', () => {
  const env = { PATH: '/usr/bin:/bin', HOME: '/home/someone', LANG: 'en_US.UTF-8', GEMINI_API_KEY: 'secret-value', AUTOAGY_HOME: '/tmp/other' };
  const ctx = ctxFor({ CommandLine: 'echo hi' }, { env: { ...env } });
  const line = scrubbedCommandLine(ctx, 'echo hi && ls -l > out.txt');
  assert.match(line, /^'\/usr\/bin\/env' -i /, 'env -i comes first');
  assert.match(line, /'PATH=\/usr\/bin:\/bin'/);
  assert.match(line, /'LANG=en_US\.UTF-8'/);
  assert.ok(!line.includes('GEMINI_API_KEY'), 'the hook\'s own secrets are not put in the command line');
  assert.ok(!line.includes('AUTOAGY_HOME'), 'nor is anything else the allowlist does not name');
  // The policy's home wins over the inherited one, so a `~` in the command is
  // the same `~` the credential list and the protected paths were built from —
  // the reason `autoagy setup` pins that home into hooks.json.
  assert.ok(!line.includes('/home/someone'), 'the inherited HOME is not passed through');
  assert.ok(line.includes(`'HOME=${dirs.home}'`), 'the pinned home is');
  assert.match(line, / -c 'echo hi && ls -l > out\.txt'$/, 'the shell keeps pipes and redirections working');
});

test('the scrub can be widened by ownSandboxEnvPassThrough', () => {
  const env = { PATH: '/usr/bin', CARGO_HOME: '/home/someone/.cargo', OTHER: 'x' };
  const base = configWith({ ownSandbox: 'on', ownSandboxEnvPassThrough: ['CARGO_HOME'] });
  const ctx = new HookContext(payloadFor(dirs, 'run_command', { CommandLine: 'cargo build' }), { config: base, env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe });
  const line = scrubbedCommandLine(ctx, 'cargo build');
  assert.match(line, /'CARGO_HOME=\/home\/someone\/\.cargo'/, 'the one list widens both rewrites');
  assert.ok(!line.includes('OTHER='));
});

test('a repository nested in the workspace keeps its .git read-only too', () => {
  const nested = path.join(dirs.workspace, 'sub');
  const deep = path.join(dirs.workspace, 'packages', 'lib');
  const skipped = path.join(dirs.workspace, 'node_modules', 'pkg');
  for (const dir of [nested, deep, skipped]) fs.mkdirSync(path.join(dir, '.git'), { recursive: true });
  try {
    const ctx = ctxFor({ CommandLine: 'ls' });
    const found = ctx.nestedGitPaths;
    assert.ok(found.includes(path.join(nested, '.git')), 'a submodule-style nested repository is found');
    assert.ok(found.includes(path.join(deep, '.git')), 'a repository a few directories down is found');
    assert.ok(!found.includes(path.join(skipped, '.git')), 'node_modules is not walked');
    assert.ok(!found.includes(path.join(dirs.workspace, '.git')), 'the top-level one is already a protected workspace directory');
    // The point of finding them: a hook planted in a nested .git runs on the
    // next git command in that directory, which has to leave this sandbox to
    // write anything. The edit tools already refuse the same path.
    const argv = parseShell(confinedCommandLine(ctx, 'ls')).commands[0].argv;
    const mountIndex = (flag, p) => argv.findIndex((a, i) => a === flag && argv[i + 1] === p && argv[i + 2] === p);
    const workspaceRw = mountIndex('--bind-try', dirs.workspace);
    assert.ok(mountIndex('--ro-bind-try', path.join(nested, '.git')) > workspaceRw);
    assert.ok(mountIndex('--ro-bind-try', path.join(deep, '.git')) > workspaceRw);
    assert.equal(classify(new HookContext(payloadFor(dirs, 'write_to_file', { TargetFile: path.join(nested, '.git', 'hooks', 'pre-commit') }), {
      config: configWith({ ownSandbox: 'off' }), env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp],
    })).verdict, 'review');
  } finally {
    for (const dir of [nested, path.join(dirs.workspace, 'packages'), path.join(dirs.workspace, 'node_modules')]) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

// ---------------------------------------------------------------------------
// A nested `.git` the command creates itself (see newNestedGitPlantings).
//
// `--ro-bind-try` skips a path that does not exist when the command line is
// built, and the placeholders only ever cover the top-level protected
// directories, so the write lands on the host. Nothing can mount the directory
// in advance — the set of paths that might become repositories is unbounded —
// so what is checked is the filesystem, after the fact.
// ---------------------------------------------------------------------------

const plantedConfig = (capture) => ({
  ownSandbox: 'on',
  reviewer: { backend: 'mock', mock: { response: 'allow', capture } },
});

// Both caps are gone: eight per command and twenty per conversation, each of
// which dropped a repository in silence. Nine in one command, or twenty-one
// across two, was a legal way to get a planted hook's `git commit` to the
// reviewer with nothing said about the hook.
test('no number of planted repositories pushes one out of the record', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  const capture = path.join(dirs.root, 'planted-many.jsonl');
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(plantedConfig(capture)));
  const conversationId = '99999999-0000-4000-8000-p1a17ed0000e';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const base = path.join(dirs.workspace, 'many');
  fs.rmSync(base, { recursive: true, force: true });
  fs.rmSync(capture, { force: true });
  fs.mkdirSync(base, { recursive: true });
  const plant = (i) => {
    const hooks = path.join(base, `r${i}`, '.git', 'hooks');
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(hooks, 'pre-commit'), `#!/bin/sh\necho ${i}\n`);
  };
  const step = async (stepIdx, range) => {
    const started = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'true' }, { conversationId, stepIdx }), opts);
    for (const i of range) plant(i);
    handlePostToolUse(payloadFor(dirs, 'run_command', started.overwrite, { conversationId, stepIdx }), opts);
  };
  try {
    await step(80, Array.from({ length: 9 }, (_, i) => i));
    assert.equal(readState(home, conversationId).plantedHooks.length, 9, 'the ninth in one command is recorded');
    await step(81, Array.from({ length: 13 }, (_, i) => i + 9));
    const state = readState(home, conversationId);
    assert.equal(state.plantedHooks.length, 22, 'and the twenty-first and later do not push the first out');
    assert.equal(state.untrusted, null, 'many plants are still not grounds for distrusting the conversation');

    const first = path.join(base, 'r0');
    const commit = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'git commit -m x', Cwd: first }, { conversationId, stepIdx: 82 }), opts);
    assert.equal(commit.decision, 'allow', 'the mock reviewer allows — what matters is that it was asked');
    const prompts = fs.readFileSync(capture, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const prompt = JSON.stringify(prompts[prompts.length - 1]);
    assert.ok(prompt.includes(JSON.stringify(path.join(first, '.git')).slice(1, -1)), 'the oldest repository is still the one named');
    // Bounded where it is shown: eight in full, the rest named.
    assert.equal((prompt.match(/hook \\"pre-commit\\"/g) ?? []).length, 8);
    assert.match(prompt, /14 more whose contents are not kept/);
    assert.match(prompt, /treat every one of them as holding something git will run/, 'no contents is not read as nothing runnable');
    // In the state file too: every path, and contents only for the newest.
    const kept = readState(home, conversationId).plantedHooks;
    assert.equal(kept.length, 22);
    assert.ok(kept.slice(0, -8).every((p) => p.contentsDropped && !p.hooks && p.path), 'older ones keep their path, not their hooks');
    assert.ok(kept.slice(-8).every((p) => p.hooks?.length > 0), 'the newest keep what they hold');
    assert.ok(JSON.stringify(kept[0]).length < 300, 'an older record costs a path, not a hook file');
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
    fs.rmSync(capture, { force: true });
  }
});

test('a nested .git the command created is found afterwards, and commands touching it are reviewed', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  const capture = path.join(dirs.root, 'planted-prompt.jsonl');
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(plantedConfig(capture)));
  const conversationId = '99999999-0000-4000-8000-p1a17ed00001';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const repo = path.join(dirs.workspace, 'sub');
  const gitDir = path.join(repo, '.git');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.rmSync(capture, { force: true });
  fs.mkdirSync(repo, { recursive: true });
  try {
    const args = { CommandLine: `mkdir -p ${gitDir}/hooks` };
    const started = await handlePreToolUse(payloadFor(dirs, 'run_command', args, { conversationId, stepIdx: 70 }), opts);
    assert.equal(started.decision, 'allow');
    // The before-set is what makes "this command created it" answerable, and an
    // empty list is the hole itself: there was no nested repository yet.
    assert.deepEqual(readState(home, conversationId).pendingNestedGit[70], []);

    // The effect this test stands in for: the mount skipped the path that did
    // not exist, so the write reached the host.
    fs.mkdirSync(path.join(gitDir, 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(gitDir, 'hooks', 'pre-commit'), '#!/bin/sh\necho pwned\n');

    assert.deepEqual(handlePostToolUse(payloadFor(dirs, 'run_command', started.overwrite, { conversationId, stepIdx: 70 }), opts), {});
    const state = readState(home, conversationId);
    assert.equal(state.plantedHooks.length, 1);
    assert.equal(state.plantedHooks[0].path, gitDir);
    assert.equal(state.plantedHooks[0].dir, repo, 'the repository is what a later git command runs in');
    assert.equal(state.pendingNestedGit[70], undefined, 'consumed with the rewrite record it was written beside');
    assert.equal(state.untrusted, null, 'one plant is not grounds for distrusting the whole conversation');
    assert.ok(
      readDecisions(home, 10).some((r) => r.verdict === 'planted-git-hook' && r.path === gitDir),
      'the decision log names the path',
    );

    // The consequence: the command names the repository, never the hook, and the
    // reviewer is handed what is in it.
    const commit = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'git commit -m x', Cwd: repo }, { conversationId, stepIdx: 71 }), opts);
    assert.equal(commit.decision, 'allow', 'the reviewer allowed it — the point is that it was asked');
    const prompts = fs.readFileSync(capture, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const prompt = JSON.stringify(prompts[prompts.length - 1]);
    assert.match(prompt, />>> PLANTED GIT HOOKS START/);
    assert.ok(prompt.includes(gitDir), 'the reviewer is told which directory');
    assert.match(prompt, /pre-commit/, 'and what is in it');

    // The control: the rest of the workspace is not dragged along with it. The
    // walk is by repository, not by "the workspace has a plant in it".
    const other = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'npm test', Cwd: dirs.workspace }, { conversationId, stepIdx: 72 }), opts);
    assert.equal(other.decision, 'allow');
    // Scoped to this repository: the decision log is shared by every test in
    // this file, and it is the record for THIS path that must not multiply.
    assert.equal(readDecisions(home, 10).filter((r) => r.verdict === 'planted-git-hook' && r.path === gitDir).length, 1, 'one record, not one per command');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(path.join(home, 'config.json'), { force: true });
  }
});

test('an ordinary repository the command creates is not a planting', async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(plantedConfig(null)));
  const conversationId = '99999999-0000-4000-8000-p1a17ed00002';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const repo = path.join(dirs.workspace, 'fresh');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  try {
    const started = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: `git init ${repo}` }, { conversationId, stepIdx: 73 }), opts);
    // What `git init` leaves: samples and a plain config, plus a hooks entry
    // that is a directory rather than a file.
    fs.mkdirSync(path.join(repo, '.git', 'hooks', 'pre-commit'), { recursive: true });
    fs.writeFileSync(path.join(repo, '.git', 'hooks', 'pre-commit.sample'), '#!/bin/sh\n');
    fs.writeFileSync(path.join(repo, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n');
    handlePostToolUse(payloadFor(dirs, 'run_command', started.overwrite, { conversationId, stepIdx: 73 }), opts);
    assert.deepEqual(readState(home, conversationId).plantedHooks, []);
    assert.equal(
      readDecisions(home, 20).some((r) => r.verdict === 'planted-git-hook' && r.path === path.join(repo, '.git')),
      false,
      'creating a repository is routine and must not accuse anyone of anything',
    );
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(path.join(home, 'config.json'), { force: true });
  }
});

test('a command that may still be running is looked at again at the end of the turn', async () => {
  // The walk at PostToolUse races a command agy backgrounded: the `.git` may not
  // be on disk yet when the tool call returns. The before-set is kept for the
  // turn-end sweep, which is the same rule the mount points follow.
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(plantedConfig(null)));
  const conversationId = '99999999-0000-4000-8000-p1a17ed00003';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  const repo = path.join(dirs.workspace, 'late');
  const gitDir = path.join(repo, '.git');
  fs.rmSync(repo, { recursive: true, force: true });
  fs.mkdirSync(repo, { recursive: true });
  try {
    const nested = [gitDir];
    updateState(home, conversationId, (s) => {
      s.pendingNestedGit[74] = [];
      s.backgroundSuspected = false;
    });
    // Nothing on disk yet: the sweep finds nothing and says nothing.
    handlePostInvocation({ conversationId }, opts);
    assert.deepEqual(readState(home, conversationId).plantedHooks, []);

    // Now the command gets there, after the tool call already returned.
    updateState(home, conversationId, (s) => {
      s.pendingNestedGit[74] = [];
    });
    fs.mkdirSync(path.join(gitDir, 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(gitDir, 'hooks', 'pre-commit'), '#!/bin/sh\necho pwned\n');
    handlePostInvocation({ conversationId }, opts);
    const state = readState(home, conversationId);
    assert.equal(state.plantedHooks.length, 1);
    assert.equal(state.plantedHooks[0].path, nested[0]);
    assert.deepEqual(state.pendingNestedGit, {}, 'the sweep clears what it looked at');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.rmSync(path.join(home, 'config.json'), { force: true });
  }
});

test('a nested .git is protected once it exists, and not while it is being created', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // The premise the whole after-the-fact check rests on, and the reason it is a
  // check rather than a mount: an existing nested `.git` is bound read-only,
  // while one the command creates itself is not covered by anything.
  const repo = path.join(dirs.workspace, 'nested-repo');
  const gitDir = path.join(repo, '.git');
  const hook = path.join(gitDir, 'hooks', 'pre-commit');
  const run = (script) => {
    const ctx = ctxFor({ CommandLine: 'x' }, { probe: () => real });
    const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, script)], { cwd: dirs.workspace, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    return res.stdout.trim();
  };
  try {
    fs.rmSync(repo, { recursive: true, force: true });
    fs.mkdirSync(path.join(gitDir, 'hooks'), { recursive: true });
    const held = run(`printf x > ${JSON.stringify(hook)} 2>/dev/null && echo WROTE=yes || echo WROTE=no`);
    assert.equal(held, 'WROTE=no', 'an existing nested .git is read-only inside the sandbox');
    assert.equal(fs.existsSync(hook), false, 'and the write did not reach the host');

    // A fresh context: nestedGitPaths is memoized per HookContext, and this
    // second command has to be built as if the directory were not there.
    fs.rmSync(gitDir, { recursive: true, force: true });
    const made = run(`mkdir -p ${JSON.stringify(path.dirname(hook))} && printf x > ${JSON.stringify(hook)} && echo WROTE=yes`);
    assert.equal(made, 'WROTE=yes', 'the one the command creates is not covered by a mount');
    assert.equal(fs.existsSync(hook), true, 'it reached the host — which is why the after-the-fact check exists');
  } finally {
    fs.rmSync(repo, { recursive: true, force: true });
  }
});

test('a workspace full of nested repositories does not turn the check off', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ownSandbox: 'on' }));
  const conversationId = '99999999-0000-4000-8000-p1a17ed00004';
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  // An empty `.git` holds nothing runnable, so creating one is never a finding.
  // Making a lot of them used to be a legal move that put the workspace over a
  // count cap, and going over the cap recorded no before-set at all — one
  // unreviewed command silenced the check for the rest of the conversation.
  const decoys = path.join(dirs.workspace, 'many');
  // Not `target`, `build` or another name on the scan's skip list: those are
  // not walked at all, which is the documented cost of the budget.
  const repo = path.join(decoys, 'app');
  const gitDir = path.join(repo, '.git');
  fs.rmSync(decoys, { recursive: true, force: true });
  try {
    for (let i = 0; i < 120; i++) fs.mkdirSync(path.join(decoys, `d${i}`, '.git'), { recursive: true });
    const args = { CommandLine: `mkdir -p ${gitDir}/hooks` };
    const started = await handlePreToolUse(payloadFor(dirs, 'run_command', args, { conversationId, stepIdx: 90 }), opts);
    assert.equal(started.decision, 'allow');
    assert.ok(readState(home, conversationId).pendingNestedGit[90].length >= 120, 'the whole set is recorded, never a truncated one');

    fs.mkdirSync(path.join(gitDir, 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(gitDir, 'hooks', 'pre-commit'), '#!/bin/sh\necho pwned\n');
    handlePostToolUse(payloadFor(dirs, 'run_command', started.overwrite, { conversationId, stepIdx: 90 }), opts);
    const planted = readState(home, conversationId).plantedHooks ?? [];
    assert.ok(planted.some((entry) => entry.path === gitDir), 'the plant is still found among 120 decoys');
    // And the decoys themselves are not accused: they hold nothing runnable.
    assert.equal(planted.length, 1);
  } finally {
    fs.rmSync(decoys, { recursive: true, force: true });
    fs.rmSync(path.join(home, 'config.json'), { force: true });
  }
});

test('executor mode hands agy a token instead of the command, and will not fall back without one', { skip: linuxOnly }, async () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  const conversationId = '99999999-0000-4000-8000-70ke40000001';
  const config = { ownSandbox: 'on', commandGrant: 'executor' };
  fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(config));
  const opts = { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe };
  try {
    // Before the executor exists the own sandbox refuses to call itself active,
    // rather than falling back to the rewrite that needs `command(*)` — the
    // grant this configuration deliberately does not have.
    const ctx = ctxFor({ CommandLine: 'ls' }, { ownSandbox: 'on' });
    ctx.config.commandGrant = 'executor';
    const detected = detectOwnSandbox({ config: ctx.config, host: cliHost(), appDataDir: dirs.appData, autoagyHome: home, platform: 'linux', probe: okProbe });
    assert.equal(detected.active, false);
    assert.match(detected.detail, /not installed/);

    installExecutor(home);
    const out = await handlePreToolUse(payloadFor(dirs, 'run_command', { CommandLine: 'echo hi', Cwd: dirs.workspace }, { conversationId, stepIdx: 5 }), opts);
    assert.equal(out.decision, 'allow');
    assert.equal(out.overwrite.BypassSandbox, true);
    // What agy runs is one program and a name — nothing an agent could aim.
    const match = /^'([^']+)' ([0-9a-f]{32})$/.exec(out.overwrite.CommandLine);
    assert.ok(match, out.overwrite.CommandLine);
    assert.equal(match[1], executorPath(home));

    const token = JSON.parse(fs.readFileSync(path.join(tokenDir(home), `${match[2]}.json`), 'utf8'));
    assert.match(token.commandLine, /bwrap/, 'the bwrap line is what the token carries');
    assert.equal(token.cwd, dirs.workspace, 'the working directory is recorded, not left to be inherited');
    assert.equal(token.conversation, conversationId);

    // An escalation the agent asked for itself goes through a token too, and this
    // is the case the narrow grant used to break. Measured on agy 1.2.7: a
    // `command(...)` grant matches the command's *content*, so with
    // `command(<executor>)` the content `whoami` matched nothing and agy refused
    // it outright in print mode — the mode that closes the fail-open was the mode
    // in which the agent could not escalate at all.
    // An escalation is reviewed, so these calls need a reviewer; the mock is
    // selected from the config file, never from the environment.
    const withReviewer = (response, extra = {}) =>
      fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify({ ...config, ...extra, reviewer: { backend: 'mock', mock: { response } } }));
    withReviewer('allow');
    const escalated = await handlePreToolUse(
      payloadFor(dirs, 'run_command', { CommandLine: 'git push', BypassSandbox: true, Cwd: dirs.workspace }, { conversationId, stepIdx: 6 }),
      opts,
    );
    assert.equal(escalated.decision, 'allow');
    const hit = /^'([^']+)' ([0-9a-f]{32})$/.exec(escalated.overwrite.CommandLine);
    assert.ok(hit, escalated.overwrite.CommandLine);
    assert.equal(hit[1], executorPath(home), 'what agy is asked to run is the one program the grant names');
    const escalatedToken = JSON.parse(fs.readFileSync(path.join(tokenDir(home), `${hit[2]}.json`), 'utf8'));
    assert.equal(escalatedToken.commandLine, 'git push', 'unconfined, which is what approving an escalation meant');
    assert.doesNotMatch(escalatedToken.commandLine, /bwrap/);
    assert.equal(escalatedToken.cwd, dirs.workspace);
    // And nothing is recorded for the sandbox self-check: there was no bwrap
    // rewrite to verify, and comparing against one would mark the conversation
    // untrusted for a command that ran exactly as approved.
    assert.equal(readState(home, conversationId).pendingConfined[6], undefined);

    // Denied, nothing is minted: a token is a decision already made.
    withReviewer('deny');
    const refused = await handlePreToolUse(
      payloadFor(dirs, 'run_command', { CommandLine: 'rm -rf /', BypassSandbox: true }, { conversationId, stepIdx: 7 }),
      opts,
    );
    assert.equal(refused.decision, 'deny');
    assert.equal(refused.overwrite, undefined);

    // With the wildcard grant there is nothing to work around, so the call is
    // left alone — `command(*)` already covers any content.
    withReviewer('allow', { commandGrant: 'wildcard' });
    const wildcard = await handlePreToolUse(
      payloadFor(dirs, 'run_command', { CommandLine: 'git push', BypassSandbox: true }, { conversationId, stepIdx: 8 }),
      opts,
    );
    assert.equal(wildcard.decision, 'allow');
    assert.equal(wildcard.overwrite, undefined);
    fs.writeFileSync(path.join(home, 'config.json'), JSON.stringify(config));

    // The turn ending takes away whatever nobody redeemed: a surviving token is
    // a retry, and autoagy's retries are deliberately one-shot.
    handlePostInvocation({ conversationId }, opts);
    assert.equal(fs.existsSync(path.join(tokenDir(home), `${match[2]}.json`)), false);
    assert.equal(fs.existsSync(path.join(tokenDir(home), `${hit[2]}.json`)), false);
  } finally {
    fs.rmSync(path.join(home, 'config.json'), { force: true });
  }
});

test('a declared writable root gets the same read-only metadata as the workspace', () => {
  // Measured before this existed: with `writableRoots: [<declared>]`, a
  // sandboxed `echo > <declared>/.git/hooks/pre-commit` reached the host, while
  // the same write inside the workspace got `Read-only file system`. The edit
  // tools already refused it (`classifyWriteTarget` covers the declared roots),
  // so the two paths to one decision disagreed and the weaker one was the
  // sandbox — which is the shape the fourth round called a bug, and the reason
  // the own sandbox exists at all.
  const declared = path.join(dirs.root, 'declared');
  fs.mkdirSync(path.join(declared, '.git'), { recursive: true });
  fs.mkdirSync(path.join(declared, 'sub', '.git'), { recursive: true });
  const ctx = new HookContext(payloadFor(dirs, 'run_command', { CommandLine: 'true' }), {
    config: configWith({ ownSandbox: 'on', writableRoots: [declared] }),
    env: dirs.env,
    home: dirs.home,
    host: cliHost(),
    tempRoots: [dirs.tmp],
    bwrapProbe: okProbe,
  });
  const ro = readOnlyPaths(ctx);
  assert.ok(ro.includes(path.join(declared, '.git')), 'the declared root keeps its own .git read-only');
  assert.ok(ro.includes(path.join(declared, '.agents')), 'and the rest of the agent metadata');
  assert.ok(ro.includes(path.join(declared, 'sub', '.git')), 'a repository nested under it too');
  // The workspace is unchanged, and the root itself is still writable — that is
  // what declaring it was for.
  assert.ok(ro.includes(path.join(dirs.workspace, '.git')));
  assert.ok(!ro.includes(declared), 'the declared root itself stays writable');
});

// bwrap resolves a mount destination inside the new root, where an absolute
// symlink points at nothing yet: `Can't mount tmpfs on /newroot/…: No such file
// or directory`, exit 1, before the command starts. That is any component of the
// path, not only the last — so `~/.gemini` kept in a dotfiles repository, which is
// how stow and chezmoi lay it out, failed every sandboxed command through the
// mount of autoagy's own directory, while the self-check still said `verified`.
test('an absolute symlink anywhere in a mounted path does not fail every command', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const d = makeSandboxDirs();
  try {
    const dotfiles = path.join(d.root, 'dotfiles');
    fs.mkdirSync(path.join(dotfiles, 'codex'), { recursive: true });
    fs.symlinkSync(path.join(dotfiles, 'codex'), path.join(d.workspace, '.codex'));
    fs.renameSync(path.join(d.home, '.gemini'), path.join(dotfiles, 'gemini'));
    fs.symlinkSync(path.join(dotfiles, 'gemini'), path.join(d.home, '.gemini'));
    fs.mkdirSync(d.env.AUTOAGY_HOME, { recursive: true });
    const ctx = new HookContext(payloadFor(d, 'run_command', { CommandLine: 'true' }), {
      config: configWith({ ownSandbox: 'on' }),
      env: d.env,
      home: d.home,
      host: { kind: 'cli', cwd: d.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [] } },
      tempRoots: [d.tmp],
      bwrapProbe: () => real,
    });
    const script = [
      'echo ran',
      `touch ${JSON.stringify(path.join(d.workspace, '.codex', 'x'))} 2>/dev/null`,
      `touch ${JSON.stringify(path.join(d.env.AUTOAGY_HOME, 'x'))} 2>/dev/null`,
      'true',
    ].join('; ');
    const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, script)], { cwd: d.workspace, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /ran/);
    // Mounted where the link lands, and still read-only through the link.
    assert.equal(fs.existsSync(path.join(dotfiles, 'codex', 'x')), false, 'the workspace .codex behind its symlink stays read-only');
    assert.equal(fs.existsSync(path.join(dotfiles, 'gemini', 'autoagy', 'x')), false, "and so does autoagy's own directory");
  } finally {
    d.cleanup();
  }
});

// A declared root that does not exist yet has no `.git` to protect, and the
// mount of one either failed every command (`Can't mkdir parents …: Read-only
// file system`, where the root sits under the read-only /) or had bwrap create
// the empty mount points on the host and leave them there (where it sits under a
// writable root).
test('a declared writable root that does not exist yet neither fails commands nor gets directories made in it', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const d = makeSandboxDirs();
  try {
    const underRo = path.join(d.root, 'not-yet');
    const underRw = path.join(d.tmp, 'not-yet');
    const ctx = new HookContext(payloadFor(d, 'run_command', { CommandLine: 'true' }), {
      config: configWith({ ownSandbox: 'on', writableRoots: [underRo, underRw] }),
      env: d.env,
      home: d.home,
      host: { kind: 'cli', cwd: d.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [] } },
      tempRoots: [d.tmp],
      bwrapProbe: () => real,
    });
    const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, 'echo ran')], { cwd: d.workspace, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /ran/);
    assert.equal(fs.existsSync(underRw), false, 'nothing is created on the host where the root will be');
  } finally {
    d.cleanup();
  }
});

// The self-check compares command lines and never sees an exit status, so a
// mount bwrap refuses has only ever been found by someone noticing that nothing
// runs. This is the check `status` makes instead: start it and look.
test('whether the sandbox starts is asked by starting it', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  const present = () => PROTECTED_WORKSPACE_DIRS.filter((name) => fs.existsSync(path.join(dirs.workspace, name)));
  const before = present();
  assert.deepEqual(sandboxStartCheck(ctxFor({ CommandLine: 'true' }, { probe: () => real })), { ok: true, detail: '' });
  // A sandbox that exits non-zero before the command, standing in for a refused mount.
  const refused = sandboxStartCheck(ctxFor({ CommandLine: 'true' }, { probe: () => ({ ...real, bwrap: '/bin/false' }) }));
  assert.equal(refused.ok, false);
  assert.ok(refused.detail.length > 0, 'and says something about why');
  assert.equal(sandboxStartCheck(ctxFor({ CommandLine: 'true' }, { ownSandbox: 'off' })), null, 'nothing to start where it is not in use');
  assert.deepEqual(present(), before, 'the mount points it made are gone again');
});

test('a protected name that is a file does not fail every command in the workspace', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // `git worktree add` and a checked-out submodule leave `.git` as a *file*
  // holding `gitdir: …`, and `--tmpfs` cannot mount on a file: measured, bwrap
  // exits 1 with "Can't mkdir <ws>/.git: Not a directory" — so every command in
  // such a repository failed, while the self-check recorded `verified` (agy did
  // run the line autoagy rewrote) and `status` reported a working sandbox.
  const worktree = path.join(dirs.root, 'linked-worktree');
  fs.mkdirSync(worktree, { recursive: true });
  const gitFile = path.join(worktree, '.git');
  fs.writeFileSync(gitFile, 'gitdir: /elsewhere/.git/worktrees/linked\n');
  const ctx = new HookContext(payloadFor(dirs, 'run_command', { CommandLine: 'x' }, { workspacePaths: [worktree] }), {
    config: configWith({ ownSandbox: 'on' }),
    env: dirs.env,
    home: dirs.home,
    host: cliHost(),
    tempRoots: [dirs.tmp],
    bwrapProbe: () => real,
  });
  const placeholders = [];
  const line = confinedCommandLine(ctx, 'echo WORKTREE-OK', { placeholders });
  assert.ok(!line.includes(`'--tmpfs' '${gitFile}'`), 'no mount point is staged on a file');
  assert.ok(line.includes(`'--ro-bind-try' '${gitFile}' '${gitFile}'`), 'the file itself is still bound read-only');

  const res = spawnSync('/bin/sh', ['-c', line], { cwd: worktree, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.trim(), 'WORKTREE-OK');

  // And the protection that is left is the one that matters: the file is
  // readable as before and cannot be replaced from inside.
  const write = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, `printf x > ${JSON.stringify(gitFile)}`)], { cwd: worktree, encoding: 'utf8' });
  assert.notEqual(write.status, 0, 'the gitfile is read-only in the sandbox');
  assert.equal(fs.readFileSync(gitFile, 'utf8'), 'gitdir: /elsewhere/.git/worktrees/linked\n');
  removeControlPlaceholders(placeholders);
});

test('the walk stops on the clock as well as on the directory count', () => {
  // The directory bound cannot stand in for a time bound: one `readdir` costs
  // ~2.4-3.6ms on this machine's 9p mounts against ~0.01ms on ext4, so the same
  // tree is a five-second walk in one place and fifteen milliseconds in the
  // other. Two walks are paid per sandboxed command, and the PostToolUse half
  // sits inside a 10s watchdog — which exits the hook without running the
  // self-checks at all, so an unbounded walk is not slow, it is absent.
  const work = path.join(dirs.root, 'walk-clock');
  fs.mkdirSync(path.join(work, 'sub'), { recursive: true });
  const readings = [1_000, 1_100, 10_000]; // starts the budget, inside it, then past it
  let i = 0;
  const scan = findNestedGitPaths(work, { maxMs: 500, now: () => readings[Math.min(i++, readings.length - 1)] });
  assert.equal(scan.truncated, true, 'a walk that ran out of time says so');
  assert.equal(scan.visited, 1, 'and it stops there rather than finishing the tree');
  assert.deepEqual(scan.paths, []);

  // A tree that fits is not marked, so the two cases cannot be confused.
  const whole = findNestedGitPaths(path.join(dirs.workspace), { maxMs: 10_000 });
  assert.equal(whole.truncated, false);
  assert.ok(whole.visited > 0);
});

test('protectedPaths reaches commands, not only the edit tools', { skip: linuxOnly }, () => {
  // The setting is documented as "paths that need review to modify" and the
  // class it names — `.husky/`, `.envrc`, a `postinstall` script — is the
  // "written now, executed later outside the sandbox" one, which a *command*
  // writes. It gated only the edit tools: measured, `echo pwn >
  // .husky/pre-commit` was `allow | sandboxed-command` with or without the entry.
  const husky = path.join(dirs.workspace, '.husky', 'pre-commit');
  const config = configWith({ ownSandbox: 'on', protectedPaths: [`${dirs.workspace}/.husky/**`] });
  const withGlob = (CommandLine, extra = {}) => classify(contextFor(dirs, 'run_command', { CommandLine, ...extra }, { config, bwrapProbe: okProbe }));
  assert.equal(withGlob(`echo pwn > ${husky}`).verdict, 'review');
  assert.equal(withGlob(`echo pwn > ${husky}`).category, 'protected-path');
  assert.equal(withGlob('rm -rf .husky').verdict, 'review', 'deleting the directory is the same path');
  assert.equal(withGlob('cd .husky && ls').verdict, 'review');
  assert.equal(withGlob('ls -la .husky/pre-commit').verdict, 'review', 'it cannot tell a read from a write, and erring towards a review is the point');
  assert.equal(withGlob('echo pwn > src/other.txt').verdict, 'allow', 'and nothing else is dragged in');
  // A `~` in the command and in the setting name the same file.
  const homeConfig = configWith({ ownSandbox: 'on', protectedPaths: [`${dirs.home}/secrets/**`] });
  assert.equal(
    classify(contextFor(dirs, 'run_command', { CommandLine: 'echo x > ~/secrets/a' }, { config: homeConfig, bwrapProbe: okProbe })).verdict,
    'review',
  );
  // Without the setting nothing changes.
  assert.equal(classify(contextFor(dirs, 'run_command', { CommandLine: `echo pwn > ${husky}` }, { config: configWith({ ownSandbox: 'on' }), bwrapProbe: okProbe })).verdict, 'allow');
});

test('protectedPaths that name a place are mounted read-only, not merely recognised', () => {
  // The command-side check reads the command line, so it sees a literal path and
  // not one the shell assembles: measured, `echo pwn > .husky/pre-commit` is
  // reviewed while `p=.husky/pre-commit; echo pwn > $p` is `allow |
  // sandboxed-command`. The class this setting exists for is written by commands,
  // so the entries that name a place become read-only mounts as well.
  fs.mkdirSync(path.join(dirs.workspace, '.husky'), { recursive: true });
  fs.mkdirSync(path.join(dirs.workspace, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dirs.workspace, '.envrc'), 'export A=1');
  fs.writeFileSync(path.join(dirs.workspace, 'key.pem'), 'x');
  fs.writeFileSync(path.join(dirs.workspace, 'Makefile'), 'all:');
  fs.mkdirSync(path.join(dirs.home, 'secrets'), { recursive: true });
  const mounts = (protectedPaths) =>
    readOnlyPaths(contextFor(dirs, 'run_command', { CommandLine: 'x' }, { config: configWith({ ownSandbox: 'on', protectedPaths }), bwrapProbe: okProbe }));

  assert.ok(mounts(['**/.husky/**']).includes(path.join(dirs.workspace, '.husky')), 'a basename-anchored glob names the top of each writable root');
  assert.ok(mounts(['.envrc']).includes(path.join(dirs.workspace, '.envrc')), 'so does a bare name');
  assert.ok(mounts(['*.pem']).includes(path.join(dirs.workspace, 'key.pem')), 'and a star is matched against the root\'s entries');
  assert.ok(mounts([path.join(dirs.workspace, 'Makefile')]).includes(path.join(dirs.workspace, 'Makefile')), 'an absolute entry inside a writable root names itself');

  // Every writable root, not just the first one. `writableRoots` is the workspace
  // roots followed by the declared ones and the artifact/scratch/temp
  // directories, and an absolute entry names a place rather than a position in
  // that list: with the `break` where it was, an entry inside a *declared* root
  // was dropped in silence — measured end to end, the write it was meant to stop
  // went through (`PWN` in the file), while the same entry inside the workspace
  // was refused with `Read-only file system`.
  const declared = path.join(dirs.root, 'declared-root');
  fs.mkdirSync(declared, { recursive: true });
  fs.writeFileSync(path.join(declared, 'keep.md'), 'declared');
  const declaredMounts = readOnlyPaths(
    contextFor(dirs, 'run_command', { CommandLine: 'x' }, { config: configWith({ ownSandbox: 'on', writableRoots: [declared], protectedPaths: [path.join(declared, 'keep.md')] }), bwrapProbe: okProbe }),
  );
  assert.ok(declaredMounts.includes(path.join(declared, 'keep.md')), 'an absolute entry inside a declared root is a mount too');
  const outside = mounts([path.join(dirs.root, 'nowhere', 'x.md')]);
  assert.ok(!outside.some((p) => p.includes('nowhere')), 'and one that is inside no writable root at all still names nothing');

  // The ones that cannot name a mount point, each for its own reason.
  const middle = mounts(['src/**/gen*']);
  assert.ok(!middle.includes(path.join(dirs.workspace, 'src')), 'a `**` in the middle is skipped, not widened to the directory that holds the subtree');
  assert.ok(!mounts(['.vscode/tasks.json']).includes(path.join(dirs.workspace, '.vscode', 'tasks.json')), 'a relative entry with a slash matches nothing in the glob engine either');
  assert.ok(!mounts(['**/../escape']).some((p) => p.includes('escape')), 'and an entry cannot be joined out of the root it was anchored to');
  // Outside every writable root the sandbox is read-only anyway, so mounting it
  // would only lengthen the command line.
  assert.ok(!mounts([path.join(dirs.home, 'secrets')]).includes(path.join(dirs.home, 'secrets')));
  // Existing paths only: `--ro-bind-try` skips what is not there, and the one
  // mechanism that covers a missing path creates the mount point on the host —
  // which for a file name means a directory by that name in the workspace.
  assert.ok(!mounts(['**/.absent/**']).some((p) => p.includes('.absent')));
  assert.equal(mounts([]).includes(path.join(dirs.workspace, '.husky')), false, 'and nothing happens without the setting');
});

test('a protectedPaths entry is read-only inside the real sandbox, however the command spells it', { skip: real.ok ? false : `bubblewrap unavailable: ${real.detail ?? 'not Linux'}` }, () => {
  // The point of the mount: the command-side check cannot see through `$p`, and
  // this does not have to. Measured here rather than reasoned about, because the
  // mount order (writable root bind first, read-only binds after) is what makes
  // it hold.
  fs.mkdirSync(path.join(dirs.workspace, '.husky'), { recursive: true });
  fs.writeFileSync(path.join(dirs.workspace, '.husky', 'pre-commit'), '#!/bin/sh\n');
  fs.writeFileSync(path.join(dirs.workspace, '.envrc'), 'export A=1');
  const ctx = new HookContext(payloadFor(dirs, 'run_command', { CommandLine: 'x' }), {
    config: configWith({ ownSandbox: 'on', protectedPaths: ['**/.husky/**', '.envrc'] }),
    env: dirs.env,
    home: dirs.home,
    host: cliHost(),
    tempRoots: [dirs.tmp],
    bwrapProbe: () => real,
  });
  const script = [
    'echo pwn > .husky/pre-commit 2>/dev/null && echo LITERAL=rw || echo LITERAL=ro',
    'p=.husky/pre-commit; echo pwn > $p 2>/dev/null && echo ASSEMBLED=rw || echo ASSEMBLED=ro',
    'echo pwn > .husky/new-hook 2>/dev/null && echo NEWFILE=rw || echo NEWFILE=ro',
    'echo pwn > .envrc 2>/dev/null && echo ENVRC=rw || echo ENVRC=ro',
    'echo ok > ordinary.txt 2>/dev/null && echo WORKSPACE=rw || echo WORKSPACE=ro',
    'cat .husky/pre-commit > /dev/null 2>&1 && echo READ=ok || echo READ=denied',
  ].join('; ');
  const placeholders = [];
  const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, script, { placeholders })], { cwd: dirs.workspace, encoding: 'utf8' });
  removeControlPlaceholders(placeholders);
  assert.equal(res.status, 0, res.stderr);
  assert.deepEqual(Object.fromEntries(res.stdout.trim().split('\n').map((l) => l.split('='))), {
    LITERAL: 'ro',
    ASSEMBLED: 'ro',
    NEWFILE: 'ro',
    ENVRC: 'ro',
    WORKSPACE: 'rw',
    READ: 'ok',
  });
  assert.equal(fs.readFileSync(path.join(dirs.workspace, '.husky', 'pre-commit'), 'utf8'), '#!/bin/sh\n', 'nothing reached the host');
  assert.equal(fs.readFileSync(path.join(dirs.workspace, '.envrc'), 'utf8'), 'export A=1');
});
