import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { detectOwnSandbox, confinedCommandLine, probeBwrap, readOnlyPaths, readSandboxCheck, removeControlPlaceholders } from '../plugin/lib/confine.mjs';
import { seccompProgram, seccompSupported } from '../plugin/lib/seccomp.mjs';
import { HookContext, PROTECTED_WORKSPACE_DIRS } from '../plugin/lib/context.mjs';
import { handlePreToolUse, handlePostToolUse } from '../plugin/lib/hook.mjs';
import { parseShell } from '../plugin/lib/shell.mjs';
import { classify } from '../plugin/lib/policy.mjs';
import { makeSandboxDirs, configWith, payloadFor } from './helpers.mjs';

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

function ctxFor(args, { ownSandbox = 'on', probe = okProbe, tempRoots = [dirs.tmp] } = {}) {
  return new HookContext(payloadFor(dirs, 'run_command', args), {
    config: configWith({ ownSandbox }),
    env: dirs.env,
    home: dirs.home,
    host: cliHost(),
    tempRoots,
    bwrapProbe: probe,
  });
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

test('a required but unavailable own sandbox makes commands count as unsandboxed', () => {
  const ctx = ctxFor({ CommandLine: 'ls' }, { probe: failProbe });
  assert.equal(ctx.sandbox.active, false);
  assert.match(ctx.sandbox.detail, /ownSandbox is "on" but unavailable: no user namespaces/);
  assert.equal(ctxFor({ CommandLine: 'ls' }).sandbox.source, 'autoagy');
});

test('the confined command mounts read-only paths over writable roots and keeps the command intact', () => {
  const original = `echo "it's $HOME" && printf '%s\\n' 'a b' > out.txt; cat <<'EOF'\n$(not run)\nEOF`;
  const ctx = ctxFor({ CommandLine: original });
  const line = confinedCommandLine(ctx, original);
  const parsed = parseShell(line);
  assert.equal(parsed.error, null);
  const argv = parsed.commands[0].argv;
  assert.equal(argv[0], 'exec');
  assert.equal(argv[1], '/usr/bin/bwrap');
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

test('inside the own sandbox a command naming a credential store needs no review: the store is hidden', () => {
  assert.equal(classify(ctxFor({ CommandLine: 'cat ~/.ssh/id_ed25519' })).category, 'sandboxed-command');
  assert.equal(classify(ctxFor({ CommandLine: 'cat ~/.ssh/id_ed25519', BypassSandbox: true })).category, 'sandbox-escalation');
});

test('allowed sandboxed commands are rewritten into the own sandbox; escalations and denials are not', async () => {
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  const run = (args, mock = 'allow') => {
    const config = { ownSandbox: 'on', reviewer: { backend: 'mock', mock: { response: mock } } };
    fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify(config));
    return handlePreToolUse(payloadFor(dirs, 'run_command', args), { env: dirs.env, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe });
  };
  const sandboxed = await run({ CommandLine: 'npm test' });
  assert.equal(sandboxed.decision, 'allow');
  assert.equal(sandboxed.overwrite.BypassSandbox, true);
  assert.match(sandboxed.overwrite.CommandLine, /^exec '\/usr\/bin\/bwrap' /);
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

test('self-check: when agy ignores the rewrite, the own sandbox is switched off for that build, with one notice', async () => {
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
  assert.throws(() => seccompProgram('s390x'), /no seccomp filter/);
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

test('the mount points for missing protected directories exist only while the command runs', async () => {
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
