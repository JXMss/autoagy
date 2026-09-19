import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { detectOwnSandbox, confinedCommandLine, probeBwrap, readOnlyPaths } from '../plugin/lib/confine.mjs';
import { HookContext } from '../plugin/lib/context.mjs';
import { handlePreToolUse } from '../plugin/lib/hook.mjs';
import { parseShell } from '../plugin/lib/shell.mjs';
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
});

test('allowed sandboxed commands are rewritten into the own sandbox; escalations and denials are not', async () => {
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ ownSandbox: 'on' }));
  const run = (args, env = {}) =>
    handlePreToolUse(payloadFor(dirs, 'run_command', args), { env: { ...dirs.env, ...env }, home: dirs.home, host: cliHost(), tempRoots: [dirs.tmp], bwrapProbe: okProbe });
  const sandboxed = await run({ CommandLine: 'npm test' });
  assert.equal(sandboxed.decision, 'allow');
  assert.equal(sandboxed.overwrite.BypassSandbox, true);
  assert.match(sandboxed.overwrite.CommandLine, /^exec '\/usr\/bin\/bwrap' /);
  // Reviewed inside the sandbox (forced rm), approved, and still confined.
  const reviewed = await run({ CommandLine: 'rm -rf build' }, { AUTOAGY_MOCK_REVIEW: 'allow' });
  assert.equal(reviewed.decision, 'allow');
  assert.ok(reviewed.overwrite);
  // An escalation the reviewer approves runs as requested, outside any sandbox.
  const escalated = await run({ CommandLine: 'npm install', BypassSandbox: true }, { AUTOAGY_MOCK_REVIEW: 'allow' });
  assert.equal(escalated.decision, 'allow');
  assert.equal(escalated.overwrite, undefined);
  const denied = await run({ CommandLine: 'rm -rf build' }, { AUTOAGY_MOCK_REVIEW: 'deny' });
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
  ].join('; ');
  fs.mkdirSync(path.join(dirs.workspace, '.git', 'hooks'), { recursive: true });
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(dirs.transcriptPath, '');
  const res = spawnSync('/bin/sh', ['-c', confinedCommandLine(ctx, script)], { cwd: dirs.workspace, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  const got = Object.fromEntries(res.stdout.trim().split('\n').map((l) => l.split('=')));
  assert.deepEqual(got, { WORKSPACE: 'rw', GIT: 'ro', LOG: 'ro', ARTIFACT: 'rw', SELF: 'ro', HOME: 'ro', TMP: 'rw', NET: 'closed' });
  assert.equal(fs.readFileSync(path.join(dirs.workspace, 'quoted.txt'), 'utf8'), "it's");
  assert.equal(fs.readFileSync(dirs.transcriptPath, 'utf8'), '');
});
