import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { applySetup, applyTeardown, pinHookCommands, planSetup, cliSettingsPath, grantsFor, writableRootGrants, RECOMMENDED_SETTINGS } from '../plugin/lib/setup.mjs';
import { executorPath } from '../plugin/lib/tokens.mjs';
import { configPath, loadConfig } from '../plugin/lib/config.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-setup-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

test('setup adds grants and sandbox settings, teardown restores them', () => {
  const home = path.join(root, 'home');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const original = {
    model: 'Gemini Flash',
    toolPermission: 'request-review',
    enableTerminalSandbox: false,
    permissions: { allow: ['command(git status)'], deny: ['command(rm -rf /)'] },
  };
  fs.writeFileSync(file, JSON.stringify(original, null, 2));

  const dry = applySetup({ home, env, dryRun: true });
  assert.deepEqual(dry.addGrants, ['command(*)', 'mcp(*)', 'execute_url(*)']);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), original);

  const report = applySetup({ home, env });
  const after1 = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after1.permissions.allow, ['command(git status)', 'command(*)', 'mcp(*)', 'execute_url(*)']);
  assert.deepEqual(after1.permissions.deny, ['command(rm -rf /)']);
  assert.equal(after1.enableTerminalSandbox, true);
  assert.equal(after1.toolPermission, 'proceed-in-sandbox');
  // The one check that happens at the moment of the write, and follows
  // symlinks to decide where that write lands.
  assert.equal(after1.allowNonWorkspaceAccess, false);
  assert.ok(fs.existsSync(report.backup));
  assert.ok(!after1.permissions.allow.includes('read_url(*)'));

  // Idempotent.
  const again = applySetup({ home, env });
  assert.equal(again.addGrants.length + again.changes.length, 0);

  const teardown = applyTeardown({ home, env });
  assert.equal(teardown.found, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), { ...original, permissions: { ...original.permissions } });
  assert.equal(applyTeardown({ home, env }).found, false);
});

test('planSetup reports grants that permissions.deny would override', () => {
  const plan = planSetup({ permissions: { deny: ['mcp(*)'] } });
  assert.deepEqual(plan.conflicting, ['mcp(*)']);
});

test('only AUTOAGY_HOME relocates the config file', () => {
  const home = path.join(root, 'home');
  assert.equal(configPath({ AUTOAGY_CONFIG: path.join(root, 'work', 'cfg.json') }, home), path.join(home, '.gemini', 'autoagy', 'config.json'));
  assert.equal(configPath({ AUTOAGY_HOME: path.join(root, 'alt') }, home), path.join(root, 'alt', 'config.json'));
});

test('pinHookCommands rewrites bare node commands', () => {
  const dir = path.join(root, 'plugin');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'hooks.json'),
    JSON.stringify({ autoagy: { PreToolUse: [{ matcher: '*', hooks: [{ command: 'node ./bin/autoagy.mjs hook pre-tool-use' }] }], PostInvocation: [{ command: 'node ./bin/autoagy.mjs hook post-invocation' }] } }),
  );
  assert.equal(pinHookCommands(dir, { nodePath: '/opt/node 22/bin/node' }).changed, 2);
  const hooks = JSON.parse(fs.readFileSync(path.join(dir, 'hooks.json'), 'utf8'));
  assert.equal(hooks.autoagy.PreToolUse[0].hooks[0].command, '"/opt/node 22/bin/node" ./bin/autoagy.mjs hook pre-tool-use');
  assert.equal(pinHookCommands(dir, { nodePath: '/usr/bin/node' }).changed, 0);
});

test('pinHookCommands pins the configuration directory and home', () => {
  const dir = path.join(root, 'plugin-pinned');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'hooks.json');
  fs.writeFileSync(file, JSON.stringify({ autoagy: { PreToolUse: [{ hooks: [{ command: 'node ./bin/autoagy.mjs hook pre-tool-use' }] }] } }));
  const configHome = '/home/someone with space/.gemini/autoagy';
  assert.equal(pinHookCommands(dir, { nodePath: '/usr/bin/node', configHome, home: '/home/someone' }).changed, 1);
  const command = JSON.parse(fs.readFileSync(file, 'utf8')).autoagy.PreToolUse[0].hooks[0].command;
  assert.match(command, /--autoagy-home "\/home\/someone with space\/\.gemini\/autoagy"/);
  assert.match(command, /--home \/home\/someone$/);
  // Running setup again must not append the flags a second time.
  assert.equal(pinHookCommands(dir, { nodePath: '/usr/bin/node', configHome, home: '/home/someone' }).changed, 0);
});

test('the grants follow the configuration: the command shape, and one per writable root', () => {
  const home = path.join(root, 'grants-home');
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  assert.deepEqual(grantsFor({}, { autoagyHome, home }), ['command(*)', 'mcp(*)', 'execute_url(*)']);

  // The executor shape names one program in place of the wildcard.
  assert.deepEqual(grantsFor({ commandGrant: 'executor' }, { autoagyHome, home })[0], `command(${executorPath(autoagyHome)})`);

  // `allowNonWorkspaceAccess: false` would otherwise make writableRoots a dead
  // letter: agy refuses the write whatever autoagy says about it.
  const config = { writableRoots: ['~/shared-lib', '/srv/build ', '', 42] };
  assert.deepEqual(writableRootGrants(config, home), [`write_file(${path.join(home, 'shared-lib')})`, 'write_file(/srv/build)']);
  assert.deepEqual(grantsFor(config, { autoagyHome, home }).slice(3), writableRootGrants(config, home));
});

test('setup writes a write_file grant for each writable root', () => {
  const home = path.join(root, 'roots-home');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, '{}');
  const grants = grantsFor({ writableRoots: ['~/shared-lib'] }, { autoagyHome: env.AUTOAGY_HOME, home });
  applySetup({ home, env, grants });
  const written = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(written.permissions.allow.includes(`write_file(${path.join(home, 'shared-lib')})`));
  assert.equal(written.allowNonWorkspaceAccess, false);
  assert.equal(RECOMMENDED_SETTINGS.allowNonWorkspaceAccess, false);
  // Teardown puts the setting back where it found it rather than at the default.
  applyTeardown({ home, env });
  assert.equal('allowNonWorkspaceAccess' in JSON.parse(fs.readFileSync(file, 'utf8')), false);
});

test('a path-shaped setting is resolved once, so the policy and the grants agree', () => {
  // `writableRoots` had two readers and they disagreed: the policy dropped a
  // relative entry without a word, while `writableRootGrants` resolved it
  // against whatever directory `autoagy setup` happened to run in. The declared
  // root was therefore never honoured, and a grant nobody could see accumulated
  // in the Antigravity settings — one more on every run from a new directory.
  const home = path.join(root, 'one-reading');
  fs.mkdirSync(path.join(home, '.gemini', 'autoagy'), { recursive: true });
  fs.writeFileSync(
    configPath({}, home),
    JSON.stringify({ writableRoots: ['rel/dir', 'file:///srv/build', '~/ok'], protectedPaths: ['.husky/**', '**/.husky/**'] }),
  );
  const { config, warnings } = loadConfig({ env: {}, home });
  assert.deepEqual(config.writableRoots, ['/srv/build', path.join(home, 'ok')]);
  assert.deepEqual(writableRootGrants(config, home), ['write_file(/srv/build)', `write_file(${path.join(home, 'ok')})`]);
  // A glob that can never match an absolute path is dropped too, and the one
  // that can is kept. `status` prints these; they used to be nothing at all.
  assert.deepEqual(config.protectedPaths, ['**/.husky/**']);
  assert.equal(warnings.filter((w) => w.startsWith('writableRoots[0]')).length, 1);
  assert.equal(warnings.filter((w) => w.startsWith('protectedPaths[0]')).length, 1);
});
