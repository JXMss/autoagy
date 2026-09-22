import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { applySetup, applyTeardown, pinHookCommands, planSetup, cliSettingsPath, grantsFor, writableRootGrants, trustedDomainGrants, RECOMMENDED_SETTINGS, halfInstalledRecord, staleGrants, effectiveSetting } from '../plugin/lib/setup.mjs';
import { executorPath } from '../plugin/lib/tokens.mjs';
import { configPath, loadConfig } from '../plugin/lib/config.mjs';
import { configWith } from './helpers.mjs';
import { removeTripwire, tripwireInstalled, tripwireRegistered, userHooksPath, registeredTripwirePath, registeredAutoagyHome, TRIPWIRE_KEY } from '../plugin/lib/tripwire.mjs';

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
  // symlinks to decide where that write lands. A missing key is agy's own
  // false, so nothing is written for it.
  assert.equal(effectiveSetting(after1, 'allowNonWorkspaceAccess'), false);
  assert.equal('allowNonWorkspaceAccess' in after1, false);
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

test('setup without the plugin installed is recognised, from wherever the question is asked', () => {
  // Found on a real machine: grants written by `autoagy setup`, nothing in
  // ~/.gemini/config/plugins, no hook able to run. The first version of this
  // check asked "is this command running from the install location", which a
  // status run from a checkout beside a real install answers "no" — shouting NOT
  // INSTALLED at a plugin that is there. The question belongs to the install
  // location, which is why it takes a home and not a directory.
  const home = path.join(root, 'half-home');
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  fs.mkdirSync(autoagyHome, { recursive: true });
  assert.equal(halfInstalledRecord({ autoagyHome, home }), null, 'no setup record, nothing to say');

  fs.writeFileSync(path.join(autoagyHome, 'setup.json'), JSON.stringify({ time: '2026-09-21T02:10:05.946Z', addedGrants: ['command(*)', 'mcp(*)', 'execute_url(*)'] }));
  assert.deepEqual(halfInstalledRecord({ autoagyHome, home }).addedGrants, ['command(*)', 'mcp(*)', 'execute_url(*)'], 'grants and no plugin: the fail-open');

  const installed = path.join(home, '.gemini', 'config', 'plugins', 'autoagy');
  fs.mkdirSync(installed, { recursive: true });
  fs.writeFileSync(path.join(installed, 'hooks.json'), '{}');
  assert.equal(halfInstalledRecord({ autoagyHome, home }), null, 'a plugin at the install location answers it, whoever is asking');

  fs.writeFileSync(path.join(autoagyHome, 'setup.json'), JSON.stringify({ time: 'x', addedGrants: [] }));
  fs.rmSync(installed, { recursive: true, force: true });
  assert.equal(halfInstalledRecord({ autoagyHome, home }), null, 'setup --no-settings wrote no grants, so there is nothing live');
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
  assert.deepEqual(grantsFor({}, { autoagyHome, home }), ['command(*)', 'mcp(*)', 'execute_url(*)', 'read_file(/)']);

  // The executor shape names one program in place of the wildcard.
  assert.deepEqual(grantsFor({ commandGrant: 'executor' }, { autoagyHome, home })[0], `command(${executorPath(autoagyHome)})`);

  // `allowNonWorkspaceAccess: false` would otherwise make writableRoots a dead
  // letter: agy refuses the write whatever autoagy says about it.
  const config = { writableRoots: ['~/shared-lib', '/srv/build ', '', 42] };
  assert.deepEqual(writableRootGrants(config, home), [`write_file(${path.join(home, 'shared-lib')})`, 'write_file(/srv/build)']);
  assert.deepEqual(grantsFor(config, { autoagyHome, home }).slice(4), writableRootGrants(config, home));
});

test('networkGrants "all" is the one way to read_url(*), and no list entry widens into it', () => {
  const home = path.join(root, 'all-network-home');
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  const all = { networkGrants: 'all', trustedDomains: ['docs.python.org', '*'] };
  assert.deepEqual(trustedDomainGrants(all), { grants: ['read_url(*)'], skipped: [] });
  assert.equal(grantsFor(all, { autoagyHome, home }).at(-1), 'read_url(*)');
  assert.ok(!grantsFor(all, { autoagyHome, home }).includes('read_url(docs.python.org)'), 'the wildcard already covers it');
  assert.equal(loadConfig({ env: { AUTOAGY_HOME: path.join(root, 'no-config') }, home }).config.networkGrants, 'none', 'opt-in');
  // A "*" in the list is still skipped under "trusted-domains".
  assert.deepEqual(trustedDomainGrants({ networkGrants: 'trusted-domains', trustedDomains: ['*'] }).grants, []);
});

test('reads anywhere are granted unless readGrant says none, and writes never are', () => {
  // Measured on agy 1.2.7: with `allowNonWorkspaceAccess: false`, `view_file
  // /etc/hostname` asked "Reason: outside workspace" after autoagy had allowed
  // it — the cap on writes caps reads too. Codex reads anywhere without asking,
  // and a credential read has already been reviewed before agy is asked.
  const home = path.join(root, 'read-home');
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  const grants = grantsFor({}, { autoagyHome, home });
  assert.ok(grants.includes('read_file(/)'));
  assert.ok(!grants.some((g) => /^write_file\((\*|\/)\)$/.test(g)), 'the write cap stays');
  assert.ok(!grantsFor({ readGrant: 'none' }, { autoagyHome, home }).includes('read_file(/)'));
  assert.equal(loadConfig({ env: { AUTOAGY_HOME: path.join(root, 'no-config') }, home }).config.readGrant, 'anywhere');
});

test('read_url grants are opt-in, per domain, and never a wildcard', () => {
  const home = path.join(root, 'network-home');
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  const domains = ['localhost', 'docs.python.org', '*.github.com', 'API.Example.COM'];

  // Off by default, which is the behavior every install has had: autoagy can
  // approve a fetch, but agy's own permission prompt for an unknown domain is the
  // one thing a hook `allow` cannot answer.
  assert.deepEqual(trustedDomainGrants({ trustedDomains: domains }), { grants: [], skipped: [] });
  assert.deepEqual(grantsFor({ trustedDomains: domains }, { autoagyHome, home }), ['command(*)', 'mcp(*)', 'execute_url(*)', 'read_file(/)']);

  // Opted in: the list the user already wrote, one grant each. A leading `*.`
  // comes off because `isTrustedHost` treats the two spellings as one rule.
  const on = trustedDomainGrants({ networkGrants: 'trusted-domains', trustedDomains: domains });
  assert.deepEqual(on.grants, ['read_url(localhost)', 'read_url(docs.python.org)', 'read_url(github.com)', 'read_url(api.example.com)']);
  assert.deepEqual(on.skipped, []);
  assert.deepEqual(grantsFor({ networkGrants: 'trusted-domains', trustedDomains: ['example.com'] }, { autoagyHome, home }).at(-1), 'read_url(example.com)');

  // The line that is not crossed: a read_url rule is also the terminal sandbox's
  // network allowlist, so `read_url(*)` must not be reachable from a config file.
  // An entry that is not a plain hostname is reported, not widened.
  const wild = trustedDomainGrants({ networkGrants: 'trusted-domains', trustedDomains: ['*', '*.*', 'ex*mple.com', 'http://x/y', 'a b', ''] });
  assert.deepEqual(wild.grants, []);
  assert.deepEqual(wild.skipped, ['*', '*.*', 'ex*mple.com', 'http://x/y', 'a b']);
});

test('setup writes the read_url grants, and teardown takes exactly those away', () => {
  const home = path.join(root, 'network-setup-home');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  // A rule the user put there themselves must survive the round trip: teardown
  // removes what the setup record says it added, not everything that looks like it.
  const original = { permissions: { allow: ['read_url(mine.example)'] } };
  fs.writeFileSync(file, JSON.stringify(original));
  const config = { networkGrants: 'trusted-domains', trustedDomains: ['docs.python.org'] };
  applySetup({ home, env, grants: grantsFor(config, { autoagyHome: env.AUTOAGY_HOME, home }) });
  const written = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(written.permissions.allow.includes('read_url(docs.python.org)'));
  assert.ok(!written.permissions.allow.includes('read_url(*)'));
  assert.equal(applyTeardown({ home, env }).found, true);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow, ['read_url(mine.example)']);
});

test('a missing allowNonWorkspaceAccess is agy\'s own false, and a true is still turned off and put back', () => {
  // The sequence from a real install, agy 1.2.7: the user had `true`, setup
  // wrote `false`, and trusting a new folder made agy save its settings without
  // the key — it drops false booleans. A headless write outside the workspace
  // was refused all the same, so missing means false.
  const home = path.join(root, 'nonworkspace-home');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const read = () => JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify({ enableTerminalSandbox: true, toolPermission: 'proceed-in-sandbox', allowNonWorkspaceAccess: true }));

  // An explicit true is a real opening, and setup still closes it.
  const first = applySetup({ home, env, grants: [] });
  assert.deepEqual(first.changes, [{ key: 'allowNonWorkspaceAccess', from: true, to: false }]);
  assert.equal(read().allowNonWorkspaceAccess, false);

  // agy saves the file and the key is gone. Nothing is open, so a later setup
  // has nothing to change and takes no backup.
  const { allowNonWorkspaceAccess, ...dropped } = read();
  fs.writeFileSync(file, JSON.stringify(dropped));
  const again = applySetup({ home, env, grants: [] });
  assert.deepEqual(again.changes, []);
  assert.equal(again.backup, null);

  // Teardown still puts back what the user had before the first setup.
  applyTeardown({ home, env });
  assert.equal(read().allowNonWorkspaceAccess, true);

  // A file that cannot be read says nothing about what agy will do.
  assert.equal(effectiveSetting(null, 'allowNonWorkspaceAccess'), undefined);
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
  assert.equal(effectiveSetting(written, 'allowNonWorkspaceAccess'), false);
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

const SOURCE_PLUGIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'plugin');

/**
 * A copy of the plugin whose `hooks.json` carries the pin `autoagy setup`
 * writes, so the CLI can be run against it the way an installed plugin is run.
 */
function pinnedPlugin({ root, configHome, home }) {
  const dir = path.join(root, 'plugin');
  fs.cpSync(SOURCE_PLUGIN, dir, { recursive: true });
  const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(path.join(dir, 'bin', 'autoagy.mjs'))} hook pre-tool-use --autoagy-home ${JSON.stringify(configHome)} --home ${JSON.stringify(home)}`;
  fs.writeFileSync(path.join(dir, 'hooks.json'), JSON.stringify({ autoagy: { PreToolUse: [{ matcher: '*', hooks: [{ command }] }] } }));
  return dir;
}

test('narrowing the configuration narrows the grants, and only the ones setup added', () => {
  // Setup used to only ever add: turning networkGrants back to "none", dropping a
  // writableRoots entry or moving to the executor left the old grants in place,
  // while setup printed "read_url(...) is not granted" and status "network
  // grants none" — both worked out from the configuration, not the file.
  const home = path.join(root, 'narrowing');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  const roots = path.join(home, 'shared');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.mkdirSync(roots, { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ permissions: { allow: ['read_url(docs.example.org)'] } }));
  const where = { autoagyHome: env.AUTOAGY_HOME, home };
  const wide = configWith({ networkGrants: 'trusted-domains', trustedDomains: ['example.com'], writableRoots: [roots] });
  applySetup({ home, env, grants: grantsFor(wide, where) });
  const allow = () => JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow;
  assert.ok(allow().includes('read_url(example.com)') && allow().includes(`write_file(${roots})`) && allow().includes('command(*)'));

  const narrow = configWith({ networkGrants: 'none', commandGrant: 'executor' });
  assert.deepEqual(staleGrants(narrow, allow(), where).sort(), ['command(*)', 'read_url(example.com)', `write_file(${roots})`].sort(), 'status can name them before setup runs');
  const report = applySetup({ home, env, grants: grantsFor(narrow, where) });
  assert.deepEqual(report.removeGrants.sort(), ['command(*)', 'read_url(example.com)', `write_file(${roots})`].sort());
  assert.ok(!allow().includes('read_url(example.com)') && !allow().includes(`write_file(${roots})`) && !allow().includes('command(*)'));
  assert.ok(allow().includes('read_url(docs.example.org)'), "a grant the user wrote is not setup's to take");
  assert.deepEqual(staleGrants(narrow, allow(), where), []);

  // And teardown still takes back exactly what is left of autoagy's.
  applyTeardown({ home, env });
  assert.deepEqual(allow(), ['read_url(docs.example.org)']);
});

test('setup writes no grant when the file its tripwire registers in cannot be read', () => {
  // The tripwire is what stands behind the grants. If registering it would mean
  // overwriting the user's own hooks file, neither happens: grants whose tripwire
  // could not be registered are the fail-open it exists to catch.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-hooks-'));
  try {
    const pinned = path.join(root2, 'pinned-autoagy-home');
    const userHome = path.join(root2, 'user-home');
    fs.mkdirSync(userHome, { recursive: true });
    const pluginDir = pinnedPlugin({ root: root2, configHome: pinned, home: userHome });
    const settingsFile = cliSettingsPath(userHome);
    fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
    fs.writeFileSync(settingsFile, JSON.stringify({ permissions: { allow: [] } }));
    const hooksFile = path.join(userHome, '.gemini', 'config', 'hooks.json');
    fs.mkdirSync(path.dirname(hooksFile), { recursive: true });
    const broken = '{ "mine": { "PreToolUse": [] }, }';
    fs.writeFileSync(hooksFile, broken);

    const res = spawnSync(process.execPath, [path.join(pluginDir, 'bin', 'autoagy.mjs'), 'setup'], { env: { HOME: userHome, PATH: process.env.PATH }, encoding: 'utf8' });
    assert.equal(res.status, 1, res.stdout);
    assert.match(res.stderr, /not valid JSON/);
    assert.match(res.stderr, /no grants were written/);
    assert.deepEqual(JSON.parse(fs.readFileSync(settingsFile, 'utf8')).permissions.allow, [], 'no grant stands without its tripwire');
    assert.equal(fs.readFileSync(hooksFile, 'utf8'), broken, 'and the user\'s file is untouched');
  } finally {
    fs.rmSync(root2, { recursive: true, force: true });
  }
});

test('a teardown that cannot revert the grants keeps the tripwire that stands behind them', () => {
  // It used to remove the tripwire first and then report "nothing was changed
  // and nothing was removed" — with the grants still in place and nothing left
  // to notice if the plugin stopped loading.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-td-'));
  try {
    const pinned = path.join(root2, 'pinned-autoagy-home');
    const userHome = path.join(root2, 'user-home');
    fs.mkdirSync(userHome, { recursive: true });
    const pluginDir = pinnedPlugin({ root: root2, configHome: pinned, home: userHome });
    const settingsFile = cliSettingsPath(userHome);
    fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
    fs.writeFileSync(settingsFile, JSON.stringify({ permissions: { allow: [] } }));
    const run = (...argv) => spawnSync(process.execPath, [path.join(pluginDir, 'bin', 'autoagy.mjs'), ...argv], { env: { HOME: userHome, PATH: process.env.PATH }, encoding: 'utf8' });
    assert.equal(run('setup').status, 0);
    assert.ok(tripwireInstalled({ autoagyHome: pinned, home: userHome }));

    const good = fs.readFileSync(settingsFile, 'utf8');
    fs.writeFileSync(settingsFile, `${good.trimEnd().slice(0, -1)}, }`);
    const refused = run('teardown');
    assert.equal(refused.status, 1, refused.stdout);
    assert.match(refused.stderr, /not valid JSON/);
    assert.doesNotMatch(refused.stdout, /Removed the tripwire/);
    assert.ok(tripwireInstalled({ autoagyHome: pinned, home: userHome }), 'the tripwire is still there');
    assert.ok(fs.existsSync(path.join(pinned, 'setup.json')), 'and so is the record');

    fs.writeFileSync(settingsFile, good);
    const removed = run('teardown');
    assert.equal(removed.status, 0, removed.stderr);
    assert.match(removed.stdout, /Removed the tripwire/);
    assert.equal(tripwireInstalled({ autoagyHome: pinned, home: userHome }), false);
    assert.ok(!JSON.parse(fs.readFileSync(settingsFile, 'utf8')).permissions.allow.includes('command(*)'));
  } finally {
    fs.rmSync(root2, { recursive: true, force: true });
  }
});

test('teardown reverts through the pin, not through the environment', () => {
  // The bug this covers was in the wiring, not in the library: `setup` wrote the
  // record into the pinned home while `teardown` looked for it in whatever
  // `HOME`/`AUTOAGY_HOME` the current shell had. It then printed "no setup
  // record" and left `command(*)`, `mcp(*)` and `execute_url(*)` standing — the
  // fail-open the README opens with, together with the tripwire this command had
  // already removed.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-pin-'));
  try {
    const pinned = path.join(root2, 'pinned-autoagy-home');
    const userHome = path.join(root2, 'user-home');
    const elsewhere = path.join(root2, 'elsewhere');
    fs.mkdirSync(userHome, { recursive: true });
    fs.mkdirSync(path.join(elsewhere, '.gemini'), { recursive: true });
    const pluginDir = pinnedPlugin({ root: root2, configHome: pinned, home: userHome });
    const settingsFile = cliSettingsPath(userHome);
    fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
    fs.writeFileSync(settingsFile, JSON.stringify({ model: 'Gemini Flash', permissions: { allow: [] } }, null, 2));

    // A shell that knows nothing: no AUTOAGY_HOME, and a `HOME` of its own.
    const env = { HOME: elsewhere, PATH: process.env.PATH };
    const run = (...argv) => spawnSync(process.execPath, [path.join(pluginDir, 'bin', 'autoagy.mjs'), ...argv], { env, encoding: 'utf8' });

    const installed = run('setup');
    assert.equal(installed.status, 0, installed.stderr);
    const after = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
    assert.ok(after.permissions.allow.includes('command(*)'), 'setup wrote the grants into the pinned home');
    assert.ok(fs.existsSync(path.join(pinned, 'setup.json')), 'and the record that makes them revertable');
    assert.ok(fs.readFileSync(path.join(pluginDir, 'hooks.json'), 'utf8').includes('--autoagy-home'), 'and pinned the hooks');

    const removed = run('teardown');
    assert.equal(removed.status, 0, removed.stderr);
    assert.doesNotMatch(removed.stdout, /No setup record found/, 'the record is in the pinned home, and that is where teardown looks');
    const reverted = JSON.parse(fs.readFileSync(settingsFile, 'utf8'));
    assert.deepEqual(reverted.permissions.allow, [], 'the grants are gone whatever the shell had set');
    assert.equal(reverted.model, 'Gemini Flash');
    assert.equal(fs.existsSync(path.join(pinned, 'setup.json')), false);
  } finally {
    fs.rmSync(root2, { recursive: true, force: true });
  }
});

test('the tripwire is removed where it is registered, not where this shell would put it', () => {
  // `install.mjs` and `teardown` both have to work when the home they resolve
  // differs from the one the install pinned: the registration names the program
  // by absolute path, so it — not the environment — is the ground truth.
  const root3 = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-pin-tw-'));
  try {
    const registered = path.join(root3, 'pinned', 'bin', 'tripwire.mjs');
    const hooksFile = userHooksPath(root3);
    fs.mkdirSync(path.dirname(registered), { recursive: true });
    fs.writeFileSync(registered, '// the registered program\n');
    fs.mkdirSync(path.dirname(hooksFile), { recursive: true });
    fs.writeFileSync(hooksFile, JSON.stringify({ [TRIPWIRE_KEY]: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: JSON.stringify(registered) }] }] } }));

    assert.equal(registeredTripwirePath(root3), registered);
    assert.equal(registeredAutoagyHome(root3), path.dirname(path.dirname(registered)));
    assert.equal(tripwireInstalled({ autoagyHome: path.join(root3, 'other'), home: root3 }), true, 'the registration names where the program is');

    // Asked to remove it "from" a different home entirely.
    const removed = removeTripwire({ autoagyHome: path.join(root3, 'other'), home: root3 });
    assert.equal(removed.script, true);
    assert.equal(removed.path, registered);
    assert.equal(fs.existsSync(registered), false, 'the registered program is the one that goes');
    assert.equal(tripwireRegistered({ home: root3 }), false);
  } finally {
    fs.rmSync(root3, { recursive: true, force: true });
  }
});

test('a settings file that cannot be parsed stops the revert instead of being replaced', () => {
  // The destructive half of the same bug class as the pin: `applyTeardown` read
  // the settings with `catch { settings = {} }` and then wrote that object back.
  // Measured with a single syntax error in the file — the user's model, theme,
  // mcpServers and existing deny rules went with it, the grants it was supposed
  // to remove stayed (the reader could not see them, so nothing was reported as
  // left), and the record was deleted, making them unrevertable.
  const home = path.join(root, 'broken-settings');
  const env = { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy') };
  const file = cliSettingsPath(home);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ model: 'Gemini Flash', permissions: { allow: [] } }, null, 2));
  applySetup({ home, env });
  // Leave the file the way a hand-edit would: grants and all, plus one syntax
  // error (a trailing comma is the ordinary shape).
  const installed = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, `${JSON.stringify(installed, null, 2).replace(/\n}$/, ',\n}')}`);
  const after = fs.readFileSync(file, 'utf8');
  assert.throws(() => applySetup({ home, env }), /not valid JSON/, 'setup refuses too, rather than overwriting what it cannot read');

  const report = applyTeardown({ home, env });
  assert.equal(report.found, true);
  assert.equal(report.unreadable, true);
  assert.equal(fs.readFileSync(file, 'utf8'), after, 'the file it could not read is left exactly as it was');
  assert.ok(fs.existsSync(path.join(env.AUTOAGY_HOME, 'setup.json')), 'and the record survives, so this is still revertable');

  // With the file repaired, the same call reverts it.
  fs.writeFileSync(file, JSON.stringify(installed, null, 2));
  const done = applyTeardown({ home, env });
  assert.equal(done.unreadable, undefined);
  assert.ok(done.removedGrants.includes('command(*)'));
  assert.ok(!JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow.includes('command(*)'));
});
