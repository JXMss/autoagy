// The hook that runs from outside the plugin system, so that a plugin which
// stopped loading cannot be silent about it. Measured behaviour it rests on is
// in docs/design.md: `~/.gemini/config/hooks.json` is loaded, survives
// `agy plugin disable` and `agy plugin install`, and two files registering the
// same name both run — which is why this has a name of its own.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { installTripwire, removeTripwire, tripwireInstalled, tripwireRegistered, tripwirePath, userHooksPath, installedPluginDir, TRIPWIRE_KEY } from '../plugin/lib/tripwire.mjs';

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-tripwire-')));
const home = path.join(root, 'home');
const autoagyHome = path.join(home, '.gemini', 'autoagy');
const pluginDir = path.join(home, '.gemini', 'config', 'plugins', 'autoagy');
const configJson = path.join(home, '.gemini', 'config', 'config.json');
after(() => fs.rmSync(root, { recursive: true, force: true }));

const healthyHooks = () =>
  JSON.stringify({ autoagy: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: '/usr/bin/node /x/bin/autoagy.mjs hook pre-tool-use --autoagy-home /y --home /z' }] }] } });

function setPlugin({ hooks = healthyHooks(), enabled = undefined } = {}) {
  fs.mkdirSync(pluginDir, { recursive: true });
  if (hooks === null) fs.rmSync(path.join(pluginDir, 'hooks.json'), { force: true });
  else fs.writeFileSync(path.join(pluginDir, 'hooks.json'), hooks);
  fs.mkdirSync(path.dirname(configJson), { recursive: true });
  fs.writeFileSync(configJson, JSON.stringify(enabled === undefined ? {} : { plugins: { autoagy: { enabled } } }));
}

const run = () => {
  const res = spawnSync(tripwirePath(autoagyHome), [], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  return res.stdout === '' ? null : JSON.parse(res.stdout);
};

setPlugin();
installTripwire({ autoagyHome, home, pluginDir });

test('installs a runnable program with its interpreter and every path pinned', () => {
  const text = fs.readFileSync(tripwirePath(autoagyHome), 'utf8');
  assert.equal(text.split('\n')[0], `#!${process.execPath}`);
  assert.ok(text.includes(pluginDir) && text.includes(configJson));
  assert.ok(!text.includes('__PLUGIN_DIR__') && !text.includes('__CONFIG_JSON__') && !text.includes('__HOOKS_JSON__'));
  assert.ok(text.includes(userHooksPath(home)), 'the refusal has to name the file it is registered in');
  // The key is spelled twice on purpose: the installed program is copied out of
  // the plugin and cannot import the lib that writes it. This pins the two
  // spellings together, so a rename on either side fails here.
  assert.ok(text.includes(TRIPWIRE_KEY), 'and the key to delete');
  assert.ok(tripwireInstalled({ autoagyHome, home }));
});

test('says nothing while the plugin is there and enabled', () => {
  setPlugin();
  assert.equal(run(), null, 'no opinion: autoagy\'s real hook is the one deciding');
});

test('refuses every tool call once the plugin is disabled', () => {
  setPlugin({ enabled: false });
  const out = run();
  assert.equal(out.decision, 'deny');
  assert.match(out.reason, /plugin is disabled/);
  // The reason has to say what to do instead, or the answer is to turn autoagy off.
  assert.match(out.reason, /autoagy mode off/);
  assert.match(out.reason, /autoagy teardown/);
});

test('refuses when the plugin hooks are gone, or no longer pinned', () => {
  setPlugin({ hooks: null });
  assert.match(run().reason, /missing or unreadable/);

  // `agy plugin install` writes the source tree's copy over the installed one,
  // which drops the absolute paths setup pinned into it.
  setPlugin({ hooks: JSON.stringify({ autoagy: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'node ./bin/autoagy.mjs hook pre-tool-use' }] }] } }) });
  assert.match(run().reason, /not pinned/);

  setPlugin({ hooks: JSON.stringify({ autoagy: { PostToolUse: [] } }) });
  assert.match(run().reason, /no longer registers/);

  setPlugin();
  assert.equal(run(), null);
});

test('the refusal names the way out that does not need a command', () => {
  // The lockout this exists for: the plugin directory is deleted by hand, so
  // every instruction that begins with `autoagy …` points at a program that is
  // no longer there. The registration is the only way back, and the refusal has
  // to say so rather than let the user guess.
  fs.rmSync(pluginDir, { recursive: true, force: true });
  const out = run();
  assert.equal(out.decision, 'deny');
  // A directory deleted by hand is the not-installed case, and it is named as
  // that now; `missing or unreadable` belongs to the narrower one above, where the
  // directory is there and its hooks.json is not.
  assert.match(out.reason, /plugin is not installed at/);
  assert.ok(out.reason.includes(userHooksPath(home)), 'the file to edit');
  assert.ok(out.reason.includes(TRIPWIRE_KEY), 'and the key to delete from it');
  setPlugin();
});

test('registration merges into the user hooks file and leaves the rest alone', () => {
  const file = userHooksPath(home);
  const mine = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: '/bin/true' }] }] };
  const existing = { ...JSON.parse(fs.readFileSync(file, 'utf8')), 'someone-else': mine };
  fs.writeFileSync(file, JSON.stringify(existing));

  installTripwire({ autoagyHome, home, pluginDir });
  const after1 = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(after1['someone-else'], mine, 'a user-level file may hold hooks that are not ours');
  assert.ok(after1[TRIPWIRE_KEY]);

  removeTripwire({ autoagyHome, home });
  const after2 = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(Object.keys(after2), ['someone-else']);
  assert.equal(fs.existsSync(tripwirePath(autoagyHome)), false);
});

test('a user hooks file that cannot be read is left exactly as it was, not replaced', () => {
  // Registration used to read the file with `readJson(file) ?? {}`, so one
  // syntax error became `{}` plus the tripwire: every hook the user had in there
  // gone, and exit 0.
  const file = userHooksPath(home);
  const broken = '{ "someone-else": { "PreToolUse": [] }, }\n';
  fs.writeFileSync(file, broken);
  assert.throws(() => installTripwire({ autoagyHome, home, pluginDir }), /not valid JSON/);
  assert.equal(fs.readFileSync(file, 'utf8'), broken, 'byte for byte');
  // Removal already refused to touch such a file; the two agree now.
  removeTripwire({ autoagyHome, home });
  assert.equal(fs.readFileSync(file, 'utf8'), broken);
  fs.rmSync(file, { force: true });
});

test('a file that held nothing but the tripwire is taken away with it', () => {
  fs.rmSync(userHooksPath(home), { force: true });
  installTripwire({ autoagyHome, home, pluginDir });
  assert.ok(fs.existsSync(userHooksPath(home)));
  removeTripwire({ autoagyHome, home });
  assert.equal(fs.existsSync(userHooksPath(home)), false);
  assert.equal(tripwireInstalled({ autoagyHome, home }), false);
});

// This one is structural rather than behavioural, and it earns its place: the
// wiring was written, verified by hand, and then silently removed by a later
// commit — leaving a tripwire that every test here passes and that nothing ever
// installs. A defence nobody calls is not a defence, and nothing else in this
// file could tell the difference.
test('it watches the directory agy loads from, not the one setup ran in', () => {
  // The failure this closes was found on a real machine: `autoagy setup` writes
  // the grants wherever it is run, so running it from a checkout baked the
  // checkout's path in here. That directory exists, so the tripwire answered
  // "all is well" while agy — which loads plugin hooks from one place only —
  // loaded nothing at all. Grants live, nothing reviewing, and the mechanism whose
  // whole job is to notice that was looking somewhere else.
  const checkout = path.join(root, 'some', 'checkout', 'plugin');
  fs.mkdirSync(checkout, { recursive: true });
  fs.writeFileSync(path.join(checkout, 'hooks.json'), healthyHooks());
  setPlugin();
  installTripwire({ autoagyHome, home, pluginDir: checkout });
  assert.equal(installedPluginDir(home), pluginDir);
  const text = fs.readFileSync(tripwirePath(autoagyHome), 'utf8');
  assert.ok(text.includes(pluginDir), 'the installed location is baked in');
  assert.ok(!text.includes(checkout), 'the caller does not get to name a different one');
  assert.equal(run(), null, 'and with a real plugin there it still says nothing');

  // With nothing installed there it refuses, and names that rather than blaming
  // the hooks file inside a directory that is not there.
  fs.rmSync(pluginDir, { recursive: true, force: true });
  const refused = run();
  assert.equal(refused.decision, 'deny');
  assert.match(refused.reason, /plugin is not installed at/);
  assert.match(refused.reason, new RegExp(pluginDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(refused.reason, /agy plugin install/);
  setPlugin();
  installTripwire({ autoagyHome, home });
});

test('setup installs the tripwire and teardown removes it', () => {
  const bin = fs.readFileSync(new URL('../plugin/bin/autoagy.mjs', import.meta.url), 'utf8');
  const body = (name) => {
    const start = bin.indexOf(`function ${name}(`);
    assert.ok(start > 0, `${name} not found`);
    return bin.slice(start, bin.indexOf('\n}', start));
  };
  assert.match(body('setup'), /installTripwire\(/, 'setup must install it, or the grants it guards stand alone');
  // And unconditionally on where this command runs from. It used to be guarded by
  // `PLUGIN_DIR.startsWith(installedRoot)` — the one case where the tripwire is
  // least needed — so the case that needed it (grants written, plugin never
  // installed) got nothing.
  assert.doesNotMatch(body('setup'), /if \(!dryRun && PLUGIN_DIR\.startsWith/, 'the tripwire must not be conditional on the plugin already being installed');
  assert.match(body('teardown'), /removeTripwire\(/, 'teardown must remove it, or every tool call is refused after uninstall');
  assert.match(body('status'), /tripwireInstalled\(/, 'status must say whether it is there');
});

// The other half of the same failure, in the uninstaller, and two invariants
// about where the removal sits. It once lived inside `if (fs.existsSync(BIN))`,
// so the case that needed it most — the plugin directory already gone — skipped
// it. It then moved to the very top, before the grants were reverted, so a
// revert that failed had already taken away the one thing standing behind the
// grants it left. Both are positions, which is why they are asserted rather than
// described; the tests below check the behaviour.
test('the uninstaller removes the tripwire only after the grants are out, and whether or not an installed copy exists', () => {
  const text = fs.readFileSync(new URL('../scripts/install.mjs', import.meta.url), 'utf8');
  const start = text.indexOf('function uninstall(');
  assert.ok(start > 0, 'uninstall() not found');
  const body = text.slice(start, text.indexOf('\n}', start));
  const removal = body.indexOf('removeTripwire(');
  assert.ok(removal > 0, 'uninstall must remove it, or a half-removed install has no way back');
  const stop = body.indexOf('if (!reverted)');
  assert.ok(stop > 0, 'uninstall must stop when the grants did not come out');
  assert.ok(body.indexOf('existsSync(BIN)') < stop && body.indexOf('applyTeardown(') < stop, 'both ways of reverting come before that check');
  assert.ok(removal > stop, 'and the removal after it — outside the existsSync(BIN) branch, and only once the grants are gone');
});

test('an uninstall whose grants cannot be reverted keeps everything, --purge included', () => {
  // The reported failure: a revert refused (settings not valid JSON), then the
  // tripwire and the plugin removed anyway, and `--purge` deleting the record
  // that makes the grants revertable at all. A second run found no record and
  // printed "autoagy uninstalled." with exit 0 over grants nobody could revert.
  const script = fileURLToPath(new URL('../scripts/install.mjs', import.meta.url));
  const custom = path.join(root, 'unrevertable');
  installTripwire({ autoagyHome: custom, home, pluginDir });
  const settingsFile = path.join(home, '.gemini', 'antigravity-cli', 'settings.json');
  fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
  fs.writeFileSync(path.join(custom, 'setup.json'), JSON.stringify({ time: new Date().toISOString(), settingsFile, addedGrants: ['command(*)'], priorValues: {} }));
  fs.writeFileSync(settingsFile, '{ "permissions": { "allow": ["command(*)"] }, }');
  fs.rmSync(pluginDir, { recursive: true, force: true });

  for (let attempt = 1; attempt <= 2; attempt++) {
    const res = spawnSync(process.execPath, [script, '--uninstall', '--purge'], { encoding: 'utf8', env: { HOME: home, PATH: '/nonexistent' } });
    assert.equal(res.status, 1, `attempt ${attempt}: ${res.stdout}`);
    assert.doesNotMatch(res.stdout, /autoagy uninstalled\./, `attempt ${attempt}`);
    assert.match(res.stderr, /could not be taken out/);
    assert.ok(fs.existsSync(path.join(custom, 'setup.json')), `attempt ${attempt}: the record that makes the grants revertable survives --purge`);
    assert.ok(tripwireInstalled({ autoagyHome: custom, home }), `attempt ${attempt}: and so does the tripwire standing behind them`);
  }

  // Once the file is repaired, the same command finishes the job.
  fs.writeFileSync(settingsFile, JSON.stringify({ permissions: { allow: ['command(*)'] } }));
  const res = spawnSync(process.execPath, [script, '--uninstall', '--purge'], { encoding: 'utf8', env: { HOME: home, PATH: '/nonexistent' } });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /autoagy uninstalled\./);
  assert.deepEqual(JSON.parse(fs.readFileSync(settingsFile, 'utf8')).permissions.allow, []);
  assert.equal(tripwireInstalled({ autoagyHome: custom, home }), false);
  assert.equal(fs.existsSync(custom), false, 'and --purge now removes the state');
  fs.rmSync(settingsFile, { force: true });
});

test('an install whose plugin directory was deleted by hand still uninstalls', () => {
  // The lockout, end to end: delete the plugin directory, then run the
  // documented uninstall. PATH is emptied so the `agy` on it cannot be reached
  // and the script takes its fallback path — which in this sandbox only ever
  // touches the fake home.
  installTripwire({ autoagyHome, home, pluginDir });
  fs.rmSync(pluginDir, { recursive: true, force: true });
  const script = fileURLToPath(new URL('../scripts/install.mjs', import.meta.url));
  const res = spawnSync(process.execPath, [script, '--uninstall'], { encoding: 'utf8', env: { HOME: home, PATH: '/nonexistent' } });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /Removed the tripwire/);
  assert.match(res.stdout, /autoagy uninstalled\./);
  assert.equal(tripwireInstalled({ autoagyHome, home }), false, 'nothing is left refusing every tool call');
});

test('the program and its registration are reported apart', () => {
  // They fail apart in both directions, and the one that matters is a
  // registration whose program is gone: the hook runs a command that is not
  // there, so every tool call fails — while `tripwireInstalled` wants both
  // halves and therefore says there is nothing here.
  installTripwire({ autoagyHome, home, pluginDir });
  assert.ok(tripwireRegistered({ home }));
  fs.rmSync(tripwirePath(autoagyHome), { force: true });
  assert.equal(tripwireInstalled({ autoagyHome, home }), false);
  assert.ok(tripwireRegistered({ home }), 'the registration outlives the program it names');
  removeTripwire({ autoagyHome, home });
  assert.equal(tripwireRegistered({ home }), false);
});

test('--dry-run says what the real run would do to a half-removed install', () => {
  // A preview that skips the half causing the lockout is worse than no preview:
  // the state it under-reports is the one this path exists for.
  const script = fileURLToPath(new URL('../scripts/install.mjs', import.meta.url));
  installTripwire({ autoagyHome, home, pluginDir });
  fs.rmSync(tripwirePath(autoagyHome), { force: true });

  const res = spawnSync(process.execPath, [script, '--uninstall', '--dry-run'], { encoding: 'utf8', env: { HOME: home, PATH: '/nonexistent' } });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /Would remove the tripwire from /);
  assert.ok(res.stdout.includes(userHooksPath(home)), 'naming the file it would be taken out of');
  // The program is already gone, so there is nothing to claim about it.
  assert.ok(!res.stdout.includes(`(${tripwirePath(autoagyHome)})`));
  removeTripwire({ autoagyHome, home });
});

test('the uninstaller finds the tripwire where the plugin put it', () => {
  // `AUTOAGY_HOME` moves it. The registration is the half that causes the
  // lockout, and an uninstaller that assumed the default home would clear that
  // one while leaving the program behind — or miss both.
  const custom = path.join(root, 'custom-home');
  installTripwire({ autoagyHome: custom, home, pluginDir });
  const script = fileURLToPath(new URL('../scripts/install.mjs', import.meta.url));
  const res = spawnSync(process.execPath, [script, '--uninstall'], { encoding: 'utf8', env: { HOME: home, AUTOAGY_HOME: custom, PATH: '/nonexistent' } });
  assert.equal(res.status, 0, res.stderr);
  assert.ok(res.stdout.includes(custom), 'the home it used is the one it names');
  assert.equal(fs.existsSync(path.join(custom, 'bin', 'tripwire.mjs')), false, 'the program goes with it');
  assert.equal(tripwireRegistered({ home }), false, 'and so does the registration');
});

test('the uninstaller finds a custom home with nothing in the environment to say so', () => {
  // The reported failure, end to end: installed with `AUTOAGY_HOME` set, later
  // uninstalled from a shell that does not have it — and with the plugin
  // directory already gone, so no pinned `hooks.json` carries it either. What
  // is left is the registration, which names the program by absolute path, and
  // the uninstaller has to follow it to the home the install wrote to.
  const script = fileURLToPath(new URL('../scripts/install.mjs', import.meta.url));
  const custom = path.join(root, 'registration-only');
  installTripwire({ autoagyHome: custom, home, pluginDir });
  fs.mkdirSync(custom, { recursive: true });
  fs.writeFileSync(
    path.join(custom, 'setup.json'),
    JSON.stringify({ time: new Date().toISOString(), settingsFile: path.join(home, 'settings.json'), addedGrants: ['command(*)'], priorValues: {} }),
  );
  fs.writeFileSync(path.join(home, 'settings.json'), JSON.stringify({ permissions: { allow: ['command(*)'] } }));
  fs.rmSync(pluginDir, { recursive: true, force: true });

  const res = spawnSync(process.execPath, [script, '--uninstall'], { encoding: 'utf8', env: { HOME: home, PATH: '/nonexistent' } });
  assert.equal(res.status, 0, res.stderr);
  assert.doesNotMatch(res.stdout, /No setup record found/, 'the record is where the registration says the install is');
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(home, 'settings.json'), 'utf8')).permissions.allow, [], 'and the grants come back out');
  removeTripwire({ autoagyHome: custom, home });
});
