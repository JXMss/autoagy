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
import { installTripwire, removeTripwire, tripwireInstalled, tripwirePath, userHooksPath, TRIPWIRE_KEY } from '../plugin/lib/tripwire.mjs';

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
  assert.match(out.reason, /missing or unreadable/);
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
test('setup installs the tripwire and teardown removes it', () => {
  const bin = fs.readFileSync(new URL('../plugin/bin/autoagy.mjs', import.meta.url), 'utf8');
  const body = (name) => {
    const start = bin.indexOf(`function ${name}(`);
    assert.ok(start > 0, `${name} not found`);
    return bin.slice(start, bin.indexOf('\n}', start));
  };
  assert.match(body('setup'), /installTripwire\(/, 'setup must install it, or the grants it guards stand alone');
  assert.match(body('teardown'), /removeTripwire\(/, 'teardown must remove it, or every tool call is refused after uninstall');
  assert.match(body('status'), /tripwireInstalled\(/, 'status must say whether it is there');
});

// The other half of the same failure, in the uninstaller. The call used to sit
// inside `if (fs.existsSync(BIN))`, so the case that needed it most — the plugin
// directory already gone — skipped it, and the script said "uninstalled"
// anyway. The invariant is the position, which is why it is asserted rather
// than described.
test('the uninstaller removes the tripwire before it asks for an installed copy', () => {
  const text = fs.readFileSync(new URL('../scripts/install.mjs', import.meta.url), 'utf8');
  const start = text.indexOf('function uninstall(');
  assert.ok(start > 0, 'uninstall() not found');
  const body = text.slice(start, text.indexOf('\n}', start));
  const removal = body.indexOf('removeTripwire(');
  assert.ok(removal > 0, 'uninstall must remove it, or a half-removed install has no way back');
  const guard = body.indexOf('existsSync(BIN)');
  assert.ok(guard > 0 && removal < guard, 'and outside the existsSync(BIN) branch, which is the case it exists for');
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
