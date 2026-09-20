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

test('installs a runnable program with its interpreter and both paths pinned', () => {
  const text = fs.readFileSync(tripwirePath(autoagyHome), 'utf8');
  assert.equal(text.split('\n')[0], `#!${process.execPath}`);
  assert.ok(text.includes(pluginDir) && text.includes(configJson));
  assert.ok(!text.includes('__PLUGIN_DIR__') && !text.includes('__CONFIG_JSON__'));
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
