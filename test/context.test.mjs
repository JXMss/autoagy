import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { detectSandbox, HOST_INSPECTABLE_PLATFORMS } from '../plugin/lib/context.mjs';
import { makeSandboxDirs, configWith } from './helpers.mjs';

const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

const cliHost = (flags = {}) => ({ kind: 'cli', cwd: dirs.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [], ...flags } });
const detect = (options) => detectSandbox({ config: configWith(), host: null, appDataDir: dirs.appData, own: { active: false, required: false }, ...options });

test('the settings file cannot report an active sandbox where the process arguments cannot be read', () => {
  // Windows has no terminal sandbox, and --dangerously-skip-permissions cannot
  // be seen there. autoagy setup writes the very values the settings file is
  // checked for, so trusting it would report a sandbox that does not exist.
  const out = detect({ platform: 'win32' });
  assert.equal(out.active, false);
  assert.equal(out.source, 'platform');
  assert.match(out.detail, /cannot read the agy process arguments/);
  assert.ok(!HOST_INSPECTABLE_PLATFORMS.includes('win32'));
});

test('the IDE case still reads the sandbox state from the settings file', () => {
  // On Linux and macOS the host is only sometimes identifiable — an IDE user
  // relies on this branch, and there the flag could have been read if present.
  for (const platform of HOST_INSPECTABLE_PLATFORMS) {
    const out = detect({ platform });
    assert.equal(out.active, true, platform);
    assert.equal(out.source, 'settings', platform);
  }
});

test('detected flags and an explicit config still decide the answer', () => {
  assert.equal(detect({ platform: 'win32', config: configWith({ sandbox: 'on' }) }).active, true, 'config.sandbox "on" is the documented escape hatch');
  assert.equal(detect({ platform: 'linux', host: cliHost({ skipPermissions: true }) }).active, false);
  assert.equal(detect({ platform: 'linux', host: cliHost({ skipPermissions: true }) }).source, 'flag');
  // Nowhere to read the arguments, no settings file, nothing declared.
  assert.equal(detect({ platform: 'win32', appDataDir: null }).source, 'platform');
});
