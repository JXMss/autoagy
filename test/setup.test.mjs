import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { applySetup, applyTeardown, pinNodeInHooks, planSetup, cliSettingsPath } from '../plugin/lib/setup.mjs';

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
  assert.equal(after1.allowNonWorkspaceAccess, true);
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

test('pinNodeInHooks rewrites bare node commands', () => {
  const dir = path.join(root, 'plugin');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'hooks.json'),
    JSON.stringify({ autoagy: { PreToolUse: [{ matcher: '*', hooks: [{ command: 'node ./bin/autoagy.mjs hook pre-tool-use' }] }], PostInvocation: [{ command: 'node ./bin/autoagy.mjs hook post-invocation' }] } }),
  );
  assert.equal(pinNodeInHooks(dir, '/opt/node 22/bin/node').changed, 2);
  const hooks = JSON.parse(fs.readFileSync(path.join(dir, 'hooks.json'), 'utf8'));
  assert.equal(hooks.autoagy.PreToolUse[0].hooks[0].command, '"/opt/node 22/bin/node" ./bin/autoagy.mjs hook pre-tool-use');
  assert.equal(pinNodeInHooks(dir, '/usr/bin/node').changed, 0);
});
