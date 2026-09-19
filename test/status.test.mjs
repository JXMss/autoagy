// `autoagy status` reads the configuration directory, not the user's home
// directory. Those two were briefly confused, which silently hid the self-check
// warning — the one line that reports autoagy's own sandbox being switched off
// for an agy build.

import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeSandboxDirs } from './helpers.mjs';
import { updateState, markUntrusted } from '../plugin/lib/state.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'plugin', 'bin', 'autoagy.mjs');
const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

beforeEach(() => {
  fs.rmSync(dirs.env.AUTOAGY_HOME, { recursive: true, force: true });
});

const status = () => {
  const res = spawnSync(process.execPath, [BIN, 'status'], { env: dirs.env, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  return res.stdout;
};

test('status keeps the configuration directory and the user home apart', () => {
  const out = status();
  assert.match(out, new RegExp(`log: ${dirs.env.AUTOAGY_HOME}/logs/decisions\\.jsonl`));
  assert.doesNotMatch(out, new RegExp(`log: ${dirs.home}/logs/`), 'the user home is not the configuration directory');
  assert.match(out, /setup record\s+none/);
});

test('status names the flagged conversations', () => {
  assert.doesNotMatch(status(), /Flagged conversations/);
  updateState(dirs.env.AUTOAGY_HOME, dirs.conversationId, (s) => {
    markUntrusted(s, { reason: 'edit-target-changed', detail: 'x resolved to y', step: 7 });
    s.backgroundSuspected = true;
    s.pendingPlaceholders = { 7: [] };
  });
  const out = status();
  assert.match(out, /Flagged conversations/);
  assert.match(out, new RegExp(dirs.conversationId));
  assert.match(out, /edit-target-changed/);
  assert.match(out, /backgrounded command may still be running/);
});
