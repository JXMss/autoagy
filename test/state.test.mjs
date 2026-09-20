import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { withLock, lockIsStale, readState, updateState, markUntrusted, isUntrusted, LOCK_STALE_MS, touchHeartbeat, readHeartbeat } from '../plugin/lib/state.mjs';
import { hookBudgetSec } from '../plugin/lib/timeout.mjs';
import { appendDecision } from '../plugin/lib/log.mjs';
import { PLUGIN_DIR } from '../plugin/lib/context.mjs';

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-state-')));
const autoagyHome = path.join(root, 'autoagy');
after(() => fs.rmSync(root, { recursive: true, force: true }));

test('only a lock older than the staleness limit may be broken', () => {
  // The critical section is a read, a write and a rename over a small file. A
  // waiter that has waited a while is not evidence that the holder is gone, and
  // stealing from a live holder loses one of the two writes — which here can
  // drop a sticky `untrusted` mark.
  assert.equal(lockIsStale(0), false);
  assert.equal(lockIsStale(4_999), false);
  assert.equal(lockIsStale(5_000), false);
  assert.equal(lockIsStale(5_001), true);
  assert.equal(lockIsStale(60_000), true);
});

test('a lock wait fits inside the tightest hook budget', () => {
  // The post-tool-use hook runs the self-checks, and its watchdog exits before
  // they run — so a wait longer than that budget does not delay the checks, it
  // removes them. Whatever the limit is, it has to stay under it.
  for (const event of ['post-tool-use', 'post-invocation']) {
    const budgetMs = hookBudgetSec(event, { pluginDir: PLUGIN_DIR }) * 1000;
    assert.ok(LOCK_STALE_MS < budgetMs, `${LOCK_STALE_MS}ms of waiting vs the ${event} budget of ${budgetMs}ms`);
  }
});

test('withLock runs and releases, and breaks a lock nobody is holding', () => {
  const file = path.join(autoagyHome, 'state', 'abc.json');
  let ran = 0;
  withLock(file, () => ran++);
  assert.equal(ran, 1);
  assert.equal(fs.existsSync(`${file}.lock`), false);

  // A lock file left behind by a process that died: the age is what lets the
  // next caller through, rather than waiting forever.
  fs.writeFileSync(`${file}.lock`, '');
  const old = new Date(Date.now() - 60_000);
  fs.utimesSync(`${file}.lock`, old, old);
  withLock(file, () => ran++);
  assert.equal(ran, 2);
  assert.equal(fs.existsSync(`${file}.lock`), false);
});

test('a sticky mark survives a read-modify-write round trip', () => {
  updateState(autoagyHome, 'conv-1', (s) => markUntrusted(s, { reason: 'edit-target-changed', detail: '/w/x -> /tmp/x' }));
  assert.equal(isUntrusted(readState(autoagyHome, 'conv-1')), true);
  // A later update that does not touch it must not drop it.
  updateState(autoagyHome, 'conv-1', (s) => {
    s.recentEdits = [{ step: 1, kind: 'write_to_file', path: '/w/y', real: '/w/y' }];
  });
  const state = readState(autoagyHome, 'conv-1');
  assert.equal(isUntrusted(state), true);
  assert.equal(state.untrusted.reason, 'edit-target-changed');
});

test('a hook leaves a heartbeat, so a plugin that stopped loading is visible', () => {
  // A plugin that is not loading cannot say so; this is the only trace it
  // leaves, and `autoagy status` is what reads it.
  const home = path.join(root, 'autoagy-heartbeat');
  assert.equal(readHeartbeat(home), null, 'nothing recorded yet');
  touchHeartbeat(home, 'post-invocation');
  const beat = readHeartbeat(home);
  assert.equal(beat.event, 'post-invocation');
  assert.ok(Math.abs(Date.now() - Date.parse(beat.at)) < 5_000, beat.at);
  // A heartbeat that cannot be written must never break a hook: put a directory
  // where the file goes, so the rename fails and is swallowed.
  fs.rmSync(path.join(home, 'state', 'last-hook-run.json'));
  fs.mkdirSync(path.join(home, 'state', 'last-hook-run.json'));
  assert.doesNotThrow(() => touchHeartbeat(home, 'post-invocation'));
});

test("autoagy's own directories are not readable by other users on the machine", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-mode-'));
  try {
    updateState(home, 'conv-mode', (s) => {
      s.turnKey = 1;
    });
    appendDecision(home, { conversation: 'conv-mode', verdict: 'allow' });
    // The decision log holds command lines, and with `log.reviews` whole
    // transcripts; the state holds the paths this conversation touched.
    for (const dir of [path.join(home, 'state'), path.join(home, 'logs')]) {
      assert.equal(fs.statSync(dir).mode & 0o077, 0, dir);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
