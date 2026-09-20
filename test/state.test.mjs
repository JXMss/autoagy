import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { withLock, lockIsStale, readState, updateState, markUntrusted, isUntrusted, LOCK_STALE_MS, LOCK_WAIT_MS, touchHeartbeat, readHeartbeat, takeConfigWarnings, recordReviewOutcome } from '../plugin/lib/state.mjs';
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
  // removes them. `LOCK_WAIT_MS` is what actually bounds a wait now (a live
  // holder is never broken before `LOCK_BREAK_MS`), and it has to leave room for
  // the work the hook does around the lock — the nested-repository walk, which
  // costs seconds on a large tree.
  for (const event of ['post-tool-use', 'post-invocation']) {
    const budgetMs = hookBudgetSec(event, { pluginDir: PLUGIN_DIR }) * 1000;
    assert.ok(LOCK_WAIT_MS * 2 < budgetMs, `${LOCK_WAIT_MS}ms of waiting plus the walk vs the ${event} budget of ${budgetMs}ms`);
  }
  assert.ok(LOCK_STALE_MS < hookBudgetSec('post-tool-use', { pluginDir: PLUGIN_DIR }) * 1000);
});

test('a lock whose holder is gone is taken at once, not after a timer', () => {
  // Liveness is what says the holder is gone, and it is a fact: the pid is not
  // there. The old rule waited out `LOCK_STALE_MS` before believing it, which a
  // hook killed by agy's own timeout paid on every following call.
  const file = path.join(autoagyHome, 'state', 'dead-holder.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(`${file}.lock`, JSON.stringify({ pid: 999_999, start: 1, at: Date.now() }));
  const started = Date.now();
  withLock(file, () => {});
  assert.ok(Date.now() - started < LOCK_STALE_MS, 'no timer is consulted for a holder that does not exist');
  assert.equal(fs.existsSync(`${file}.lock`), false);
});

test('a lock whose holder is alive is not broken; the waiter fails closed instead', () => {
  // The measured lost update: a holder that stayed inside the section longer
  // than the staleness limit had its lock taken, and whatever it wrote was
  // overwritten. Here the holder is this process, which is alive by definition.
  const file = path.join(autoagyHome, 'state', 'live-holder.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(`${file}.lock`, JSON.stringify({ pid: process.pid, at: Date.now() }));
  const started = Date.now();
  assert.throws(() => withLock(file, () => assert.fail('the section must not run')), /did not come free/);
  assert.ok(Date.now() - started >= LOCK_WAIT_MS - 100, 'it waited the deadline rather than breaking in');
  assert.equal(readState(autoagyHome, 'untouched').untrusted ?? null, null);
  fs.rmSync(`${file}.lock`, { force: true });
});

test('a lock whose recorded time is in the future does not spin forever', () => {
  // The reported wedge: `Date.now() - mtimeMs` is negative, so an age rule never
  // fires — and the wait is a synchronous `Atomics.wait`, which blocks the event
  // loop, so the hook's own watchdog could not fire either. agy killed the hook
  // instead, every tool call in that conversation failed, and the self-checks
  // never ran. A clock step backwards (WSL2 on resume) is enough to get there.
  const file = path.join(autoagyHome, 'state', 'future.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(`${file}.lock`, '');
  const future = new Date(Date.now() + 3_600_000);
  fs.utimesSync(`${file}.lock`, future, future);
  const started = Date.now();
  assert.throws(() => withLock(file, () => {}), /did not come free/);
  assert.ok(Date.now() - started < LOCK_WAIT_MS + 1_000, 'it gives up on its own instead of hanging');
  fs.rmSync(`${file}.lock`, { force: true });
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

test('a configuration warning is reported once per distinct set', () => {
  // `loadConfig` drops a setting that cannot work, and until this existed that
  // only reached the decision log and `autoagy status` — so in a session the
  // setting looked accepted and the whole symptom was a directory that kept
  // being reviewed for no visible reason. Once per set, not once per tool call:
  // a line on every command teaches people to stop reading stderr.
  const home = path.join(root, 'config-warnings');
  const first = ['writableRoots[0] ("rel/dir") is not an absolute path'];
  assert.deepEqual(takeConfigWarnings(home, first), first);
  assert.deepEqual(takeConfigWarnings(home, first), []);
  assert.deepEqual(takeConfigWarnings(home, [...first]), [], 'the same set by value, not by identity');
  const second = ['protectedPaths[0] (".husky/**") is relative'];
  assert.deepEqual(takeConfigWarnings(home, second), second, 'a changed config reports again');
  assert.deepEqual(takeConfigWarnings(home, second), []);
  assert.deepEqual(takeConfigWarnings(home, []), [], 'nothing to say stays silent');
});

test('a reviewer that cannot answer stops the turn, like one that says no', () => {
  // The rejection breaker counted only `denied`, so a backend that was down —
  // logged out, out of quota, unreachable — denied every risky action for the
  // rest of the session while the agent retried into the same wall and nothing
  // ever ended the turn.
  const circuitBreaker = { maxConsecutiveDenials: 3, maxRecentDenials: 10, window: 50 };
  const state = {};
  const outcome = (extra) => recordReviewOutcome(state, { denied: false, turnKey: 1, circuitBreaker, ...extra });
  const error = { backendError: 'failed: reviewer unreachable' };
  assert.equal(outcome(error), null);
  assert.equal(outcome(error), null);
  const trip = outcome(error);
  assert.match(trip.message, /could not answer 3 times in a row/);
  assert.match(trip.message, /reviewer unreachable/);
  assert.equal(trip.pending, true);
  // An answer — either way — clears the streak, and a denial still counts as
  // one: the two are tracked apart.
  const fresh = {};
  const forState = (extra) => recordReviewOutcome(fresh, { turnKey: 1, circuitBreaker, ...extra });
  forState({ denied: false, backendError: 'timeout' });
  forState({ denied: false, backendError: 'timeout' });
  assert.equal(forState({ denied: true }), null, 'a real answer resets the error streak');
  assert.equal(forState({ denied: true, backendError: 'timeout' }), null);
  assert.match(forState({ denied: true, backendError: 'timeout' }).message, /rejected too many/);
});

test('a state file that cannot be read is kept as evidence, and the conversation is marked', () => {
  // Reading it as a new conversation is the same act as clearing every sticky
  // mark it held — `untrusted` and `plantedHooks` above all — and the next write
  // would replace the only copy of what it did say. A truncated tail on a
  // filesystem where rename is not atomic is the ordinary way to get here.
  const home = path.join(root, 'corrupt-state');
  const dir = path.join(home, 'state');
  const file = path.join(dir, 'conv-broken.json');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, '{"version":1,"untrusted":{"reason":"edit-target-changed"},"consecutiveDeni');

  const state = readState(home, 'conv-broken');
  assert.equal(state.untrusted.reason, 'state-file-unreadable');
  assert.match(state.untrusted.detail, /conv-broken\.json/);
  assert.equal(isUntrusted(state), true);

  // A copy is kept, and the file itself stays where it is until a locked write
  // replaces it — renaming it away would make the next read report a brand-new
  // conversation, which is the answer this exists to avoid.
  assert.match(fs.readFileSync(`${file}.corrupt`, 'utf8'), /edit-target-changed/, 'the evidence is kept');
  assert.equal(fs.existsSync(file), true, 'and the file is still in place');
  assert.equal(isUntrusted(readState(home, 'conv-broken')), true, 'reading it again gives the same answer');

  // The mark survives the next write, and the state file is valid again.
  updateState(home, 'conv-broken', (s) => {
    s.recentEdits = [];
  });
  assert.equal(isUntrusted(readState(home, 'conv-broken')), true);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).untrusted.reason, 'state-file-unreadable');
  assert.match(fs.readFileSync(`${file}.corrupt`, 'utf8'), /edit-target-changed/, 'the evidence copy is still there');

  // A missing file is a new conversation, which is not a read failure.
  assert.equal(readState(home, 'never-seen').untrusted, null);
});
