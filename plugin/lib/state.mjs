// Per-conversation state shared by concurrent hook processes: the Codex
// rejection circuit breaker, recent denials, and one-shot user approvals.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * How old a lock file must be before a waiter may break it.
 *
 * Chosen to fit inside the tightest hook budget, not to measure patience: the
 * post-tool-use and post-invocation hooks get ten seconds (hooks.json declares
 * fifteen, the watchdog answers five seconds inside it), and their watchdog
 * exits before the check runs — so a lock wait longer than that does not delay
 * the self-checks, it deletes them. The critical sections are a read, a write
 * and a rename over a small file, so five seconds is already four orders of
 * magnitude past "the holder is alive".
 */
export const LOCK_STALE_MS = 5_000;
const MAX_DENIALS = 20;

export function stateDir(autoagyHome) {
  return path.join(autoagyHome, 'state');
}

export function stateFile(autoagyHome, conversationId) {
  const safe = String(conversationId || 'unknown').replace(/[^A-Za-z0-9_-]/g, '_');
  return path.join(stateDir(autoagyHome), `${safe}.json`);
}

function freshState(conversationId) {
  return {
    version: 1,
    conversationId,
    turnKey: null,
    consecutiveDenials: 0,
    recent: [],
    interrupt: null,
    escalatedCommandApproved: false,
    // stepIdx -> hash of the command autoagy rewrote into its own sandbox, checked at PostToolUse.
    pendingConfined: {},
    // stepIdx -> hash of the command autoagy rewrote to run under `env -i`, for
    // the platforms where it has no sandbox of its own; checked the same way.
    pendingEnvScrub: {},
    // stepIdx -> mount points created for protected directories that were missing, removed after the command.
    pendingPlaceholders: {},
    // The lock file those mount points were protected under, recorded when the
    // command was built so a later reclamation probes the same one.
    pendingLock: null,
    // stepIdx -> [{ abs, real }] a file edit targets, resolved when it was approved.
    pendingEdits: {},
    // Set when supervision saw the environment do something it did not approve:
    // a path that resolved elsewhere when the edit ran, or a command that wrote
    // into a protected directory. Sticky for the conversation, because a new
    // user message does not undo a symlink that was already swapped. See
    // markUntrusted.
    untrusted: null,
    // A command may still be running in a terminal autoagy cannot observe (agy
    // backgrounded it, or the agent has been typing into a persistent one), so
    // PostToolUse is not evidence that a mount point is free. Sticky.
    backgroundSuspected: false,
    // The workspace files this conversation edited, newest last. The reviewer
    // gets these because an edit made long ago can fall out of the trimmed
    // transcript, and it cannot otherwise see that a path already moved.
    recentEdits: [],
    rootConversationId: undefined,
    denials: [],
    approvals: [],
    updatedAt: null,
  };
}

/** True when the conversation's environment is no longer trusted. */
export function isUntrusted(state) {
  return Boolean(state?.untrusted);
}

/**
 * Records that the conversation can no longer be trusted, together with why.
 * Never cleared by a new turn: the condition is a fact about the filesystem,
 * not about the agent's behaviour. `autoagy trust` clears it.
 * @param {object} state
 * @param {{ reason: string, detail?: string, step?: number|null, at?: string|null }} info
 */
export function markUntrusted(state, { reason, detail = '', step = null, at = null }) {
  if (!state.untrusted) state.untrusted = { reason, detail, step, at };
  else if (!state.untrusted.detail && detail) state.untrusted.detail = detail;
  // A one-shot escalation approval from before the compromise must not keep
  // terminal input auto-allowed for the rest of the conversation.
  state.escalatedCommandApproved = false;
  return state.untrusted;
}

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

/**
 * Whether a lock file of this age may be broken.
 *
 * Age is the whole rule. A waiter's own elapsed time says nothing about whether
 * the holder is alive, so letting a long wait cause a break would take the lock
 * from a process that may be in the middle of a read-modify-write.
 */
export function lockIsStale(ageMs) {
  return ageMs > LOCK_STALE_MS;
}

/**
 * Runs fn while holding an exclusive lock file next to `file`.
 *
 * Breaking a lock two processes hold means two read-modify-writes interleave,
 * which silently loses whichever wrote first. What is stored here is not just
 * counters: an `untrusted` mark is sticky and cleared only by `autoagy trust`,
 * so losing one to a race would undo a security decision with nothing to show
 * it happened. The critical sections are a read, a write and a rename over a
 * small file, so a lock older than LOCK_STALE_MS belongs to a process that is
 * gone or wedged.
 */
export function withLock(file, fn) {
  const lock = `${file}.lock`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, 'wx'));
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      let age;
      try {
        age = Date.now() - fs.statSync(lock).mtimeMs;
      } catch {
        continue; // released while we looked; try to take it again
      }
      if (lockIsStale(age)) {
        fs.rmSync(lock, { force: true });
        continue;
      }
      sleepSync(15);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lock, { force: true });
  }
}

export function readState(autoagyHome, conversationId) {
  const file = stateFile(autoagyHome, conversationId);
  try {
    return { ...freshState(conversationId), ...JSON.parse(fs.readFileSync(file, 'utf8')) };
  } catch {
    return freshState(conversationId);
  }
}

function writeState(file, state) {
  state.updatedAt = new Date().toISOString();
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, file);
}

/** Read-modify-write under the lock; returns whatever `mutate` returns. */
export function updateState(autoagyHome, conversationId, mutate) {
  const file = stateFile(autoagyHome, conversationId);
  return withLock(file, () => {
    const state = readState(autoagyHome, conversationId);
    const result = mutate(state);
    writeState(file, state);
    return result;
  });
}

/**
 * Records that a hook just ran, for `autoagy status`.
 *
 * A plugin that is not loading cannot report that it is not loading, and the
 * three ways it can go missing — `agy plugin disable`, `agy plugin install`
 * replacing the pinned hooks.json, or the pinned interpreter no longer working —
 * all look the same from the outside: no hook runs. So the hook leaves a mark
 * instead, and `status` can say how long ago the last one was.
 */
export function touchHeartbeat(autoagyHome, event = 'unknown') {
  const file = path.join(stateDir(autoagyHome), 'last-hook-run.json');
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ at: new Date().toISOString(), event }));
    fs.renameSync(tmp, file);
  } catch {
    // A heartbeat that cannot be written must never fail a hook.
  }
}

/** When the last hook ran, or null when there is no record. */
export function readHeartbeat(autoagyHome) {
  try {
    return JSON.parse(fs.readFileSync(path.join(stateDir(autoagyHome), 'last-hook-run.json'), 'utf8'));
  } catch {
    return null;
  }
}

/** Stable identity of an action for one-shot approvals. */
export function actionKey(toolName, args) {
  const { toolAction, toolSummary, WaitMsBeforeAsync, ...rest } = args ?? {};
  const canonical = (value) => {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.keys(value).sort().map((k) => [k, canonical(value[k])]));
    }
    return value;
  };
  return crypto.createHash('sha256').update(JSON.stringify([toolName, canonical(rest)])).digest('hex').slice(0, 16);
}

export function newId() {
  return crypto.randomBytes(4).toString('hex');
}

/**
 * Codex's GuardianRejectionCircuitBreaker, per conversation turn.
 * @returns {{ turnKey: number, message: string, pending: boolean } | null} the interrupt, when it trips
 */
export function recordReviewOutcome(state, { denied, turnKey, circuitBreaker }) {
  if (state.turnKey !== turnKey) {
    state.turnKey = turnKey;
    state.consecutiveDenials = 0;
    state.recent = [];
    state.interrupt = null;
  }
  state.consecutiveDenials = denied ? state.consecutiveDenials + 1 : 0;
  state.recent.push(Boolean(denied));
  while (state.recent.length > circuitBreaker.window) state.recent.shift();
  const recentDenials = state.recent.filter(Boolean).length;
  if (
    denied &&
    !state.interrupt &&
    (state.consecutiveDenials >= circuitBreaker.maxConsecutiveDenials || recentDenials >= circuitBreaker.maxRecentDenials)
  ) {
    state.interrupt = {
      turnKey,
      pending: true,
      message:
        `Automatic approval review rejected too many approval requests for this turn ` +
        `(${state.consecutiveDenials} consecutive, ${recentDenials} in the last ${circuitBreaker.window} reviews); interrupting the turn.`,
    };
    return state.interrupt;
  }
  return null;
}

export function recordDenial(state, denial) {
  state.denials.push(denial);
  while (state.denials.length > MAX_DENIALS) state.denials.shift();
}

/** Takes (and consumes) the user's one-shot approvals for an action. */
export function takeApprovals(state, key) {
  const matching = state.approvals.filter((a) => a.actionKey === key);
  state.approvals = state.approvals.filter((a) => a.actionKey !== key);
  return matching;
}

/** Lists state files, newest first. */
export function listStates(autoagyHome) {
  const dir = stateDir(autoagyHome);
  let names = [];
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith('.json'));
  } catch {
    return [];
  }
  return names
    .map((name) => {
      const file = path.join(dir, name);
      try {
        return { file, mtimeMs: fs.statSync(file).mtimeMs, state: JSON.parse(fs.readFileSync(file, 'utf8')) };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
}
