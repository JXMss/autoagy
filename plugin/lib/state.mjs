// Per-conversation state shared by concurrent hook processes: the Codex
// rejection circuit breaker, recent denials, and one-shot user approvals.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const LOCK_STALE_MS = 15_000;
const LOCK_WAIT_MS = 5_000;
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
    // stepIdx -> mount points created for protected directories that were missing, removed after the command.
    pendingPlaceholders: {},
    // stepIdx -> [{ abs, real }] a file edit targets, resolved when it was approved.
    pendingEdits: {},
    rootConversationId: undefined,
    denials: [],
    approvals: [],
    updatedAt: null,
  };
}

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

/** Runs fn while holding an exclusive lock file next to `file`. */
export function withLock(file, fn) {
  const lock = `${file}.lock`;
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      fs.closeSync(fs.openSync(lock, 'wx'));
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      let stale = Date.now() > deadline;
      try {
        stale = stale || Date.now() - fs.statSync(lock).mtimeMs > LOCK_STALE_MS;
      } catch {
        continue;
      }
      if (stale) {
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
