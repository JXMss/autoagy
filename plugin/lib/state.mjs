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

/**
 * The `.json` files under `state/` that are not any conversation's state.
 *
 * The directory holds two kinds of file and the only thing telling them apart is
 * the name: a conversation's state is named after its id — and that sanitized id
 * can be any word, `bwrap-probe` included — while these are named after what
 * they hold. So the list lives here, where the directory is defined, and the
 * readers ask it rather than each inventing a rule.
 *
 * Before this, both readers treated every `.json` as a conversation:
 * `unreadableStateFiles` reported a truncated `bwrap-probe.json` as "the next
 * tool call in that conversation will quarantine it and mark the conversation
 * untrusted", which is false in every clause — no conversation has that id,
 * nothing quarantines it, and no `autoagy trust <id>` applies — and `listStates`
 * handed all of them to its callers as states that merely happened to have no
 * fields.
 */
const RESERVED_STATE_FILES = new Set(['bwrap-probe.json', 'own-sandbox-check.json', 'command-env-check.json', 'config-warning.json', 'last-hook-run.json']);

/**
 * The path of one of those files.
 *
 * Going through here is what keeps the set above from drifting: a new file under
 * `state/` that nobody registered throws on its first use, in development,
 * instead of quietly becoming a conversation that `status` reports and `trust`
 * cannot clear.
 */
export function reservedStateFile(autoagyHome, name) {
  if (!RESERVED_STATE_FILES.has(name)) throw new Error(`state/${name} is not a registered non-conversation state file`);
  return path.join(stateDir(autoagyHome), name);
}

/** Whether a name in `stateDir` is some conversation's state file. */
export function isConversationStateFile(name) {
  return name.endsWith('.json') && !RESERVED_STATE_FILES.has(name);
}

/**
 * Writes JSON so that a crash cannot leave a half-written file behind: into a
 * pid-unique temporary name, then one rename.
 *
 * Shared because the failure is shared. `writeState` did this from the start,
 * while `bwrap-probe.json` and the two self-check files were written in place —
 * which made them the files in this directory most likely to be *found*
 * truncated, and a truncated file here is read as "no record", the answer every
 * sticky mark in it exists to prevent.
 *
 * The temporary name ends in `.tmp`, so one left behind by a process that died
 * between the write and the rename is not mistaken for a state file.
 */
export function writeJsonFile(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
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
    // stepIdx -> the nested `.git` directories that existed when the command line
    // was built, so PostToolUse can tell which of them the command created.
    // Recorded in the same breath as pendingConfined and deleted with it; a step
    // with no key is simply not checked, and an empty list is the hole itself —
    // "there was no nested repository before this command ran".
    pendingNestedGit: {},
    // The lock file those mount points were protected under, recorded when the
    // command was built so a later reclamation probes the same one.
    pendingLock: null,
    // stepIdx -> [{ abs, real }] a file edit targets, resolved when it was approved.
    pendingEdits: {},
    // The same for the tools that return file contents. Kept apart from
    // pendingEdits because the two feed different things: only the edits go on
    // to `recentEdits`, which the reviewer is told is the list of files this
    // conversation *edited*.
    pendingReads: {},
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
    // `.git` directories that appeared while a sandboxed command ran and hold
    // something git will execute (a hook file, or a config key pointing git at
    // hooks elsewhere). Deliberately not `untrusted`: husky, pre-commit and
    // lefthook installs produce exactly this shape in a freshly made nested
    // repository, and untrusted is session-wide, sticky and only a human can
    // clear it. The consequence is narrower — commands touching the repository
    // are reviewed, with the hook content in the review material — and
    // `autoagy trust` clears it, since that command is the human saying they
    // have looked at the disk.
    plantedHooks: [],
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
 * This is what is left for a lock whose holder cannot be identified: the
 * identity is written by the holder, so a lock created by an older version of
 * this file, or one caught in the instant between creation and that write, has
 * nothing to check. A waiter's own elapsed time still says nothing about
 * whether the holder is alive, so age is the fallback and not the rule.
 */
export function lockIsStale(ageMs) {
  return ageMs > LOCK_STALE_MS;
}

/**
 * How long a waiter may wait before it gives up.
 *
 * Every caller is a hook with a budget, and the watchdog exits when that budget
 * runs out — so a wait that outlives the budget does not delay the work, it
 * deletes it (the self-checks in `handlePostToolUse` are the ones that would
 * disappear). Giving up is therefore the only safe answer, and it is the
 * fail-closed one: the caller's error path refuses what it cannot classify.
 */
export const LOCK_WAIT_MS = 2_000;

/**
 * The ceiling for a lock whose holder is *alive*.
 *
 * The section is a read, a write and a rename over a small file, so a live
 * process still inside it after a minute is not going to finish — a debugger
 * stopped it, or it is wedged in a way that will never release. Waiters reach
 * `LOCK_WAIT_MS` long before this, so this only decides whether the next call
 * recovers on its own or needs `autoagy trust`.
 */
export const LOCK_BREAK_MS = 60_000;

/** The lock file's holder record, or null when it cannot be read. */
function readHolder(lock) {
  try {
    const text = fs.readFileSync(lock, 'utf8').trim();
    if (!text) return null;
    const holder = JSON.parse(text);
    return holder && typeof holder === 'object' ? holder : null;
  } catch {
    return null;
  }
}

/**
 * The kernel's start time for a process, which tells two uses of one pid apart.
 *
 * Field 22 of `/proc/<pid>/stat`, counted from after the last `)` because
 * `comm` can hold spaces and parentheses of its own. Null means the process is
 * gone (or, on a host without /proc, that this cannot be answered).
 */
function processStartTime(pid) {
  if (process.platform !== 'linux') return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    const value = Number(fields[19]);
    return Number.isFinite(value) && value > 0 ? value : null;
  } catch {
    return null;
  }
}

/**
 * Whether the process named in the lock is still the one holding it:
 * `true`, `false`, or `null` when the record cannot say.
 *
 * A pid on its own is not an identity — the kernel reuses them — so on Linux
 * the start time recorded with it is checked too. With that, "the holder is
 * gone" becomes a fact rather than an inference from age: a hook killed by
 * agy's timeout leaves a lock whose owner no longer exists, and the next call
 * may take it immediately instead of waiting out a timer.
 */
function holderIsAlive(holder) {
  if (!holder || !Number.isInteger(holder.pid) || holder.pid <= 0) return null;
  if (process.platform === 'linux') {
    const start = processStartTime(holder.pid);
    if (start === null) return false;
    if (Number.isFinite(holder.start) && holder.start > 0 && start !== holder.start) return false;
    return true;
  }
  try {
    process.kill(holder.pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM'; // alive, but not ours to signal
  }
}

/**
 * Runs fn while holding an exclusive lock file next to `file`.
 *
 * Breaking a lock two processes hold means two read-modify-writes interleave,
 * which silently loses whichever wrote first. What is stored here is not just
 * counters: an `untrusted` mark is sticky and cleared only by `autoagy trust`,
 * so losing one to a race would undo a security decision with nothing to show
 * it happened — and losing `plantedHooks` would put a repository the reviewer
 * was told about back out of its reach.
 *
 * Two things this used to get wrong, both measured:
 *
 * - age alone broke the lock, so a holder that took longer than
 *   `LOCK_STALE_MS` inside the section — a slow filesystem (this repository
 *   lives on a 9p mount where one `readdir` costs ~3ms), a suspended VM, or a
 *   *forward* clock step — had its lock taken and its write lost;
 * - a lock whose recorded time was in the future was never stale
 *   (`Date.now() - mtimeMs` negative), and because the wait is a synchronous
 *   `Atomics.wait` the hook's watchdog could not fire either, so the hook spun
 *   until agy killed it: every tool call in that conversation failed, and the
 *   self-checks never ran at all. A clock step backwards — which WSL2 does on
 *   resume — is enough.
 */
export function withLock(file, fn) {
  const lock = `${file}.lock`;
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const deadline = Date.now() + LOCK_WAIT_MS;
  for (;;) {
    try {
      const fd = fs.openSync(lock, 'wx');
      try {
        fs.writeSync(fd, JSON.stringify({ pid: process.pid, start: processStartTime(process.pid), at: Date.now() }));
      } catch {
        // An unreadable identity is not a reason to refuse the lock: a waiter
        // treats an empty record as unknown and falls back to age.
      }
      fs.closeSync(fd);
      break;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
      const holder = readHolder(lock);
      const alive = holderIsAlive(holder);
      let age;
      try {
        age = Number.isFinite(holder?.at) ? Date.now() - holder.at : Date.now() - fs.statSync(lock).mtimeMs;
      } catch {
        continue; // released while we looked; try to take it again
      }
      const limit = alive === true ? LOCK_BREAK_MS : LOCK_STALE_MS;
      if (alive === false || age > limit) {
        fs.rmSync(lock, { force: true });
        continue;
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `autoagy: ${lock} is held by pid ${holder?.pid ?? '?'} and did not come free within ${LOCK_WAIT_MS}ms; refusing to guess which of the two writes to lose`,
        );
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

/**
 * Keeps a copy of a state file that cannot be read, once.
 *
 * A *copy*, not a rename: what it held is the only record of an `untrusted` mark
 * or a planting, and it stays where it is until a locked write replaces it. The
 * mark returned by `readState` is also what the next read has to see again —
 * renaming the file away would make that read report a brand-new conversation,
 * which is the very answer this is here to avoid.
 *
 * The name is fixed rather than timestamped so a reader that never writes (a
 * listing, a sweep) cannot fill the directory with copies of one broken file.
 * Best effort: the mark is the part that matters, and an unreadable copy must
 * never become a hook failure.
 */
function quarantine(file) {
  const copy = `${file}.corrupt`;
  try {
    if (!fs.existsSync(copy)) fs.copyFileSync(file, copy);
  } catch {
    // best effort
  }
}

/**
 * The state file that cannot be read as state, if there is one.
 *
 * `listStates` skips those files, which is right for a listing and wrong for the
 * one report a user reads: nothing else says that a conversation's record is
 * unreadable, and the hook's own answer to that is to stop trusting the
 * conversation.
 *
 * Conversation files only (`isConversationStateFile`). What this report says
 * about a file — that the next tool call in that conversation will quarantine it
 * and distrust the conversation — is only true of a conversation's own state, and
 * the reserved files are the ones most likely to be here, since a truncated
 * write is what puts a file in this list at all.
 */
export function unreadableStateFiles(autoagyHome) {
  let names = [];
  try {
    names = fs.readdirSync(stateDir(autoagyHome)).filter(isConversationStateFile);
  } catch {
    return [];
  }
  return names
    .map((name) => path.join(stateDir(autoagyHome), name))
    .filter((file) => {
      try {
        JSON.parse(fs.readFileSync(file, 'utf8'));
        return false;
      } catch (err) {
        return err?.code !== 'ENOENT';
      }
    });
}

export function readState(autoagyHome, conversationId) {
  const file = stateFile(autoagyHome, conversationId);
  try {
    return { ...freshState(conversationId), ...JSON.parse(fs.readFileSync(file, 'utf8')) };
  } catch (err) {
    if (err?.code === 'ENOENT') return freshState(conversationId);
    // The file is there and is not state: a truncated write on a filesystem
    // where rename is not atomic, a restored backup, a hand-edit. Reading it as
    // a new conversation is the same act as clearing every sticky mark it held
    // — `untrusted` and `plantedHooks` above all — and the next write would
    // overwrite the only copy of what it did say. So it is kept, and the
    // conversation is marked instead of quietly trusted again: "we cannot read
    // the record of what happened here" is a reason to stop trusting this
    // conversation's paths, and `autoagy trust` is how a person says otherwise.
    quarantine(file);
    return {
      ...freshState(conversationId),
      untrusted: { reason: 'state-file-unreadable', detail: `${path.basename(file)}: ${err.message}`, step: null, at: null },
    };
  }
}

function writeState(file, state) {
  state.updatedAt = new Date().toISOString();
  writeJsonFile(file, state);
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
/**
 * The configuration warnings, the first time this exact set is seen.
 *
 * `loadConfig` catches a setting that cannot work — a relative `writableRoots`
 * entry, a glob that can never match — and drops it. Until now that only
 * reached the decision log and `autoagy status`, so in a session nobody saw it:
 * the setting looked accepted, and the whole symptom was a directory that kept
 * being reviewed for no visible reason. That is the failure the validation was
 * added to end, so it has to reach a channel someone is looking at.
 *
 * Once per distinct set, not once per tool call: the warnings only change when
 * the config file does, and a line on every command is noise that teaches
 * people to stop reading stderr.
 *
 * @returns {string[]} the warnings to print, or an empty array
 */
export function takeConfigWarnings(autoagyHome, warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) return [];
  const seen = crypto.createHash('sha1').update(warnings.join('\n')).digest('hex').slice(0, 16);
  const file = reservedStateFile(autoagyHome, 'config-warning.json');
  try {
    if (JSON.parse(fs.readFileSync(file, 'utf8')).seen === seen) return [];
  } catch {
    // Never reported, or unreadable: report it.
  }
  try {
    writeJsonFile(file, { seen, at: new Date().toISOString() });
  } catch {
    // If the marker cannot be written the warning repeats, which is the safe direction.
  }
  return warnings;
}

export function touchHeartbeat(autoagyHome, event = 'unknown') {
  const file = reservedStateFile(autoagyHome, 'last-hook-run.json');
  try {
    writeJsonFile(file, { at: new Date().toISOString(), event });
  } catch {
    // A heartbeat that cannot be written must never fail a hook.
  }
}

/** When the last hook ran, or null when there is no record. */
export function readHeartbeat(autoagyHome) {
  try {
    return JSON.parse(fs.readFileSync(reservedStateFile(autoagyHome, 'last-hook-run.json'), 'utf8'));
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
export function recordReviewOutcome(state, { denied, backendError = null, turnKey, circuitBreaker }) {
  if (state.turnKey !== turnKey) {
    state.turnKey = turnKey;
    state.consecutiveDenials = 0;
    state.consecutiveReviewErrors = 0;
    state.recent = [];
    state.interrupt = null;
  }
  state.consecutiveDenials = denied ? state.consecutiveDenials + 1 : 0;
  // A reviewer that cannot answer is not a reviewer that answered "no": the two
  // are counted apart, and only a real answer (either way) clears the streak.
  state.consecutiveReviewErrors = backendError ? (state.consecutiveReviewErrors ?? 0) + 1 : 0;
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
  // Nothing risky can be judged while the backend is down, so every action past
  // this point fails closed and the agent can only retry into the same wall. The
  // threshold is the operator's consecutive-denial one, because it answers the
  // same question — how many failures in a row mean this turn cannot proceed.
  if (!state.interrupt && state.consecutiveReviewErrors >= circuitBreaker.maxConsecutiveDenials) {
    state.interrupt = {
      turnKey,
      pending: true,
      message:
        `The approval reviewer could not answer ${state.consecutiveReviewErrors} times in a row (${backendError}); ` +
        'without it nothing risky can be approved, so this turn is stopping. Tell the user, and suggest `autoagy status` ' +
        '(the reviewer may be logged out, out of quota, or unreachable).',
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

/** Lists the conversations' state files, newest first. */
export function listStates(autoagyHome) {
  const dir = stateDir(autoagyHome);
  let names = [];
  try {
    // Conversations only: the reserved files parse fine and would come back as
    // states with none of the fields any caller looks at, which is why nothing
    // has gone visibly wrong with them — `trust` filters on a flag, `status` on
    // the same. That is luck, not a rule.
    names = fs.readdirSync(dir).filter(isConversationStateFile);
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
