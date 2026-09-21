// One-shot tokens for `bin/exec-confined`, the single program the narrow
// `command(...)` grant names.
//
// The grant that lets autoagy's own sandbox run at all is the same grant that
// makes the plugin fail open: `command(*)` keeps working after the hook stops
// running. Naming one program instead moves the question from "what may run"
// to "who may say what runs", and the answer is a directory only the hook
// writes — `$AUTOAGY_HOME/state/pending`, which Antigravity's terminal sandbox
// mounts read-only (everything outside the workspace is) and which the policy's
// `selfPaths` refuses edits to.
//
// That last sentence is load-bearing, and it is only completely true with
// `allowNonWorkspaceAccess: false`: with it set to true, a file-editing tool can
// still write outside the workspace, and while the hook is alive autoagy refuses
// such a write to its own directory — but a hook that is not running refuses
// nothing. `autoagy status` says so rather than implying a guarantee it does not
// have.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const TOKEN_TTL_MS = 5 * 60 * 1000;
const EXECUTOR_SOURCE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'exec-confined.mjs');

/** Where tokens live. The executor derives the same path from its own location. */
export function tokenDir(autoagyHome) {
  return path.join(autoagyHome, 'state', 'pending');
}

/**
 * The installed executor. It lives under `$AUTOAGY_HOME`, not in the plugin
 * directory, for two reasons: `agy plugin install` replaces the plugin
 * directory wholesale, and the executor has to sit next to the token directory
 * so it can find it without being told where it is.
 */
export function executorPath(autoagyHome) {
  return path.join(autoagyHome, 'bin', 'exec-confined.mjs');
}

/** True when the executor is installed and runnable. */
export function executorInstalled(autoagyHome) {
  try {
    const stat = fs.statSync(executorPath(autoagyHome));
    return stat.isFile() && (stat.mode & 0o111) !== 0;
  } catch {
    return false;
  }
}

/**
 * Copies the executor next to the token directory, with its interpreter pinned.
 *
 * The shebang is rewritten to an absolute node for the same reason `autoagy
 * setup` pins the hook commands: Antigravity may be started without the user's
 * PATH, and `#!/usr/bin/env node` would then find nothing.
 * @returns {{ path: string, node: string }}
 */
export function installExecutor(autoagyHome, { nodePath = process.execPath } = {}) {
  const target = executorPath(autoagyHome);
  const source = fs.readFileSync(EXECUTOR_SOURCE, 'utf8').replace(/^#![^\n]*\n/, `#!${nodePath}\n`);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.mkdirSync(tokenDir(autoagyHome), { recursive: true, mode: 0o700 });
  const tmp = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, source, { mode: 0o700 });
  fs.renameSync(tmp, target);
  return { path: target, node: nodePath };
}

/**
 * Writes one token and returns the command line that redeems it.
 *
 * The token carries the command autoagy already decided to run, so the executor
 * never has to judge anything: everything it needs was settled by the hook that
 * wrote the file.
 * @returns {{ name: string, file: string, commandLine: string }}
 */
export function mintToken(autoagyHome, { commandLine, cwd = null, conversation = null, step = null, ttlMs = TOKEN_TTL_MS, now = Date.now() }) {
  const dir = tokenDir(autoagyHome);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const name = crypto.randomBytes(16).toString('hex');
  const file = path.join(dir, `${name}.json`);
  const payload = { commandLine, cwd, conversation, step, issuedAt: now, expiresAt: now + ttlMs };
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
  fs.renameSync(tmp, file);
  return { name, file, commandLine: `${executorWord(autoagyHome)} ${name}` };
}

// Characters a POSIX shell reads literally in an unquoted word.
const SHELL_SAFE = /^[A-Za-z0-9_@%+=:,./-]+$/;

/**
 * The executor as the first word of the redeeming command line: bare whenever
 * the shell needs no quotes for it.
 *
 * The grant `setup` writes is `command(<executor path>)`, unquoted, and agy
 * matches it against the command line as written, quotes included. Seen on the
 * first real install (agy 1.2.7): every `'<executor>' <token>` call prompted
 * despite that grant, and the prefix agy offered to remember began with the
 * quote. Written bare, the command line starts with exactly the grant's text.
 */
export function executorWord(autoagyHome) {
  const file = executorPath(autoagyHome);
  return SHELL_SAFE.test(file) ? file : quote(file);
}

/** False when the executor path needs quoting, so its grant cannot match as written. */
export function executorPathIsBare(autoagyHome) {
  return SHELL_SAFE.test(executorPath(autoagyHome));
}

/** A token as written, or null when it cannot be read. */
function readToken(file) {
  try {
    const token = JSON.parse(fs.readFileSync(file, 'utf8'));
    return token && typeof token === 'object' ? token : null;
  } catch {
    return null;
  }
}

/**
 * Removes tokens nobody redeemed, and the claim files a killed executor left.
 *
 * A token that outlives its call is a retry the user never granted, which is
 * the same thing `autoagy approve` is deliberately one-shot about. What counts
 * as outliving it has two answers, and they are not the same:
 *
 * - past its expiry, a token is spent whatever else is true, so it goes
 *   whoever asked and whatever conversation minted it;
 * - `all` — this conversation's turn is over — takes that conversation's
 *   unredeemed tokens. It is emphatically not "everything in the directory":
 *   the directory is shared by every conversation on the machine, and
 *   `handlePostInvocation` fires after every *model call*, not at the end of a
 *   turn, so a sweep that reached across conversations would delete a token
 *   another conversation minted moments ago and is about to run — the executor
 *   would refuse it as "already used, expired, or never issued", which is the
 *   wrong reason and a failure nobody could explain. Called with no
 *   conversation to attribute, `all` removes nothing.
 *
 * A `.claimed.<pid>` file belongs to an executor that is reading it right now:
 * claiming is a rename and the read follows it. It ages out by mtime like a
 * `.tmp`, never on sight.
 *
 * @returns {number} how many files were removed
 */
export function sweepTokens(autoagyHome, { now = Date.now(), all = false, conversation = null } = {}) {
  const dir = tokenDir(autoagyHome);
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const name of names) {
    const file = path.join(dir, name);
    let gone = false;
    if (name.endsWith('.json')) {
      const token = readToken(file);
      if (token === null) gone = true; // unreadable: nothing can redeem it anyway
      else if (now > (token.expiresAt ?? 0)) gone = true;
      else if (all && conversation !== null && token.conversation === conversation) gone = true;
    } else {
      // A `.claimed.<pid>` or a `.tmp` from a process that died mid-write.
      try {
        gone = now - fs.statSync(file).mtimeMs > TOKEN_TTL_MS;
      } catch {
        continue;
      }
    }
    if (!gone) continue;
    try {
      fs.rmSync(file, { force: true });
      removed++;
    } catch {
      // gone already
    }
  }
  return removed;
}

const quote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
