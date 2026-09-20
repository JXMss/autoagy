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
  return { name, file, commandLine: `${quote(executorPath(autoagyHome))} ${name}` };
}

/**
 * Removes tokens nobody redeemed, and the claim files a killed executor left.
 *
 * A token that outlives its call is a retry the user never granted, which is
 * the same thing `autoagy approve` is deliberately one-shot about. Called when
 * a token is minted (expired ones only) and again when the turn ends (`all`),
 * so neither a crashed hook nor a refused call leaves one lying around.
 * @returns {number} how many files were removed
 */
export function sweepTokens(autoagyHome, { now = Date.now(), all = false } = {}) {
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
    let expired = all;
    if (all) {
      // Called when the turn ends, where a surviving token can only be one
      // nothing redeemed: a call that was refused, or one agy never made. The
      // command a token carries is run during its own tool call, never later,
      // so there is nothing in flight for this to take away.
    } else if (name.endsWith('.json')) {
      try {
        expired = now > (JSON.parse(fs.readFileSync(file, 'utf8')).expiresAt ?? 0);
      } catch {
        expired = true; // unreadable: nothing can redeem it anyway
      }
    } else {
      // A `.claimed.<pid>` or a `.tmp` from a process that died mid-write.
      try {
        expired = now - fs.statSync(file).mtimeMs > TOKEN_TTL_MS;
      } catch {
        continue;
      }
    }
    if (!expired) continue;
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
