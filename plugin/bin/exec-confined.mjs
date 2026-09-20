#!/usr/bin/env node
// The one program the `command(...)` grant names.
//
// autoagy's own sandbox has to leave Antigravity's sandbox to create a
// namespace (bwrap cannot nest — measured), so the rewritten call carries
// `BypassSandbox: true`, and Antigravity only lets that through under a
// `command(...)` grant. A `command(*)` grant is a standing licence to run
// anything, and it keeps working after the hook stops running: that is the
// fail-open this program exists to close.
//
// So the grant names this file instead, and this file will only run what
// autoagy already decided to run: a one-shot token that the hook wrote into a
// directory the agent cannot write. No hook, no tokens, and the grant is worth
// nothing.
//
// Three rules, and the whole design rests on them:
//
//   1. The argument is a token NAME, never a path. It is matched against
//      /^[0-9a-f]{32}$/ and joined onto this program's own sibling directory.
//      If it were a path, an agent holding the grant could write its own JSON
//      into the workspace and pass that — and the narrow grant would be
//      `command(*)` again, wearing a different name.
//   2. A token is consumed by an atomic rename before anything is read, so it
//      runs at most once even if two callers race.
//   3. A token expires. A leftover token is a leftover retry, and autoagy's
//      one-shot approvals are deliberately one-shot.
//
// Self-contained on purpose: `autoagy setup` copies it next to the token
// directory, where the plugin's lib/ is not reachable.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const TOKEN_NAME_RE = /^[0-9a-f]{32}$/;
// Only root-owned shells, for the same reason confine.mjs takes only those: a
// shell found through PATH could be a file the agent planted.
const SHELL_CANDIDATES = ['/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh'];

const fail = (message) => {
  process.stderr.write(`exec-confined: ${message}\n`);
  process.exit(126);
};

function trustedShell() {
  for (const file of SHELL_CANDIDATES) {
    try {
      const stat = fs.statSync(file);
      if (stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0) return file;
    } catch {
      // try the next one
    }
  }
  return null;
}

const name = process.argv[2];
if (!name) fail('no token given');
// The check that makes the argument a name rather than a path: no separator, no
// `..`, no absolute path can survive it.
if (!TOKEN_NAME_RE.test(name)) fail('not a token name');

// This program's own location decides where tokens live. Nothing is read from
// the environment: a command that reached this point could have set it.
const here = path.dirname(fileURLToPath(import.meta.url));
const pending = path.join(here, '..', 'state', 'pending');
const tokenFile = path.join(pending, `${name}.json`);
const claimFile = path.join(pending, `${name}.claimed.${process.pid}`);

// Claim before reading: rename is atomic, so of two callers holding the same
// token exactly one gets past this line.
try {
  fs.renameSync(tokenFile, claimFile);
} catch {
  fail('no such token (already used, expired, or never issued)');
}

let token;
try {
  token = JSON.parse(fs.readFileSync(claimFile, 'utf8'));
} catch (err) {
  fs.rmSync(claimFile, { force: true });
  fail(`unreadable token: ${err.message}`);
}
fs.rmSync(claimFile, { force: true });

if (!token || typeof token.commandLine !== 'string' || token.commandLine === '') fail('token carries no command');
if (typeof token.expiresAt !== 'number' || Date.now() > token.expiresAt) fail('token has expired');

const shell = trustedShell();
if (!shell) fail('no root-owned shell to run the command with');

// The working directory comes from the token, not from the one this process was
// started in: the call that reaches here is one agy built, and its `Cwd` is the
// agent's to choose.
if (typeof token.cwd === 'string' && token.cwd) {
  try {
    process.chdir(token.cwd);
  } catch (err) {
    fail(`cannot enter ${token.cwd}: ${err.message}`);
  }
}

const res = spawnSync(shell, ['-c', token.commandLine], { stdio: 'inherit' });
if (res.error) fail(`could not run the command: ${res.error.message}`);
process.exit(res.signal ? 128 : (res.status ?? 1));
