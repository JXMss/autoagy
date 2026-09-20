// The acceptance tests for `bin/exec-confined`. They are the design: the whole
// point of narrowing `command(*)` to one program is that the program refuses
// everything except a token autoagy itself wrote, so these three refusals are
// what the narrow grant is worth. If any of them passes something through, the
// grant is `command(*)` again under another name.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { installExecutor, mintToken, sweepTokens, tokenDir, executorPath, executorInstalled, TOKEN_TTL_MS } from '../plugin/lib/tokens.mjs';

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-token-')));
const home = path.join(root, 'autoagy');
const workspace = path.join(root, 'workspace');
fs.mkdirSync(workspace, { recursive: true });
installExecutor(home);
after(() => fs.rmSync(root, { recursive: true, force: true }));

const run = (...args) => spawnSync(executorPath(home), args, { encoding: 'utf8', cwd: workspace });
const marker = (name) => path.join(workspace, name);

test('the executor is installed runnable, with its interpreter pinned', () => {
  assert.ok(executorInstalled(home));
  assert.match(fs.readFileSync(executorPath(home), 'utf8').split('\n')[0], new RegExp(`^#!${process.execPath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`));
});

test('refuses with no token at all', () => {
  const res = run();
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /no token given/);
});

// The one that decides whether the narrow grant means anything. An agent
// holding `command(<executor>)` can write files in its workspace; if the
// argument were a path it could write its own JSON and pass that, and the grant
// would be a licence to run anything again.
test('refuses anything that is a path rather than a token name', () => {
  const forged = marker('evil.json');
  fs.writeFileSync(forged, JSON.stringify({ commandLine: `touch ${marker('PWNED')}`, expiresAt: Date.now() + 60_000 }));
  const attempts = [
    forged,
    './evil.json',
    '../autoagy/state/pending/x',
    path.join(tokenDir(home), 'x.json'),
    // A name of the right shape but reached through a traversal is still a path.
    `../../${'a'.repeat(32)}`,
    'a'.repeat(31), // wrong length
    `${'a'.repeat(32)}.json`, // the file name, not the token name
    'A'.repeat(32), // uppercase is not the alphabet the names use
  ];
  for (const attempt of attempts) {
    const res = run(attempt);
    assert.notEqual(res.status, 0, attempt);
    assert.match(res.stderr, /not a token name/, attempt);
  }
  assert.ok(!fs.existsSync(marker('PWNED')), 'nothing the forged file asked for ran');
});

test('a token runs once and only once', () => {
  const out = marker('once.txt');
  const { name } = mintToken(home, { commandLine: `printf ran >> ${out}` });
  const first = run(name);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(fs.readFileSync(out, 'utf8'), 'ran');

  const second = run(name);
  assert.notEqual(second.status, 0);
  assert.match(second.stderr, /already used/);
  assert.equal(fs.readFileSync(out, 'utf8'), 'ran', 'the command did not run a second time');
  assert.ok(!fs.existsSync(path.join(tokenDir(home), `${name}.json`)), 'the token is consumed, not left for a retry');
});

test('an expired token is refused', () => {
  const out = marker('expired.txt');
  const { name } = mintToken(home, { commandLine: `touch ${out}`, now: Date.now() - TOKEN_TTL_MS - 1000 });
  const res = run(name);
  assert.notEqual(res.status, 0);
  assert.match(res.stderr, /expired/);
  assert.ok(!fs.existsSync(out));
});

test('the working directory comes from the token, not from the caller', () => {
  const elsewhere = path.join(root, 'elsewhere');
  fs.mkdirSync(elsewhere, { recursive: true });
  const { name } = mintToken(home, { commandLine: 'pwd > where.txt', cwd: elsewhere });
  assert.equal(run(name).status, 0);
  assert.equal(fs.readFileSync(path.join(elsewhere, 'where.txt'), 'utf8').trim(), elsewhere);
  assert.ok(!fs.existsSync(path.join(workspace, 'where.txt')), 'not the directory the executor was started in');
});

test('the executor passes the command exit code through', () => {
  const { name } = mintToken(home, { commandLine: 'exit 42' });
  assert.equal(run(name).status, 42);
});

test('the sweep takes away what nobody redeemed, and leaves what is still live', () => {
  const stale = mintToken(home, { commandLine: 'true', now: Date.now() - TOKEN_TTL_MS - 1000 });
  const live = mintToken(home, { commandLine: 'true' });
  assert.ok(sweepTokens(home) >= 1);
  assert.ok(!fs.existsSync(stale.file), 'an unredeemed token is a retry nobody granted');
  assert.ok(fs.existsSync(live.file), 'the one still inside its window survives');
});

// The turn-end sweep is scoped to one conversation, and the token directory is
// not: it is shared by every conversation on the machine, while the hook that
// asks for the sweep runs after every model call. Reaching across would delete
// a token another conversation minted a moment ago and is about to run.
test('the turn-end sweep takes only its own conversation\'s tokens', () => {
  const mine = mintToken(home, { commandLine: 'true', conversation: 'conv-a' });
  const theirs = mintToken(home, { commandLine: 'true', conversation: 'conv-b' });

  assert.ok(sweepTokens(home, { all: true, conversation: 'conv-a' }) >= 1);
  assert.ok(!fs.existsSync(mine.file), 'this conversation is done, so its unredeemed token is a retry nobody granted');
  assert.ok(fs.existsSync(theirs.file), 'the other conversation is mid-call: its token is about to be redeemed');

  // No conversation to attribute means no claim over anyone's token.
  const unattributed = mintToken(home, { commandLine: 'true', conversation: 'conv-c' });
  sweepTokens(home, { all: true });
  assert.ok(fs.existsSync(unattributed.file), 'an unattributable sweep takes nothing');
});

test('the sweep still takes anything expired, whoever minted it', () => {
  const expired = mintToken(home, { commandLine: 'true', conversation: 'conv-d', now: Date.now() - TOKEN_TTL_MS - 1000 });
  sweepTokens(home, { all: true, conversation: 'conv-a' });
  assert.ok(!fs.existsSync(expired.file), 'past its window it is spent, whatever else is true');
});

test('a claim an executor is reading right now is left alone', () => {
  // Claiming is a rename and the read follows it, so the file existing means an
  // executor is inside it — for milliseconds. The turn-end sweep must not take
  // it out from under that read.
  const { name } = mintToken(home, { commandLine: 'true', conversation: 'conv-a' });
  const claim = path.join(tokenDir(home), `${name}.claimed.99999`);
  fs.renameSync(path.join(tokenDir(home), `${name}.json`), claim);

  sweepTokens(home, { all: true, conversation: 'conv-a' });
  assert.ok(fs.existsSync(claim), 'a live claim is not litter');

  // What a killed executor leaves behind is litter, and ages out like one.
  fs.utimesSync(claim, new Date(Date.now() - TOKEN_TTL_MS - 1000), new Date(Date.now() - TOKEN_TTL_MS - 1000));
  sweepTokens(home, { all: true, conversation: 'conv-a' });
  assert.ok(!fs.existsSync(claim));
});
