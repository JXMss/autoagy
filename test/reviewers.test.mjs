import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createReviewer, pruneReviewConversations } from '../plugin/lib/reviewers.mjs';
import { configWith } from './helpers.mjs';

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-reviewers-')));
after(() => fs.rmSync(root, { recursive: true, force: true }));

/**
 * A stand-in for `agy --agent … --output-format stream-json`: it makes the
 * files agy 1.3.1 keeps for a conversation and prints the events the real one
 * prints (measured: `init` and `result` both carry `conversation_id`, `init`
 * names the agent).
 */
function fakeAgy(dir) {
  const file = path.join(dir, 'fake-agy.mjs');
  fs.writeFileSync(
    file,
    `#!${process.execPath}
import fs from 'node:fs';
import path from 'node:path';
const id = process.env.FAKE_AGY_ID;
const appData = path.join(process.env.HOME, '.gemini', 'antigravity-cli');
for (const d of ['brain/' + id + '/.system_generated/logs', 'conversations', 'annotations', 'presence']) fs.mkdirSync(path.join(appData, d), { recursive: true });
fs.writeFileSync(path.join(appData, 'conversations', id + '.db'), 'x');
fs.writeFileSync(path.join(appData, 'annotations', id + '.pbtxt'), 'title: ""');
fs.writeFileSync(path.join(appData, 'presence', id + '.lock'), '');
const agent = process.env.FAKE_AGY_AGENT ?? process.argv[process.argv.indexOf('--agent') + 1];
process.stdin.resume();
process.stdin.once('data', () => {
  console.log(JSON.stringify({ event: 'init', conversation_id: id, init: { agent } }));
  console.log(JSON.stringify({ event: 'result', result: { conversation_id: id, status: 'SUCCESS', response: '{"outcome":"allow"}' } }));
});
process.stdin.on('end', () => process.exit(0));
`,
  );
  fs.chmodSync(file, 0o755);
  return file;
}

function setup(name) {
  const home = path.join(root, name);
  const autoagyHome = path.join(home, '.gemini', 'autoagy');
  const appData = path.join(home, '.gemini', 'antigravity-cli');
  fs.mkdirSync(autoagyHome, { recursive: true });
  const executable = fakeAgy(home);
  const files = (id) => [
    path.join(appData, 'brain', id),
    path.join(appData, 'conversations', `${id}.db`),
    path.join(appData, 'annotations', `${id}.pbtxt`),
    path.join(appData, 'presence', `${id}.lock`),
  ];
  const review = (id, { agy = {}, agent, graceMs } = {}) => {
    const config = configWith({ reviewer: { ...configWith().reviewer, backend: 'agy', agy: { ...configWith().reviewer.agy, ...agy } } });
    const env = { HOME: home, PATH: process.env.PATH, FAKE_AGY_ID: id, ...(agent ? { FAKE_AGY_AGENT: agent } : {}) };
    const reviewer = createReviewer(config, { env, autoagyHome, executable, home, ...(graceMs === undefined ? {} : { reviewConversationGraceMs: graceMs }) });
    return reviewer.review({ system: 'policy', user: 'action' }, { timeoutMs: 20_000 });
  };
  return { home, autoagyHome, appData, files, review };
}

const ID = (n) => `${String(n).repeat(8)}-aaaa-4aaa-8aaa-${String(n).repeat(12)}`;
const exists = (p) => fs.existsSync(p);

test('a review conversation is deleted once it is old enough, and nothing else is', async () => {
  // agy keeps the newest 500 conversations, and every review was one: 479 of
  // the 501 on a real install, so the user's own were deleted after about a
  // week. agy deletes at its cap by removing these files and leaving the summary
  // index to reconcile itself (493 orphaned rows measured), and resuming a
  // deleted id only warns "not found", so this is the same thing done earlier.
  const { appData, files, review } = setup('cleanup');
  const user = ID(9);
  for (const p of files(user)) fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.mkdirSync(files(user)[0], { recursive: true });
  for (const p of files(user).slice(1)) fs.writeFileSync(p, 'mine');

  assert.equal(await review(ID(1)), '{"outcome":"allow"}');
  assert.ok(files(ID(1)).every(exists), 'the review made its conversation');
  // Not yet: a review that may still be running is never touched.
  await review(ID(2));
  assert.ok(files(ID(1)).every(exists), 'within the grace period the earlier one stays');
  // Old enough: the next review removes both earlier ones, and only those.
  await review(ID(3), { graceMs: 0 });
  assert.ok(!files(ID(1)).some(exists), 'every file of the first review conversation is gone');
  assert.ok(!files(ID(2)).some(exists));
  assert.ok(files(ID(3)).every(exists), 'the one just made waits for the next review');
  assert.ok(files(user).every(exists), 'a conversation no review made is never touched');
  assert.ok(exists(path.join(appData, 'brain')), 'nor are the directories they live in');
});

test('only a conversation the reviewer itself reported is ever recorded for deletion', async () => {
  const { files, review } = setup('only-own');
  // Another agent's conversation, a malformed id, and an operator who wants to
  // keep review conversations: none of them is deleted later.
  await review(ID(4), { agent: 'some-other-agent' });
  await review(ID(5), { agy: { keepConversations: true } });
  await review('not-a-conversation-id', {});
  await review(ID(6), { graceMs: 0 });
  assert.ok(files(ID(4)).every(exists), 'a conversation of a different agent stays');
  assert.ok(files(ID(5)).every(exists), 'keepConversations keeps it');
  assert.ok(files('not-a-conversation-id').every(exists), 'an id that is not one agy makes is never recorded');
});

let sqlite = null;
try {
  sqlite = await import('node:sqlite');
} catch {
  // Node before 22.13: prune-reviews says so instead of guessing.
}

test('prune-reviews removes the review conversations already there, by the agent name agy recorded', { skip: sqlite ? false : 'node:sqlite is unavailable (Node 22.13+ has it)' }, async () => {
  // Before this, every review stayed. The agent name is only in agy's summary
  // index; the conversation directories of a review and of a user look the same.
  // Called as a function on a fixture directory: the CLI command acts on the
  // account's real agy data, which a test must never touch.
  const { appData, autoagyHome, files } = setup('prune');
  const reviewIds = [ID(1), ID(2)];
  const userIds = [ID(7), ID(8)];
  const recent = ID(3);
  for (const id of [...reviewIds, ...userIds, recent]) {
    fs.mkdirSync(files(id)[0], { recursive: true });
    for (const p of files(id).slice(1)) {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, 'x');
    }
    if (id === recent) continue;
    const old = new Date(Date.now() - 3_600_000);
    for (const p of files(id)) fs.utimesSync(p, old, old);
  }
  const guardianDir = path.join(autoagyHome, 'guardian');
  const db = new sqlite.DatabaseSync(path.join(appData, 'conversation_summaries.db'));
  db.exec("CREATE TABLE conversation_summaries (conversation_id text, agent_name text NOT NULL DEFAULT '', workspace_uris text)");
  const insert = db.prepare('INSERT INTO conversation_summaries (conversation_id, agent_name, workspace_uris) VALUES (?, ?, ?)');
  const inGuardianDir = JSON.stringify([pathToFileURL(guardianDir).href]);
  for (const id of [...reviewIds, recent]) insert.run(id, 'autoagy-guardian', inGuardianDir);
  for (const id of userIds.slice(0, 1)) insert.run(id, '', JSON.stringify(['file:///home/me/project']));
  // The review agent run by hand, or as a subagent, in a project: not one of
  // autoagy's reviews, which always run in its own directory. Measured: one such
  // conversation among 478 on a real install.
  insert.run(userIds[1], 'autoagy-guardian', JSON.stringify(['file:///home/me/project']));
  // A row whose conversation agy already deleted: nothing to do for it.
  insert.run(ID(5), 'autoagy-guardian', inGuardianDir);
  db.close();

  const prune = (options) => pruneReviewConversations({ appDataDir: appData, agent: 'autoagy-guardian', guardianDir, ...options });
  const dry = await prune({ dryRun: true });
  assert.deepEqual(dry.ids, reviewIds);
  assert.ok(reviewIds.every((id) => files(id).every(exists)), 'a dry run deletes nothing');

  const real = await prune({});
  assert.deepEqual(real.ids, reviewIds);
  assert.ok(reviewIds.every((id) => !files(id).some(exists)), 'the review conversations are gone');
  assert.ok(userIds.every((id) => files(id).every(exists)), 'the user\'s own are untouched');
  assert.ok(files(recent).every(exists), 'a review that may still be running is left for later');
});
