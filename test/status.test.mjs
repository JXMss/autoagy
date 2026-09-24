// `autoagy status` reads the configuration directory, not the user's home
// directory. Those two were briefly confused, which silently hid the self-check
// warning — the one line that reports autoagy's own sandbox being switched off
// for an agy build.

import { test, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { makeSandboxDirs } from './helpers.mjs';
import { updateState, markUntrusted, readState } from '../plugin/lib/state.mjs';
import { probeBwrap } from '../plugin/lib/confine.mjs';

const BIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'plugin', 'bin', 'autoagy.mjs');
const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

beforeEach(() => {
  fs.rmSync(dirs.env.AUTOAGY_HOME, { recursive: true, force: true });
});

const status = () => {
  const res = spawnSync(process.execPath, [BIN, 'status'], { env: dirs.env, encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);
  return res.stdout;
};

test('status keeps the configuration directory and the user home apart', () => {
  const out = status();
  assert.match(out, new RegExp(`log: ${dirs.env.AUTOAGY_HOME}/logs/decisions\\.jsonl`));
  assert.doesNotMatch(out, new RegExp(`log: ${dirs.home}/logs/`), 'the user home is not the configuration directory');
  assert.match(out, /setup record\s+none/);
});

test('status names the flagged conversations', () => {
  assert.doesNotMatch(status(), /Flagged conversations/);
  updateState(dirs.env.AUTOAGY_HOME, dirs.conversationId, (s) => {
    markUntrusted(s, { reason: 'edit-target-changed', detail: 'x resolved to y', step: 7 });
    s.backgroundSuspected = true;
    s.pendingPlaceholders = { 7: [] };
  });
  const out = status();
  assert.match(out, /Flagged conversations/);
  assert.match(out, new RegExp(dirs.conversationId));
  assert.match(out, /edit-target-changed/);
  assert.match(out, /backgrounded command may still be running/);
});

test('a planted-hook record flags the conversation, and `trust` is what releases it', () => {
  const gitDir = path.join(dirs.workspace, 'sub', '.git');
  updateState(dirs.env.AUTOAGY_HOME, dirs.conversationId, (s) => {
    s.plantedHooks = [{ path: gitDir, dir: path.dirname(gitDir), step: 4, hooks: [{ name: 'pre-commit', bytes: 21, head: '#!/bin/sh\n' }], config: [] }];
  });
  const out = status();
  assert.match(out, /Flagged conversations/, 'a plant is something a person has to look at');
  assert.match(out, /planted git hook/);
  assert.match(out, new RegExp(gitDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  // A bare `trust` lists rather than releasing: the same premise the mount
  // points and the untrusted mark rest on.
  const listed = spawnSync(process.execPath, [BIN, 'trust'], { env: dirs.env, encoding: 'utf8' });
  assert.equal(listed.status, 0, listed.stderr);
  assert.match(listed.stdout, /planted git hook/);
  assert.equal(readState(dirs.env.AUTOAGY_HOME, dirs.conversationId).plantedHooks.length, 1, 'still there');

  const released = spawnSync(process.execPath, [BIN, 'trust', '--all'], { env: dirs.env, encoding: 'utf8' });
  assert.equal(released.status, 0, released.stderr);
  const state = readState(dirs.env.AUTOAGY_HOME, dirs.conversationId);
  assert.deepEqual(state.plantedHooks, [], 'the human has looked');
  assert.deepEqual(state.pendingNestedGit, {});
  assert.doesNotMatch(status(), /Flagged conversations/);
});

test('a reviewer command that cannot name a program is reported, not crashed on', () => {
  // `merge`'s type check lets `null` through, because the default is a string
  // but the key may be set to null — and `path.isAbsolute(null)` threw, so the
  // whole command died with `The "path" argument must be of type string.
  // Received null` and exited 1. A setting nobody can act on is a thing to say,
  // not a thing to fall over.
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  const config = path.join(dirs.env.AUTOAGY_HOME, 'config.json');
  for (const command of [null, '', './bin/agy']) {
    fs.writeFileSync(config, JSON.stringify({ reviewer: { backend: 'agy', agy: { command } } }));
    const out = status();
    assert.match(out, /reviewer\.agy\.command .* does not name a program/, `for ${JSON.stringify(command)}`);
  }
  // And a usable one still reports where it resolved.
  fs.writeFileSync(config, JSON.stringify({ reviewer: { backend: 'agy', agy: { command: '/nope/agy' } } }));
  assert.match(status(), /NOT runnable at \/nope\/agy/);
});

test('`mode` refuses to rewrite a configuration file it cannot parse', () => {
  // It was `readJsonQuiet(file) ?? {}` followed by a write of the whole object:
  // one trailing comma in `config.json` and the mode change took
  // `trustedDomains`, `credentialPaths`, `protectedPaths`, `writableRoots` and
  // `policy.file` with it. The result is *valid* JSON, so nothing downstream —
  // `loadConfig`'s warnings included — ever mentioned it again.
  const home = path.join(path.dirname(dirs.env.AUTOAGY_HOME), 'mode-home');
  const env = { ...dirs.env, AUTOAGY_HOME: home };
  fs.mkdirSync(home, { recursive: true });
  const file = path.join(home, 'config.json');
  const broken = '{\n  "trustedDomains": ["docs.example"],\n}\n';
  fs.writeFileSync(file, broken);
  const res = spawnSync(process.execPath, [BIN, 'mode', 'off'], { env, encoding: 'utf8' });
  assert.notEqual(res.status, 0, 'it fails instead of reporting a mode change');
  assert.match(res.stderr, /not valid JSON/);
  assert.equal(fs.readFileSync(file, 'utf8'), broken, 'and the file is left exactly as it was');
  fs.rmSync(home, { recursive: true, force: true });
});

test('`stats` counts the whole log, the rotated file included', () => {
  // It read the last megabyte of the current file and never the `.1.jsonl`
  // rotation leaves, so a full log was summarised from its newest tenth.
  const home = dirs.env.AUTOAGY_HOME;
  const logs = path.join(home, 'logs');
  fs.mkdirSync(logs, { recursive: true });
  const row = (i) => JSON.stringify({ time: new Date(Date.now() - 60_000 + i).toISOString(), conversation: 'c1', tool: 'run_command', verdict: 'allow', category: 'sandboxed-command', note: 'x'.repeat(150) });
  const rows = (from, n) => `${Array.from({ length: n }, (_, i) => row(from + i)).join('\n')}\n`;
  fs.writeFileSync(path.join(logs, 'decisions.1.jsonl'), rows(0, 1000));
  fs.writeFileSync(path.join(logs, 'decisions.jsonl'), rows(1000, 7000));
  assert.ok(fs.statSync(path.join(logs, 'decisions.jsonl')).size > 1024 * 1024, 'the current file alone is past the old megabyte');
  try {
    const res = spawnSync(process.execPath, [BIN, 'stats'], { env: dirs.env, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /verdicts\s+allow 8000\b/, res.stdout.split('\n').find((l) => l.includes('verdicts')));
  } finally {
    fs.rmSync(path.join(logs, 'decisions.1.jsonl'), { force: true });
    fs.rmSync(path.join(logs, 'decisions.jsonl'), { force: true });
  }
});

test('`stats` counts the decisions, and says what the log cannot show', () => {
  const home = dirs.env.AUTOAGY_HOME;
  const logs = path.join(home, 'logs');
  fs.mkdirSync(logs, { recursive: true });
  const row = (over) => JSON.stringify({ time: new Date().toISOString(), conversation: 'c1', tool: 'run_command', ...over });
  const stats = () => {
    const res = spawnSync(process.execPath, [BIN, 'stats'], { env: dirs.env, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    return res.stdout;
  };
  fs.writeFileSync(
    path.join(logs, 'decisions.jsonl'),
    [
      row({ verdict: 'deny', category: 'dangerous-command', review: { backend: 'agy', status: 'denied', risk: 'high', latencyMs: 5200 } }),
      row({ verdict: 'allow', category: 'sandbox-escalation', review: { backend: 'agy', status: 'approved', risk: 'low', latencyMs: 3900 } }),
      row({ verdict: 'deny', category: 'mcp', review: { backend: 'agy', status: 'failed', error: 'quota', latencyMs: 900 } }),
      '',
    ].join('\n'),
  );
  const out = stats();
  const reviewLine = out.split('\n').find((l) => l.includes('reviews')) ?? '';
  assert.match(reviewLine, /total 3/);
  for (const part of ['approved 1', 'denied 1', 'failed 1']) assert.ok(reviewLine.includes(part), `${part} in: ${reviewLine.trim()}`);
  assert.match(out, /p50 3\.9s/);
  const riskLine = out.split('\n').find((l) => l.includes('risk')) ?? '';
  for (const part of ['low 1', 'high 1']) assert.ok(riskLine.includes(part), `${part} in: ${riskLine.trim()}`);
  // An action allowed *without* a review is the other half of the answer, and it
  // is only in the log when `log.allowed` is on — so a zero has to be explained
  // rather than reported as "none happened".
  assert.match(out, /allowed free\s+0 action/, 'the count is shown');
  assert.match(out, /log\.allowed/, 'and the reason it may be zero is named, with how to turn it on');

  fs.appendFileSync(path.join(logs, 'decisions.jsonl'), `${row({ verdict: 'allow', category: 'read' })}\n`);
  const withAllows = stats();
  assert.match(withAllows, /allowed free\s+1 action/);
  assert.doesNotMatch(withAllows, /log\.allowed/, 'once one is recorded, the caveat is gone');
});

test('a count flag with no value falls back to the default, not to one record', () => {
  const home = dirs.env.AUTOAGY_HOME;
  const logs = path.join(home, 'logs');
  fs.mkdirSync(logs, { recursive: true });
  const rows = Array.from({ length: 5 }, (_, i) =>
    JSON.stringify({ time: new Date().toISOString(), conversation: 'c1', tool: `tool-${i}`, verdict: 'deny', reason: `r${i}` }),
  );
  fs.writeFileSync(path.join(logs, 'decisions.jsonl'), `${rows.join('\n')}\n`);

  const out = (args) => {
    const res = spawnSync(process.execPath, [BIN, ...args], { env: dirs.env, encoding: 'utf8' });
    assert.equal(res.status, 0, res.stderr);
    return res.stdout;
  };
  assert.equal((out(['log']).match(/^[A-Z0-9-]/gm) ?? []).length, 5, 'no flag means the default, which is the whole tail here');
  assert.match(out(['log', '-n', '2']), /tool-4/);
  assert.doesNotMatch(out(['log', '-n', '2']), /tool-1/, 'and a number is honoured');
  assert.match(out(['log', '-n']), /tool-0/, 'a flag with no value is not read as "one"');
});

test('status says when a conversation\'s state file cannot be read', () => {
  // The hook's answer to an unreadable state file is to stop trusting that
  // conversation, and `listStates` skips the file — so without a line here the
  // user meets the reviews with nothing telling them why.
  const dir = path.join(dirs.env.AUTOAGY_HOME, 'state');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'conv-x.json'), '{oops');
  const out = status();
  assert.match(out, /conv-x\.json cannot be read as state/);
  assert.match(out, /autoagy trust/);
});

// `status` reads the *account* home by design (see accountHome), so whether this
// machine has a real install decides what it prints; the predicate itself is
// pinned with a fixture home in setup.test.mjs. Skipped rather than faked where a
// real install exists — there the correct output is the other one.
const realInstall = fs.existsSync(path.join(os.userInfo().homedir, '.gemini', 'config', 'plugins', 'autoagy', 'hooks.json'));
test('status shouts when setup ran but the plugin was never installed', { skip: realInstall ? 'autoagy is really installed on this machine' : false }, () => {
  // Found on a real machine: `autoagy setup` had run from a checkout, so
  // `command(*)`, `mcp(*)` and `execute_url(*)` were live in agy's settings while
  // ~/.gemini/config/plugins was empty and no hook could ever run — and this
  // report described a healthy supervised system, down to "own sandbox active"
  // and "terminal sandbox in force (autoagy)". Two lines could have caught it: the
  // tripwire line, easy to read past, and the heartbeat line, which was guarded by
  // `installed` and therefore silent in exactly this case.
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(
    path.join(dirs.env.AUTOAGY_HOME, 'setup.json'),
    JSON.stringify({ time: '2026-09-21T02:10:05.946Z', addedGrants: ['command(*)', 'mcp(*)', 'execute_url(*)'] }),
  );
  const out = status();
  assert.match(out, /NOT INSTALLED — but `autoagy setup` has run/);
  assert.match(out, /grants added command\(\*\), mcp\(\*\), execute_url\(\*\)/);
  assert.match(out, /Nothing below is in force/);
  assert.match(out, /agy plugin install \.\/plugin/);
  // And the heartbeat line is no longer conditional on being installed.
  assert.match(out, /no hook has ever run \(the plugin is not installed\)/);
});

test('status says what the MCP annotations are worth here', () => {
  // Both halves are silent failures otherwise: trusting the annotations without a
  // scan reviews every call anyway, and a scan without the setting changes nothing.
  const dir = path.join(dirs.env.AUTOAGY_HOME, 'state');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ mcp: { annotations: 'trust' } }));
  assert.match(status(), /annotations are trusted but no scan has been recorded/);

  fs.writeFileSync(
    path.join(dir, 'mcp-tools.json'),
    JSON.stringify({
      at: '2026-09-21T01:00:00.000Z',
      servers: {
        github: { transport: 'stdio', error: null, tools: { get_issue: { readOnly: true }, delete_repo: { destructive: true } } },
        broken: { transport: 'stdio', error: 'it exited (code 3)', tools: {} },
      },
    }),
  );
  const out = status();
  assert.match(out, /1 of 2 scanned tool\(s\) claim read-only and run without review/);
  assert.match(out, /server "broken" could not be scanned: it exited \(code 3\)/);
  // And the cache is not mistaken for a conversation whose record is unreadable.
  assert.doesNotMatch(out, /mcp-tools\.json cannot be read as state/);
});

test('status says which tools.allow entries do nothing', () => {
  // The list only covers the `unknown-tool` fallback, which is what keeps `*`
  // from being a way to switch off the command and edit rules — but from the
  // setting alone an entry naming a known tool looks like it worked.
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ tools: { allow: ['shiny_new_tool', 'run_command', 'view_*', 'mcp_*'] } }));
  const out = status();
  assert.match(out, /tools\.allow\s+"run_command" matches a tool autoagy already has a rule for/);
  assert.match(out, /"view_\*" matches a tool autoagy already has a rule for/);
  assert.match(out, /"mcp_\*" matches a tool autoagy already has a rule for/);
  assert.doesNotMatch(out, /"shiny_new_tool" matches/, 'the entry that does something is not reported as a problem');
});

test('status says when a protection is only partial', () => {
  // Both of these were computed and reported to nobody. A truncated walk is the
  // state a 9p or network workspace is permanently in (measured here: 361 of
  // ~1269 directories), and an entry whose shape can never be mounted is
  // review-only on every host — neither is guessable from the outside.
  const dir = path.join(dirs.env.AUTOAGY_HOME, 'state');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'conv-scan.json'), JSON.stringify({ version: 1, conversationId: 'conv-scan', nestedScan: { visited: 361, truncated: true, at: '2026-09-21T00:46:28.673Z' } }));
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ protectedPaths: ['**/.husky/**', '/abs/src/**/gen*'] }));
  const out = status();
  assert.match(out, /nested scan\s+361 directories in the last run — TRUNCATED/);
  assert.match(out, /not mounted/);
  assert.match(out, /protectedPaths "\/abs\/src\/\*\*\/gen\*" is reviewed but never mounted read-only/);
  assert.doesNotMatch(out, /protectedPaths "\*\*\/\.husky/, 'a mountable entry is not reported as a problem');

  // A walk that finished says so without the warning.
  fs.writeFileSync(path.join(dir, 'conv-scan.json'), JSON.stringify({ version: 1, conversationId: 'conv-scan', nestedScan: { visited: 18, truncated: false, at: '2026-09-21T00:46:28.673Z' } }));
  const done = status();
  assert.match(done, /nested scan\s+18 directories in the last run \(/);
  assert.doesNotMatch(done, /TRUNCATED/);
});

test('status says how many domains the fetch prompt is off for, and what that costs', () => {
  // The prompt for an ungranted domain is the one autoagy cannot answer, so the
  // count is the answer to "why am I still being asked". Both directions are
  // reported, because "none" is the default and looks the same as "not
  // configured" otherwise.
  const configFile = path.join(dirs.env.AUTOAGY_HOME, 'config.json');
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(configFile, JSON.stringify({ networkGrants: 'none', trustedDomains: ['localhost', 'docs.python.org'] }));
  assert.match(status(), /network grants  none — a first fetch of any domain still prompts, including the 2/);

  fs.writeFileSync(configFile, JSON.stringify({ networkGrants: 'trusted-domains', trustedDomains: ['docs.python.org', '*.github.com', '*'] }));
  const out = status();
  assert.match(out, /network grants  2 read_url grant\(s\) from trustedDomains: read_url\(docs\.python\.org\), read_url\(github\.com\)/);
  // The wildcard entry is named rather than dropped in silence: it is a domain
  // that keeps prompting, and the reason is not guessable from the outside.
  assert.match(out, /trustedDomains entry "\*" got no read_url grant/);
  // Only the network line: the settings lines further down come from the
  // account's real settings file, which a test cannot isolate.
  assert.doesNotMatch(out.split('\n').find((l) => l.includes('network grants')), /read_url\(\*\)/);
});

test('status does not call a truncated probe cache an untrusted conversation', () => {
  // The same directory holds the probe cache and the two self-check records, and
  // they are the files here most likely to be found truncated. Reported as
  // conversations, every clause of that line is false — and it is the line a user
  // reads exactly when they are trying to find out why something feels wrong.
  const dir = path.join(dirs.env.AUTOAGY_HOME, 'state');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'bwrap-probe.json'), '{"key":"x","time":17');
  fs.writeFileSync(path.join(dir, 'own-sandbox-check.json'), '{"build":"x","stat');
  const out = status();
  assert.doesNotMatch(out, /cannot be read as state/);
  assert.doesNotMatch(out, /bwrap-probe/);
});

// From `/` the check could only fail — bwrap cannot make its mount points there
// — and "every sandboxed command fails" read as a broken sandbox to someone who
// had simply run status from a directory that is no workspace at all.
const bwrapHere = process.platform === 'linux' && probeBwrap(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-probe-'))).ok;
test('the sandbox start check runs only where agy could have a workspace', { skip: bwrapHere ? false : 'bubblewrap unavailable' }, () => {
  const home = dirs.env.AUTOAGY_HOME;
  fs.mkdirSync(home, { recursive: true });
  const cfg = path.join(home, 'config.json');
  const had = fs.existsSync(cfg) ? fs.readFileSync(cfg, 'utf8') : null;
  fs.writeFileSync(cfg, JSON.stringify({ ownSandbox: 'on', commandGrant: 'wildcard' }));
  try {
    const run = (cwd) => spawnSync(process.execPath, [BIN, 'status'], { env: dirs.env, cwd, encoding: 'utf8' }).stdout;
    const root = run('/');
    assert.match(root, /sandbox start\s+not checked: \/ is not writable/);
    assert.doesNotMatch(root, /sandbox start FAILED/);
    assert.match(run(dirs.workspace), /sandbox start\s+ok in /);
  } finally {
    if (had === null) fs.rmSync(cfg, { force: true });
    else fs.writeFileSync(cfg, had);
  }
});

test('status says when the config file pins a default this version moved on from', () => {
  // `setup` writes the whole template, so a default that changed later is still
  // sitting in the file. Measured on the first real install: a pinned
  // `timeoutSec: 90` inside a 90s per-attempt budget left nothing for the retry
  // the new default exists for, and nothing said so.
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ commandGrant: 'wildcard', reviewer: { timeoutSec: 90 } }));
  const out = status();
  assert.match(out, /reviewer\.timeoutSec is 90 in your file, which was the old default; it is now 140/);
  assert.match(out, /commandGrant is "wildcard" in your file/);
  // A value the user chose that was never a default is not reported, and neither
  // is one that matches today's default.
  fs.writeFileSync(path.join(dirs.env.AUTOAGY_HOME, 'config.json'), JSON.stringify({ commandGrant: 'executor', reviewer: { timeoutSec: 140 } }));
  const chosen = status();
  assert.ok(!/was the old default/.test(chosen), chosen);
});
