// Reviewer model backends.
//
// - agy:    runs the plugin's tool-less `autoagy-guardian` agent headlessly
//           (`agy --agent autoagy-guardian --input-format stream-json ...`).
//           Uses the user's Antigravity login; no API key needed. The agent
//           does not inherit customizations, so these hooks do not recurse.
// - openai: any OpenAI-compatible Chat Completions endpoint (OpenAI, Gemini's
//           OpenAI endpoint, DeepSeek, local servers, ...).
// - mock:   deterministic responses for tests, selected in the config file
//           (never through environment variables, which reach the hook from
//           whatever process started agy).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { ReviewTimeoutError } from './guardian.mjs';

/**
 * @typedef {{ name: string, review: (prompt: { system: string, user: string }, options: { timeoutMs: number }) => Promise<string> }} Reviewer
 */

/**
 * @param {object} config
 * @param {{ env?: NodeJS.ProcessEnv, autoagyHome: string, executable?: string | null, home?: string, reviewConversationGraceMs?: number }} options
 *   `executable`: the agy binary to run (HookContext.reviewerExecutable); never looked up on PATH here
 *   `home`: whose agy CLI data directory the review conversations land in
 * @returns {Reviewer | null} null when no reviewer model is configured
 */
export function createReviewer(config, { env = process.env, autoagyHome, executable = null, home = os.homedir(), reviewConversationGraceMs = REVIEW_CONVERSATION_GRACE_MS }) {
  switch (config.reviewer.backend) {
    case 'agy':
      return agyReviewer(config.reviewer.agy, { env, autoagyHome, executable, appDataDir: agyCliDataDir(home), graceMs: reviewConversationGraceMs });
    case 'openai':
      return openaiReviewer(config.reviewer.openai, { env });
    case 'mock':
      return mockReviewer(config.reviewer.mock);
    default:
      return null;
  }
}

/** The single message sent to the guardian agent (its system prompt is fixed in the agent file). */
export function agyMessageText({ system, user }) {
  return `<review_policy>\n${system}\n</review_policy>\n\n${user}`;
}

function agyReviewer(options, { env, autoagyHome, executable, appDataDir, graceMs }) {
  return {
    name: 'agy',
    review(prompt, { timeoutMs }) {
      if (!executable) {
        return Promise.reject(
          new Error(`cannot find "${options.command}" outside the directories agents can write; set reviewer.agy.command to the absolute path of agy`),
        );
      }
      // The conversations of earlier reviews, now that they are surely finished.
      // Never allowed to fail a review: what is left behind is the old behaviour.
      try {
        deleteFinishedReviewConversations(autoagyHome, appDataDir, { olderThanMs: graceMs });
      } catch {
        // tried again on the next review
      }
      let recorded = false;
      const cwd = path.join(autoagyHome, 'guardian');
      fs.mkdirSync(cwd, { recursive: true });
      const args = ['--agent', options.agent, '--input-format', 'stream-json', '--output-format', 'stream-json'];
      if (options.model) args.push('--model', options.model);
      if (options.effort) args.push('--effort', options.effort);
      args.push('-p=');
      const line = JSON.stringify({ event: 'user', message: { content: [{ type: 'text', text: agyMessageText(prompt) }] } });
      return new Promise((resolve, reject) => {
        let settled = false;
        let stdout = '';
        let stderr = '';
        // A Windows .cmd shim needs a shell; quote the path for it.
        const shell = process.platform === 'win32' && !/\.exe$/i.test(executable);
        const child = spawn(shell ? `"${executable}"` : executable, args, {
          cwd,
          env: { ...env, AUTOAGY_ROLE: 'guardian' },
          stdio: ['pipe', 'pipe', 'pipe'],
          shell,
          windowsHide: true,
        });
        const finish = (fn, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          fn(value);
        };
        const timer = setTimeout(() => {
          child.kill('SIGTERM');
          setTimeout(() => child.kill('SIGKILL'), 2000).unref();
          finish(reject, new ReviewTimeoutError(`agy reviewer did not answer within ${Math.round(timeoutMs / 1000)}s`));
        }, timeoutMs);
        child.stdout.on('data', (chunk) => {
          stdout += chunk;
          // As soon as agy names the conversation, so a review that is then
          // killed on its deadline is cleaned up as well.
          if (!recorded && !options.keepConversations) {
            const id = findReviewConversationId(stdout, options.agent);
            if (id) {
              recorded = true;
              try {
                recordReviewConversation(autoagyHome, id);
              } catch {
                // left behind, as before
              }
            }
          }
          const result = findResultEvent(stdout);
          if (result) {
            if (result.status === 'SUCCESS' && typeof result.response === 'string') finish(resolve, result.response);
            else finish(reject, new Error(`agy reviewer ${result.status ?? 'failed'}: ${result.error ?? 'no response'}`));
            child.stdin.destroy();
          }
        });
        child.stderr.on('data', (chunk) => {
          stderr = (stderr + chunk).slice(-4000);
        });
        child.on('error', (err) => finish(reject, new Error(`cannot run ${executable}: ${err.message}`)));
        child.on('close', (code) => {
          const result = findResultEvent(stdout);
          if (result?.status === 'SUCCESS' && typeof result.response === 'string') return finish(resolve, result.response);
          const detail = (result?.error ?? stderr.trim().split('\n').slice(-3).join(' ')) || 'no output';
          finish(reject, new Error(`agy reviewer exited with code ${code}: ${detail}`));
        });
        child.stdin.on('error', () => {});
        child.stdin.end(`${line}\n`);
      });
    },
  };
}

// agy keeps the newest 500 conversations and deletes the oldest, and every
// review is one. Measured on a real install (agy 1.3.1): 479 of 501
// conversations were reviews, so the user's own were deleted after about a
// week. Each review's conversation is therefore deleted once it is finished.
//
// What a conversation is on disk, measured the same day: a `brain/<id>`
// directory and three files named after the id; its id also sits in two summary
// indexes. agy's own deletion at the cap removes the files and leaves the index
// rows (493 orphaned rows measured), which agy reconciles at startup, and
// resuming a deleted id only warns that it was not found. Deleting the files is
// the same thing done earlier, for conversations nobody returns to: what a
// review saw and answered is kept in autoagy's own review log.
export const REVIEW_CONVERSATION_GRACE_MS = 15 * 60_000;
const CONVERSATION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The data directory of the agy CLI, which runs every agy review whoever started the agent. */
export function agyCliDataDir(home) {
  return path.join(home, '.gemini', 'antigravity-cli');
}

/** Everything agy keeps under a conversation's own name. */
function conversationPaths(appDataDir, id) {
  return [
    path.join(appDataDir, 'brain', id),
    ...['.db', '.db-wal', '.db-shm', '.db-journal'].map((ext) => path.join(appDataDir, 'conversations', `${id}${ext}`)),
    path.join(appDataDir, 'annotations', `${id}.pbtxt`),
    path.join(appDataDir, 'presence', `${id}.lock`),
  ];
}

/**
 * Deletes one conversation's files. Only an id shaped like the ones agy makes,
 * so no value can name a path of its own; `rmSync` removes a link, not what it
 * points to.
 */
export function deleteConversation(appDataDir, id) {
  if (!appDataDir || !CONVERSATION_ID_RE.test(id)) return false;
  for (const p of conversationPaths(appDataDir, id)) fs.rmSync(p, { recursive: true, force: true });
  return true;
}

const reviewRunsDir = (autoagyHome) => path.join(autoagyHome, 'state', 'review-conversations');

/**
 * The conversation id from the reviewer's `init` event, when it is the review
 * agent's own conversation.
 */
function findReviewConversationId(stdout, agent) {
  for (const raw of stdout.split('\n')) {
    const text = raw.trim();
    if (!text.startsWith('{') || !text.includes('"init"')) continue;
    try {
      const event = JSON.parse(text);
      if (event.event !== 'init') continue;
      const id = event.conversation_id;
      return event.init?.agent === agent && typeof id === 'string' && CONVERSATION_ID_RE.test(id) ? id : null;
    } catch {
      // partial line
    }
  }
  return null;
}

/** One marker file per review: concurrent reviews never rewrite each other's record. */
function recordReviewConversation(autoagyHome, id) {
  const dir = reviewRunsDir(autoagyHome);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, id), '');
}

/**
 * Deletes the review conversations recorded at least `olderThanMs` ago. The
 * default is longer than the longest review the configuration allows (600s), so
 * an agy still writing to one is never pulled out from under it.
 */
export function deleteFinishedReviewConversations(autoagyHome, appDataDir, { olderThanMs = REVIEW_CONVERSATION_GRACE_MS, now = Date.now() } = {}) {
  const dir = reviewRunsDir(autoagyHome);
  let names = [];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  let deleted = 0;
  for (const name of names) {
    const marker = path.join(dir, name);
    try {
      if (now - fs.statSync(marker).mtimeMs < olderThanMs) continue;
      if (deleteConversation(appDataDir, name)) deleted += 1;
      fs.rmSync(marker, { force: true });
    } catch {
      // the next review tries again
    }
  }
  return deleted;
}

/**
 * The review conversations already on disk, for `autoagy prune-reviews`: the
 * backlog from before reviews deleted their own, which on a real install was 479
 * of 501 conversations.
 *
 * Found in agy's summary index, read-only; the directories of a review and of a
 * user's conversation look the same, so there is nothing else to tell them by.
 * Two things must both match: the agent name, and the workspace being the
 * directory autoagy runs every review in. The agent alone was not enough on a
 * real install: one of 478 conversations of that agent had been run in a
 * project (by hand, or as a subagent), and that one is the user's. A
 * conversation touched within `olderThanMs` may be a review still running and
 * is left for later.
 *
 * @returns {Promise<{ ids: string[] }>} the conversations deleted, or that would be with `dryRun`
 */
export async function pruneReviewConversations({ appDataDir, agent, guardianDir, olderThanMs = REVIEW_CONVERSATION_GRACE_MS, dryRun = false, now = Date.now() }) {
  let sqlite;
  try {
    sqlite = await import('node:sqlite');
  } catch {
    throw new Error('this needs the node:sqlite module, which Node.js has from 22.13 on');
  }
  const index = path.join(appDataDir, 'conversation_summaries.db');
  if (!fs.existsSync(index)) return { ids: [] };
  const db = new sqlite.DatabaseSync(index, { readOnly: true });
  let rows;
  try {
    rows = db.prepare('SELECT conversation_id, workspace_uris FROM conversation_summaries WHERE agent_name = ?').all(agent);
  } finally {
    db.close();
  }
  const reviewWorkspace = JSON.stringify([pathToFileURL(guardianDir).href]);
  rows = rows.filter((row) => {
    try {
      return JSON.stringify(JSON.parse(String(row.workspace_uris))) === reviewWorkspace;
    } catch {
      return false;
    }
  });
  const lastTouched = (id) => Math.max(...conversationPaths(appDataDir, id).map((p) => {
    try {
      return fs.statSync(p).mtimeMs;
    } catch {
      return 0;
    }
  }));
  const ids = [...new Set(rows.map((row) => String(row.conversation_id)))]
    .filter((id) => CONVERSATION_ID_RE.test(id) && fs.existsSync(path.join(appDataDir, 'brain', id)))
    .filter((id) => now - lastTouched(id) >= olderThanMs)
    .sort();
  if (!dryRun) for (const id of ids) deleteConversation(appDataDir, id);
  return { ids };
}

function findResultEvent(stdout) {
  for (const raw of stdout.split('\n')) {
    const text = raw.trim();
    if (!text.startsWith('{') || !text.includes('"result"')) continue;
    try {
      const event = JSON.parse(text);
      if (event.event === 'result' && event.result) return event.result;
    } catch {
      // partial line
    }
  }
  return null;
}

function openaiReviewer(options, { env }) {
  return {
    name: 'openai',
    async review({ system, user }, { timeoutMs }) {
      const key = env[options.apiKeyEnv];
      if (!key) throw new Error(`environment variable ${options.apiKeyEnv} is not set`);
      const body = {
        model: options.model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: user },
        ],
      };
      if (options.jsonMode) body.response_format = { type: 'json_object' };
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(`${String(options.baseUrl).replace(/\/+$/, '')}/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: `Bearer ${key}`, ...(options.headers ?? {}) },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        const text = await res.text();
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`);
        const content = JSON.parse(text)?.choices?.[0]?.message?.content;
        if (typeof content !== 'string') throw new Error('response has no message content');
        return content;
      } catch (err) {
        if (err?.name === 'AbortError') throw new ReviewTimeoutError(`reviewer did not answer within ${Math.round(timeoutMs / 1000)}s`);
        throw err;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

const MOCK_RESPONSES = {
  allow: '{"outcome":"allow"}',
  deny: '{"risk_level":"high","user_authorization":"unknown","outcome":"deny","rationale":"mock denial"}',
  critical: '{"risk_level":"critical","user_authorization":"low","outcome":"deny","rationale":"mock critical denial"}',
  garbage: 'not json',
};

function mockReviewer({ response, capture }) {
  return {
    name: 'mock',
    async review(prompt, { timeoutMs }) {
      if (capture) fs.appendFileSync(capture, `${JSON.stringify(prompt)}\n`);
      let spec = response;
      const sleep = /^sleep:(\d+):(.*)$/s.exec(spec);
      if (sleep) {
        const ms = Number(sleep[1]);
        if (ms >= timeoutMs) {
          await new Promise((r) => setTimeout(r, timeoutMs));
          throw new ReviewTimeoutError();
        }
        await new Promise((r) => setTimeout(r, ms));
        spec = sleep[2];
      }
      if (spec === 'timeout') throw new ReviewTimeoutError();
      if (spec === 'error') throw new Error('mock reviewer error');
      return MOCK_RESPONSES[spec] ?? spec;
    },
  };
}
