// Reads an Antigravity conversation log (transcript_full.jsonl) and renders the
// compact transcript the reviewer sees, following Codex's guardian rules
// (codex-rs/core/src/guardian/prompt.rs, guardian-context/src/retention.rs):
//
// - user and assistant messages share a 20k-token budget, tool calls and results
//   get a separate 10k-token budget so tool output cannot crowd out the humans;
// - each entry is capped (5k tokens for messages, 1k for tools);
// - if not every user message fits, the first and newest are kept first;
// - at most 40 recent non-user entries are kept.
//
// Only the human user's messages count as trusted authorization. For a
// subagent, those are the root conversation's messages; the subagent's own
// "user" messages were written by its parent agent and are untrusted.

import fs from 'node:fs';
import path from 'node:path';
import { truncateMiddle } from './policy.mjs';

export const BUDGETS = Object.freeze({
  messageTranscriptTokens: 20_000,
  toolTranscriptTokens: 10_000,
  messageEntryTokens: 5_000,
  toolEntryTokens: 1_000,
  recentNonUserEntries: 40,
  rootMessageTokens: 2_000,
  rootAuthorizationTokens: 8_000,
});

const MAX_READ_BYTES = 24 * 1024 * 1024;
const HEAD_BYTES = 2 * 1024 * 1024;

export const approxTokens = (text) => Math.ceil(Buffer.byteLength(text) / 4);
const capTokens = (text, tokens) => truncateMiddle(text, tokens * 4);

/** Reads JSONL rows, tolerating partial lines and very large files. */
export function readTranscriptRows(file) {
  let text;
  try {
    const size = fs.statSync(file).size;
    if (size <= MAX_READ_BYTES) {
      text = fs.readFileSync(file, 'utf8');
    } else {
      const fd = fs.openSync(file, 'r');
      try {
        const head = Buffer.alloc(HEAD_BYTES);
        fs.readSync(fd, head, 0, HEAD_BYTES, 0);
        const tailBytes = MAX_READ_BYTES - HEAD_BYTES;
        const tail = Buffer.alloc(tailBytes);
        fs.readSync(fd, tail, 0, tailBytes, size - tailBytes);
        const headText = head.toString('utf8');
        const tailText = tail.toString('utf8');
        text = `${headText.slice(0, headText.lastIndexOf('\n'))}\n${tailText.slice(tailText.indexOf('\n') + 1)}`;
      } finally {
        fs.closeSync(fd);
      }
    }
  } catch {
    return [];
  }
  const rows = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch {
      // Ignore partially written lines.
    }
  }
  return rows;
}

/** Extracts what the human typed from a USER_INPUT step. */
export function extractUserRequest(content) {
  const text = typeof content === 'string' ? content : JSON.stringify(content ?? '');
  // Greedy: the request itself may contain a literal `</USER_REQUEST>`; the last one is the harness's.
  const match = /<USER_REQUEST>([\s\S]*)<\/USER_REQUEST>/.exec(text);
  if (match) return match[1].trim();
  return text
    .replace(/<ADDITIONAL_METADATA>[\s\S]*?<\/ADDITIONAL_METADATA>/g, '')
    .replace(/<USER_SETTINGS_CHANGE>[\s\S]*?<\/USER_SETTINGS_CHANGE>/g, '')
    .trim();
}

/**
 * True when a USER_INPUT step carries the settings snapshot that Antigravity adds
 * to the first message of a conversation a person started. The harness writes it
 * after the request (`<USER_REQUEST>…</USER_REQUEST><ADDITIONAL_METADATA>…`), so
 * only that tail counts: a delegating agent can put the tag inside its request
 * text, never after the harness's closing `</USER_REQUEST>`.
 */
export function hasSettingsSnapshot(content) {
  if (typeof content !== 'string') return false;
  const end = content.lastIndexOf('</USER_REQUEST>');
  if (end < 0) return false;
  const tail = content.slice(end + '</USER_REQUEST>'.length).replace(/<ADDITIONAL_METADATA>[\s\S]*?<\/ADDITIONAL_METADATA>/g, '');
  return /^\s*<USER_SETTINGS_CHANGE>/.test(tail);
}

/** Older logs double-encode argument values as JSON strings. */
export function decodeArgs(args) {
  if (!args || typeof args !== 'object') return args;
  const out = {};
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === 'string' && /^\s*["{[]/.test(value)) {
      try {
        out[key] = JSON.parse(value);
        continue;
      } catch {
        // keep as is
      }
    }
    out[key] = value;
  }
  return out;
}

function toolCallsOf(row) {
  let calls = row.tool_calls;
  if (typeof calls === 'string') {
    try {
      calls = JSON.parse(calls);
    } catch {
      return [];
    }
  }
  return Array.isArray(calls) ? calls : [];
}

function cleanResult(content) {
  const text = typeof content === 'string' ? content : JSON.stringify(content ?? '');
  return text.replace(/^Created At: [^\n]*\n(Completed At: [^\n]*\n)?\n?/, '').trim();
}

/**
 * @typedef {{ kind: 'user' | 'assistant' | 'tool_call' | 'tool_result' | 'summary' | 'notice', text: string, tool?: string }} Entry
 */

/**
 * Converts transcript rows into review entries.
 * @returns {{ entries: Entry[], userMessages: string[], firstUserHasSettings: boolean }}
 */
export function rowsToEntries(rows) {
  const entries = [];
  const userMessages = [];
  const pendingCalls = [];
  let firstUserHasSettings = null;
  for (const row of rows) {
    const type = row.type;
    if (type === 'USER_INPUT') {
      if (firstUserHasSettings === null) firstUserHasSettings = hasSettingsSnapshot(row.content);
      const text = extractUserRequest(row.content);
      if (text) {
        entries.push({ kind: 'user', text });
        userMessages.push(text);
      }
      continue;
    }
    if (type === 'PLANNER_RESPONSE') {
      if (typeof row.content === 'string' && row.content.trim()) entries.push({ kind: 'assistant', text: row.content.trim() });
      for (const call of toolCallsOf(row)) {
        const name = String(call?.name ?? 'unknown');
        pendingCalls.push(name);
        entries.push({ kind: 'tool_call', tool: name, text: JSON.stringify(decodeArgs(call?.args ?? {})) });
      }
      continue;
    }
    if (type === 'CHECKPOINT') {
      if (row.content) entries.push({ kind: 'summary', text: cleanResult(row.content) });
      continue;
    }
    if (type === 'SYSTEM_MESSAGE') {
      if (row.content) entries.push({ kind: 'notice', text: cleanResult(row.content) });
      continue;
    }
    if (row.source === 'MODEL' && type !== 'PLANNER_RESPONSE') {
      const tool = pendingCalls.shift() ?? String(type ?? 'tool').toLowerCase();
      const body = cleanResult(row.content ?? row.error ?? '');
      const text = row.status === 'ERROR' ? `ERROR: ${body}` : body;
      entries.push({ kind: 'tool_result', tool, text });
    }
    // DIRECTORY_RULES, CONVERSATION_HISTORY, ERROR_MESSAGE and similar scaffolding are skipped.
  }
  return { entries, userMessages, firstUserHasSettings: firstUserHasSettings ?? false };
}

/** Drops the trailing call that is the action under review (it is shown separately). */
export function dropPendingCall(entries, toolName) {
  for (let i = entries.length - 1; i >= 0; i--) {
    const entry = entries[i];
    if (entry.kind === 'tool_result' || entry.kind === 'user') break;
    if (entry.kind === 'tool_call' && entry.tool === toolName) {
      return [...entries.slice(0, i), ...entries.slice(i + 1)];
    }
  }
  return entries;
}

function roleOf(entry, { delegated }) {
  switch (entry.kind) {
    case 'user':
      return delegated ? 'delegating agent' : 'user';
    case 'assistant':
      return 'assistant';
    case 'tool_call':
      return `tool ${entry.tool} call`;
    case 'tool_result':
      return `tool ${entry.tool} result`;
    case 'summary':
      return 'context summary';
    default:
      return 'system notice';
  }
}

const isToolKind = (entry) => entry.kind === 'tool_call' || entry.kind === 'tool_result' || entry.kind === 'notice';

/**
 * Renders entries with Codex's budgets and selection.
 * @param {Entry[]} entries
 * @param {{ delegated?: boolean }} [options]
 * @returns {{ lines: string[], omitted: boolean }}
 */
export function renderTranscript(entries, { delegated = false } = {}) {
  if (entries.length === 0) return { lines: ['<no retained transcript entries>'], omitted: false };
  const rendered = entries.map((entry, index) => {
    const cap = isToolKind(entry) ? BUDGETS.toolEntryTokens : BUDGETS.messageEntryTokens;
    // JSON-encoding keeps each entry on one line, so content cannot forge
    // another entry's role label or the prompt's section markers.
    const text = `[${index + 1}] ${roleOf(entry, { delegated })}: ${JSON.stringify(capTokens(entry.text, cap))}`;
    return { text, tokens: approxTokens(text) };
  });
  const included = new Array(entries.length).fill(false);

  // User messages: first message first, then newest to oldest while they fit.
  const users = entries.map((e, i) => (e.kind === 'user' ? i : -1)).filter((i) => i >= 0);
  let messageTokens = 0;
  if (users.length > 0) {
    included[users[0]] = true;
    messageTokens = rendered[users[0]].tokens;
    for (const i of users.slice(1).reverse()) {
      if (messageTokens + rendered[i].tokens <= BUDGETS.messageTranscriptTokens) {
        included[i] = true;
        messageTokens += rendered[i].tokens;
      }
    }
  }
  // Recent non-user entries, newest first.
  let toolTokens = 0;
  let kept = 0;
  for (let i = entries.length - 1; i >= 0 && kept < BUDGETS.recentNonUserEntries; i--) {
    if (entries[i].kind === 'user') continue;
    const tokens = rendered[i].tokens;
    if (isToolKind(entries[i])) {
      if (toolTokens + tokens > BUDGETS.toolTranscriptTokens) continue;
      toolTokens += tokens;
    } else {
      if (messageTokens + tokens > BUDGETS.messageTranscriptTokens) continue;
      messageTokens += tokens;
    }
    included[i] = true;
    kept++;
  }
  const lines = rendered.filter((_, i) => included[i]).map((r) => r.text);
  return { lines, omitted: included.some((v) => !v) };
}

/** Renders the root user's messages (the trusted authorization for a subagent). */
export function renderRootAuthorization(messages) {
  const lines = [];
  let total = 0;
  const indexed = messages.map((text, i) => ({ text, i }));
  const order = indexed.length > 1 ? [indexed[0], ...indexed.slice(1).reverse()] : indexed;
  const chosen = [];
  for (const m of order) {
    const line = `[root ${m.i + 1}] user: ${JSON.stringify(capTokens(m.text, BUDGETS.rootMessageTokens))}`;
    const tokens = approxTokens(line);
    if (chosen.length > 0 && total + tokens > BUDGETS.rootAuthorizationTokens) continue;
    chosen.push({ i: m.i, line });
    total += tokens;
  }
  chosen.sort((a, b) => a.i - b.i);
  for (const c of chosen) lines.push(c.line);
  return lines;
}

// ---------------------------------------------------------------------------
// Subagent → root conversation

const SUBAGENT_ID_RE = (id) => new RegExp(`"conversationId"\\s*:\\s*"${id.replace(/[-]/g, '\\-')}"`);

/**
 * Looks for the conversation whose invoke_subagent result created `childId`.
 * @returns {string | null}
 */
export function findParentConversation(brainDir, childId, { maxFiles = 40, maxAgeMs = 3 * 24 * 3600 * 1000 } = {}) {
  let dirs;
  try {
    dirs = fs.readdirSync(brainDir, { withFileTypes: true }).filter((d) => d.isDirectory() && d.name !== childId);
  } catch {
    return null;
  }
  const now = Date.now();
  const candidates = [];
  for (const d of dirs) {
    const file = path.join(brainDir, d.name, '.system_generated', 'logs', 'transcript_full.jsonl');
    try {
      const { mtimeMs } = fs.statSync(file);
      if (now - mtimeMs <= maxAgeMs) candidates.push({ id: d.name, file, mtimeMs });
    } catch {
      // no transcript
    }
  }
  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const re = SUBAGENT_ID_RE(childId);
  for (const c of candidates.slice(0, maxFiles)) {
    let text;
    try {
      text = fs.readFileSync(c.file, 'utf8');
    } catch {
      continue;
    }
    if (!text.includes(childId)) continue;
    for (const line of text.split('\n')) {
      if (!line.includes(childId)) continue;
      try {
        const row = JSON.parse(line);
        if (row.type === 'INVOKE_SUBAGENT' && typeof row.content === 'string' && re.test(row.content)) return c.id;
      } catch {
        // skip
      }
    }
  }
  return null;
}

/**
 * Returns the root conversation id for a (possibly nested) subagent, or null
 * when `conversationId` has no known parent.
 */
export function findRootConversation(brainDir, conversationId, maxDepth = 4) {
  let current = conversationId;
  let root = null;
  for (let i = 0; i < maxDepth; i++) {
    const parent = findParentConversation(brainDir, current);
    if (!parent) break;
    root = parent;
    current = parent;
  }
  return root;
}

export function transcriptPathFor(brainDir, conversationId) {
  return path.join(brainDir, conversationId, '.system_generated', 'logs', 'transcript_full.jsonl');
}
