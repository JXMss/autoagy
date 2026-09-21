// Reading the MCP servers' own tool annotations, so a read-only tool need not be
// reviewed — Codex's rule (`requires_mcp_tool_approval`): `destructive_hint`
// means approval, `read_only_hint` means none, anything else means approval.
//
// Two things make this a separate module rather than a branch in the policy.
//
// The annotations only exist on the server. The hook payload carries a tool name
// and arguments and nothing else, so the only way to learn that `github/get_issue`
// is read-only is to ask the server that offers it — which means starting it and
// speaking MCP at it. That cannot happen inside a PreToolUse budget, so it is a
// command the *user* runs (`autoagy mcp-scan`), writing a cache the hook reads.
//
// And it is a trust decision, not a lookup. The annotation is written by whoever
// wrote the server: one that says "read only" is believed. Codex believes it
// implicitly at runtime; here the belief is opt-in (`mcp.annotations: "trust"`),
// the snapshot is taken at a moment the user chose, and it lands in
// `$AUTOAGY_HOME/state`, which the agent cannot write and the own sandbox mounts
// read-only. `mcp.allow` remains the version that trusts nobody but the user.
//
// The config format is agy's own, from the documentation it ships
// (`builtin/skills/agy-customizations/docs/mcp_servers.md`): a `mcpServers` map,
// `command`/`args`/`env` for stdio, `serverUrl` for SSE.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { reservedStateFile, writeJsonFile } from './state.mjs';

/** The protocol version autoagy asks for; the server's answer is recorded as it came. */
export const PROTOCOL_VERSION = '2025-06-18';
const DEFAULT_TIMEOUT_MS = 10_000;
// A server that keeps handing back cursors does not get to keep us here.
const MAX_PAGES = 20;
export const MCP_CACHE_FILE = 'mcp-tools.json';

/**
 * Where agy looks for MCP servers: the global file, and one per plugin.
 * @returns {string[]}
 */
export function mcpConfigFiles(home = os.homedir()) {
  const config = path.join(home, '.gemini', 'config');
  const files = [path.join(config, 'mcp_config.json')];
  let plugins = [];
  try {
    plugins = fs.readdirSync(path.join(config, 'plugins'));
  } catch {
    // no plugins directory
  }
  for (const plugin of plugins) files.push(path.join(config, 'plugins', plugin, 'mcp_config.json'));
  return files;
}

/**
 * The servers those files declare.
 *
 * Both spellings of the map are accepted because the binary holds both
 * (`mcpServers` and `mcp_servers`); a file that is just the map, with no wrapper,
 * is accepted too, since that shape costs nothing to allow and a config that
 * silently declares no servers is the failure this whole command exists to avoid.
 *
 * @returns {{ servers: object[], problems: string[] }}
 */
export function readMcpServers(home = os.homedir()) {
  const servers = [];
  const problems = [];
  const seen = new Set();
  for (const file of mcpConfigFiles(home)) {
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') problems.push(`${file}: ${err.message}`);
      continue;
    }
    if (text.trim() === '') continue;
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      problems.push(`${file}: not valid JSON (${err.message})`);
      continue;
    }
    const map = parsed?.mcpServers ?? parsed?.mcp_servers ?? parsed;
    if (!map || typeof map !== 'object' || Array.isArray(map)) {
      problems.push(`${file}: no "mcpServers" map`);
      continue;
    }
    for (const [id, raw] of Object.entries(map)) {
      if (!raw || typeof raw !== 'object') continue;
      // The first file wins, the way a PATH lookup does: the global file is read
      // first, so a plugin cannot quietly replace a server the user declared.
      if (seen.has(id)) {
        problems.push(`${file}: server "${id}" is already declared elsewhere; ignoring this one`);
        continue;
      }
      seen.add(id);
      const url = typeof raw.serverUrl === 'string' ? raw.serverUrl : null;
      servers.push({
        id,
        source: file,
        transport: url ? 'sse' : 'stdio',
        serverUrl: url,
        command: typeof raw.command === 'string' ? raw.command : null,
        args: Array.isArray(raw.args) ? raw.args.filter((a) => typeof a === 'string') : [],
        env: raw.env && typeof raw.env === 'object' ? raw.env : {},
      });
    }
  }
  return { servers, problems };
}

/** The annotations autoagy keeps, from a `tools/list` entry. */
function annotationsOf(tool) {
  const a = tool?.annotations ?? {};
  const pick = (camel, snake) => {
    const value = a[camel] ?? a[snake] ?? tool?.[camel] ?? tool?.[snake];
    return value === true ? true : value === false ? false : null;
  };
  return {
    readOnly: pick('readOnlyHint', 'read_only_hint'),
    destructive: pick('destructiveHint', 'destructive_hint'),
    title: typeof a.title === 'string' ? a.title : typeof tool?.title === 'string' ? tool.title : null,
  };
}

/**
 * Starts one stdio server and asks it for its tools.
 *
 * MCP's stdio transport is one JSON-RPC message per line, so this is a line
 * reader and three messages: `initialize`, the `notifications/initialized` that
 * the spec requires before anything else, and `tools/list` (following
 * `nextCursor`, bounded). Nothing here writes to the server beyond that, and the
 * child is killed on the way out whatever happened.
 *
 * @returns {Promise<{ tools: object, protocolVersion: string|null, error: string|null }>}
 */
export function fetchServerTools(server, { timeoutMs = DEFAULT_TIMEOUT_MS, env = process.env } = {}) {
  if (server.transport !== 'stdio') {
    return Promise.resolve({ tools: {}, protocolVersion: null, error: `${server.transport} transport is not scanned (autoagy speaks the stdio transport only)` });
  }
  if (!server.command) return Promise.resolve({ tools: {}, protocolVersion: null, error: 'no "command" in its configuration' });
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(server.command, server.args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: { ...env, ...server.env },
        windowsHide: true,
      });
    } catch (err) {
      resolve({ tools: {}, protocolVersion: null, error: `could not start it: ${err.message}` });
      return;
    }
    const tools = {};
    let protocolVersion = null;
    let settled = false;
    let stdout = '';
    let stderr = '';
    let nextId = 1;
    let listId = null;
    let pages = 0;
    // Declared before the handlers that compare against it: a `const` below them
    // is in its temporal dead zone until `send` runs, which only works because the
    // event loop has to turn first. That is a fact about timing, not about the
    // code, so it does not get to hold the file together.
    const initId = nextId++;

    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill('SIGKILL');
      } catch {
        // already gone
      }
      resolve({ tools, protocolVersion, error: error ?? null });
    };
    const timer = setTimeout(() => finish(`no answer within ${Math.round(timeoutMs / 1000)}s${stderr.trim() ? ` (stderr: ${stderr.trim().slice(0, 200)})` : ''}`), timeoutMs);
    const send = (message) => {
      try {
        child.stdin.write(`${JSON.stringify(message)}\n`);
      } catch (err) {
        finish(`could not write to it: ${err.message}`);
      }
    };
    const list = (cursor) => {
      listId = nextId++;
      pages++;
      send({ jsonrpc: '2.0', id: listId, method: 'tools/list', params: cursor ? { cursor } : {} });
    };

    child.on('error', (err) => finish(`could not start it: ${err.message}`));
    child.on('exit', (code, signal) => {
      if (settled) return;
      finish(`it exited (${signal ? `signal ${signal}` : `code ${code}`})${stderr.trim() ? `: ${stderr.trim().slice(0, 200)}` : ''}`);
    });
    child.stderr.on('data', (chunk) => {
      stderr = `${stderr}${chunk}`.slice(-4000);
    });
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      let cut;
      while ((cut = stdout.indexOf('\n')) >= 0) {
        const line = stdout.slice(0, cut).trim();
        stdout = stdout.slice(cut + 1);
        if (line === '') continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          continue; // servers do print things that are not messages
        }
        if (message.id === initId) {
          if (message.error) {
            finish(`initialize failed: ${JSON.stringify(message.error).slice(0, 200)}`);
            return;
          }
          protocolVersion = typeof message.result?.protocolVersion === 'string' ? message.result.protocolVersion : null;
          send({ jsonrpc: '2.0', method: 'notifications/initialized' });
          list(null);
          continue;
        }
        if (listId !== null && message.id === listId) {
          if (message.error) {
            finish(`tools/list failed: ${JSON.stringify(message.error).slice(0, 200)}`);
            return;
          }
          for (const tool of message.result?.tools ?? []) {
            if (typeof tool?.name === 'string' && tool.name !== '') tools[tool.name] = annotationsOf(tool);
          }
          const cursor = message.result?.nextCursor;
          if (typeof cursor === 'string' && cursor !== '' && pages < MAX_PAGES) list(cursor);
          else finish(null);
          return;
        }
      }
    });

    send({
      jsonrpc: '2.0',
      id: initId,
      method: 'initialize',
      params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'autoagy', version: '0.1.0' } },
    });
  });
}

/**
 * Asks every configured server what it offers, and writes the cache the hook
 * reads. Returns the same record, so the caller can report it.
 */
export async function scanMcpServers({ autoagyHome, home = os.homedir(), timeoutMs = DEFAULT_TIMEOUT_MS, env = process.env } = {}) {
  const { servers, problems } = readMcpServers(home);
  const record = { at: new Date().toISOString(), protocolVersion: PROTOCOL_VERSION, problems, servers: {} };
  for (const server of servers) {
    const { tools, protocolVersion, error } = await fetchServerTools(server, { timeoutMs, env });
    record.servers[server.id] = {
      source: server.source,
      transport: server.transport,
      protocolVersion,
      error,
      tools,
    };
  }
  if (autoagyHome) writeJsonFile(reservedStateFile(autoagyHome, MCP_CACHE_FILE), record);
  return record;
}

/** The cache `autoagy mcp-scan` wrote, or null. */
export function readMcpCache(autoagyHome) {
  try {
    const record = JSON.parse(fs.readFileSync(reservedStateFile(autoagyHome, MCP_CACHE_FILE), 'utf8'));
    return record && typeof record.servers === 'object' ? record : null;
  } catch {
    return null;
  }
}

/**
 * What the cache says about one call: `'read-only'`, `'destructive'` or
 * `'unknown'`.
 *
 * `destructive` wins over `read-only` if a server claims both, which is the only
 * safe way to read a contradiction.
 *
 * The name is the hard part, and deliberately conservative. With a server name in
 * hand it is an exact lookup. Without one — the `mcp_<rest>` tool shape, where
 * agy has already flattened the name and its own documentation says tools "are
 * automatically prefixed or namespaced if necessary" — the tool is looked for by
 * name across every server, and by splitting `<rest>` at each `_` into a
 * server/tool pair. If that turns up entries that disagree, the answer is
 * `unknown`: an ambiguous name must not inherit the more permissive verdict.
 */
export function annotationVerdict(cache, { server, tool, toolName }) {
  const entries = [];
  const at = (s, t) => cache?.servers?.[s]?.tools?.[t] ?? null;
  if (server) {
    const exact = at(server, tool);
    if (exact) entries.push(exact);
  } else {
    for (const [id, entry] of Object.entries(cache?.servers ?? {})) {
      if (entry?.tools?.[tool]) entries.push(entry.tools[tool]);
      // `mcp_<server>_<tool>`: try every split, since `_` occurs in both halves.
      const rest = typeof toolName === 'string' && toolName.startsWith('mcp_') ? toolName.slice('mcp_'.length) : null;
      if (!rest) continue;
      if (rest.startsWith(`${id}_`)) {
        const candidate = entry?.tools?.[rest.slice(id.length + 1)];
        if (candidate) entries.push(candidate);
      }
    }
  }
  if (entries.length === 0) return 'unknown';
  if (entries.some((e) => e.destructive === true)) return 'destructive';
  if (entries.every((e) => e.readOnly === true)) return 'read-only';
  return 'unknown';
}
