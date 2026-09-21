// The MCP annotation scan, against real servers: fake ones, but spoken to over a
// real pipe with the real protocol, because the point of the module is that it
// talks to something it did not write.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { readMcpServers, mcpConfigFiles, fetchServerTools, scanMcpServers, readMcpCache, annotationVerdict, MCP_CACHE_FILE } from '../plugin/lib/mcp.mjs';
import { reservedStateFile } from '../plugin/lib/state.mjs';
import { classify } from '../plugin/lib/policy.mjs';
import { makeSandboxDirs, contextFor, configWith } from './helpers.mjs';

const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

/**
 * A stdio MCP server, in as many lines as the protocol needs: one JSON-RPC
 * message per line, `initialize`, then `tools/list`. `behaviour` picks what it
 * does wrong, so the failure paths are exercised against a real child process
 * rather than a stub.
 */
function fakeServer(name, behaviour = 'ok') {
  const file = path.join(dirs.root, `${name}.mjs`);
  fs.writeFileSync(
    file,
    `
const behaviour = ${JSON.stringify(behaviour)};
if (behaviour === 'exit') process.exit(3);
if (behaviour === 'noisy') process.stdout.write('starting up, one moment\\n');
if (behaviour === 'stderr-only') { process.stderr.write('cannot find my database\\n'); }
const send = (m) => process.stdout.write(JSON.stringify(m) + '\\n');
const page1 = [
  { name: 'get_issue', annotations: { readOnlyHint: true, title: 'Get an issue' } },
  { name: 'delete_repo', annotations: { destructiveHint: true } },
];
const page2 = [
  { name: 'open_pr', annotations: { readOnlyHint: false } },
  { name: 'unannotated' },
  { name: 'both_hints', annotations: { readOnlyHint: true, destructiveHint: true } },
];
let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let cut;
  while ((cut = buffer.indexOf('\\n')) >= 0) {
    const line = buffer.slice(0, cut).trim();
    buffer = buffer.slice(cut + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    if (message.method === 'initialize') {
      if (behaviour === 'hang') continue;
      if (behaviour === 'init-error') { send({ jsonrpc: '2.0', id: message.id, error: { code: -32000, message: 'no' } }); continue; }
      send({ jsonrpc: '2.0', id: message.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: ${JSON.stringify(name)}, version: '1' } } });
      continue;
    }
    if (message.method === 'tools/list') {
      if (behaviour === 'list-error') { send({ jsonrpc: '2.0', id: message.id, error: { code: -32601, message: 'no tools here' } }); continue; }
      if (message.params?.cursor === 'page2') { send({ jsonrpc: '2.0', id: message.id, result: { tools: page2 } }); continue; }
      send({ jsonrpc: '2.0', id: message.id, result: { tools: page1, nextCursor: 'page2' } });
      continue;
    }
  }
});
`,
  );
  return { id: name, source: 'test', transport: 'stdio', command: process.execPath, args: [file], env: {} };
}

function writeMcpConfig(map) {
  const file = path.join(dirs.home, '.gemini', 'config', 'mcp_config.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ mcpServers: map }));
  return file;
}

test('the configuration is read the way agy documents it', () => {
  const file = writeMcpConfig({
    local: { command: 'node', args: ['server.mjs'], env: { TOKEN: 'x' } },
    remote: { serverUrl: 'https://mcp.example.com/sse' },
    broken: 'not an object',
  });
  assert.ok(mcpConfigFiles(dirs.home).includes(file));
  const { servers, problems } = readMcpServers(dirs.home);
  assert.deepEqual(
    servers.map((s) => [s.id, s.transport, s.command, s.args, s.env]),
    [
      ['local', 'stdio', 'node', ['server.mjs'], { TOKEN: 'x' }],
      ['remote', 'sse', null, [], {}],
    ],
    'both transports are recognised, and a non-object entry is skipped',
  );
  assert.deepEqual(problems, []);

  // `mcp_servers` is the other spelling in the binary, and a bare map is accepted.
  fs.writeFileSync(path.join(dirs.home, '.gemini', 'config', 'mcp_config.json'), JSON.stringify({ mcp_servers: { a: { command: 'x' } } }));
  assert.deepEqual(readMcpServers(dirs.home).servers.map((s) => s.id), ['a']);
  fs.writeFileSync(path.join(dirs.home, '.gemini', 'config', 'mcp_config.json'), JSON.stringify({ b: { command: 'x' } }));
  assert.deepEqual(readMcpServers(dirs.home).servers.map((s) => s.id), ['b']);

  // A file that cannot be read is said out loud rather than read as "no servers",
  // which is the same mistake the state files made.
  fs.writeFileSync(path.join(dirs.home, '.gemini', 'config', 'mcp_config.json'), '{oops');
  const bad = readMcpServers(dirs.home);
  assert.deepEqual(bad.servers, []);
  assert.match(bad.problems[0], /not valid JSON/);
});

test('a real server is asked over a real pipe, across pages', async () => {
  const { tools, protocolVersion, error } = await fetchServerTools(fakeServer('github', 'ok'), { timeoutMs: 15_000 });
  assert.equal(error, null);
  assert.equal(protocolVersion, '2025-06-18');
  assert.deepEqual(Object.keys(tools).sort(), ['both_hints', 'delete_repo', 'get_issue', 'open_pr', 'unannotated'], 'nextCursor is followed');
  assert.deepEqual(tools.get_issue, { readOnly: true, destructive: null, title: 'Get an issue' });
  assert.deepEqual(tools.delete_repo, { readOnly: null, destructive: true, title: null });
  assert.deepEqual(tools.open_pr, { readOnly: false, destructive: null, title: null });
  assert.deepEqual(tools.unannotated, { readOnly: null, destructive: null, title: null });

  // Output that is not a message does not derail the reader: servers do print.
  const noisy = await fetchServerTools(fakeServer('noisy', 'noisy'), { timeoutMs: 15_000 });
  assert.equal(noisy.error, null);
  assert.ok(noisy.tools.get_issue);
});

test('a server that cannot answer is reported, not guessed at', async () => {
  const exited = await fetchServerTools(fakeServer('gone', 'exit'), { timeoutMs: 15_000 });
  assert.match(exited.error, /exited \(code 3\)/);
  assert.deepEqual(exited.tools, {});

  const hung = await fetchServerTools(fakeServer('hung', 'hang'), { timeoutMs: 1200 });
  assert.match(hung.error, /no answer within/);

  const refused = await fetchServerTools(fakeServer('refused', 'init-error'), { timeoutMs: 15_000 });
  assert.match(refused.error, /initialize failed/);

  const noTools = await fetchServerTools(fakeServer('notools', 'list-error'), { timeoutMs: 15_000 });
  assert.match(noTools.error, /tools\/list failed/);

  const missing = await fetchServerTools({ id: 'x', transport: 'stdio', command: path.join(dirs.root, 'no-such-program'), args: [] }, { timeoutMs: 15_000 });
  assert.match(missing.error, /could not start it/);

  // The SSE transport is named as unscanned rather than silently producing an
  // empty tool list, which would read as "this server has no tools".
  const sse = await fetchServerTools({ id: 'r', transport: 'sse', serverUrl: 'https://example.com/sse' });
  assert.match(sse.error, /stdio transport only/);
});

test('the scan writes one record, and the policy reads it only when told to', async () => {
  const server = fakeServer('github', 'ok');
  writeMcpConfig({ github: { command: server.command, args: server.args } });
  const record = await scanMcpServers({ autoagyHome: dirs.env.AUTOAGY_HOME, home: dirs.home, timeoutMs: 15_000 });
  assert.equal(record.servers.github.error, null);
  assert.equal(readMcpCache(dirs.env.AUTOAGY_HOME).servers.github.tools.get_issue.readOnly, true);
  // It goes in the state directory under its registered name, so the readers that
  // scan that directory do not take it for a conversation.
  assert.ok(fs.existsSync(reservedStateFile(dirs.env.AUTOAGY_HOME, MCP_CACHE_FILE)));

  const verdict = (tool, config) =>
    classify(contextFor(dirs, 'call_mcp_tool', { ServerName: 'github', ToolName: tool }, { config: configWith(config) }));
  // Default: the scan changes nothing. Believing a server's claim is opt-in.
  assert.equal(verdict('get_issue', {}).category, 'mcp');
  assert.equal(verdict('get_issue', { mcp: { allow: [], annotations: 'ignore' } }).verdict, 'review');

  const trust = { mcp: { allow: [], annotations: 'trust' } };
  assert.equal(verdict('get_issue', trust).verdict, 'allow');
  assert.equal(verdict('get_issue', trust).category, 'mcp-read-only');
  assert.equal(verdict('delete_repo', trust).verdict, 'review');
  assert.match(verdict('delete_repo', trust).reason, /annotates as destructive/);
  assert.equal(verdict('unannotated', trust).verdict, 'review');
  assert.match(verdict('unannotated', trust).reason, /No annotation for it was found/);
  assert.equal(verdict('open_pr', trust).verdict, 'review', 'readOnlyHint: false is not an allow');
  assert.equal(verdict('both_hints', trust).verdict, 'review', 'destructive wins over read-only');
  assert.equal(verdict('never_scanned', trust).verdict, 'review');

  // The user's own list still wins, and needs no server's cooperation.
  assert.equal(verdict('delete_repo', { mcp: { allow: ['github/delete_repo'], annotations: 'trust' } }).category, 'mcp-allowed');
});

test('an ambiguous tool name does not inherit the more permissive answer', () => {
  const cache = {
    servers: {
      docs: { tools: { search: { readOnly: true, destructive: null } } },
      wiki: { tools: { search: { readOnly: null, destructive: null } } },
      github: { tools: { get_issue: { readOnly: true, destructive: null } } },
    },
  };
  // With a server named, it is an exact lookup.
  assert.equal(annotationVerdict(cache, { server: 'docs', tool: 'search' }), 'read-only');
  assert.equal(annotationVerdict(cache, { server: 'wiki', tool: 'search' }), 'unknown');
  assert.equal(annotationVerdict(cache, { server: 'docs', tool: 'missing' }), 'unknown');

  // Without one — the flattened `mcp_*` tool shape — two servers offering the same
  // name and disagreeing is reviewed, not allowed.
  assert.equal(annotationVerdict(cache, { server: '', tool: 'search', toolName: 'mcp_search' }), 'unknown');
  assert.equal(annotationVerdict(cache, { server: '', tool: 'get_issue', toolName: 'mcp_get_issue' }), 'read-only');
  // `mcp_<server>_<tool>`, where `_` is in both halves.
  assert.equal(annotationVerdict(cache, { server: '', tool: 'github_get_issue', toolName: 'mcp_github_get_issue' }), 'read-only');
  assert.equal(annotationVerdict(null, { server: 'docs', tool: 'search' }), 'unknown', 'no scan means no answer');
});
