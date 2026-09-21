// Layer 1: the deterministic policy. It decides, without a model, which tool
// calls run immediately, which must be reviewed, and which are refused.
//
// It mirrors what Codex's "Approve for me" mode lets through without asking:
// reads anywhere, edits inside the writable roots (minus protected metadata
// such as .git/.agents), and commands confined by the sandbox unless they are
// destructive. Everything Codex would have turned into an approval prompt —
// sandbox escalations, edits elsewhere, network access, MCP tools — goes to the
// reviewer instead of the user.

import fs from 'node:fs';
import path from 'node:path';
import { analyzeCommandLine, findDangerousCommand, isKnownSafeCommandLine, printsEnvironment, printedVariableNames, executableName, gitSubcommand } from './command-safety.mjs';
import { evaluateRules, describeRule } from './exec-rules.mjs';
import { HOST_INSPECTABLE_PLATFORMS } from './context.mjs';
import { envNameAllowed } from './confine.mjs';
import { annotationVerdict } from './mcp.mjs';
import { toAbsolute, resolveReal, isWithin, matchesAnyGlob, globToRegExp, findExecutable } from './paths.mjs';

export const READ_ONLY_TOOLS = new Set([
  'view_file',
  'view_content_chunk',
  'view_file_outline',
  'view_code_item',
  'read_file',
  'list_dir',
  'find_by_name',
  'grep_search',
  'codebase_search',
  'read_terminal',
  'command_status',
  'trajectory_search',
  'search_web',
  'list_permissions',
  // Observing the browser does not change anything.
  'read_browser_page',
  'capture_browser_screenshot',
  'capture_browser_console_logs',
  'list_browser_pages',
  'browser_get_dom',
  'browser_list_network_requests',
  'browser_get_network_request',
  'browser_scroll',
  'browser_scroll_dom',
  'browser_scroll_up',
  'browser_scroll_down',
  'browser_resize_window',
  'browser_refresh_page',
]);

// Tools that return file contents to the model (credential reads are reviewed).
// Also the reads an untrusted conversation loses, since a read follows symlinks.
export const CONTENT_READ_TOOLS = new Set(['view_file', 'view_content_chunk', 'view_file_outline', 'view_code_item', 'read_file', 'grep_search']);

// Coordination tools with no side effects outside the agent runtime
// (invoke_subagent is classified on its own, see classifySubagents; the tools
// that do act outside the runtime — the browser subagent, image generation,
// knowledge deletion — are classified on their own, see classifyOutsideRuntime;
// and so are the two that ask for a permission, see classifyPermissionAsk).
export const AGENT_TOOLS = new Set([
  'manage_subagents',
  'manage_task',
  'manage_inbox',
  'schedule',
  'send_message',
  'wait',
  'wait_5_seconds',
  'finish',
  'notify_user',
  'task_boundary',
  'suggested_responses',
  'ask_question',
]);

// Tools that ask for a permission rather than doing anything themselves. They
// are not in the list above because the answer decides whether they do
// anything: see classifyPermissionAsk.
export const PERMISSION_ASK_TOOLS = new Set(['ask_permission', 'ask_custom_permission']);

// Tools that stay allowed when autoagy itself fails or its hook times out.
// Deliberately a separate literal set rather than a reference to AGENT_TOOLS:
// adding a tool to the coordination list must not silently widen the path that
// runs with no supervision at all. The permission asks are not here either —
// on that path nothing can judge what they are asking for, and the request is
// one the agent makes of itself.
export const FAIL_OPEN_TOOLS = new Set([
  'manage_subagents',
  'manage_task',
  'manage_inbox',
  'schedule',
  'send_message',
  'wait',
  'wait_5_seconds',
  'finish',
  'notify_user',
  'task_boundary',
  'suggested_responses',
  'ask_question',
]);

// Agent tools that do have effects outside the agent runtime, so they are not
// covered by the coordination allow above.
export const OUTSIDE_RUNTIME_TOOLS = new Set(['browser_subagent', 'generate_image', 'delete_knowledge']);

export const FILE_EDIT_TOOLS = new Set([
  'write_to_file',
  'replace_file_content',
  'multi_replace_file_content',
  'sed_file',
  'notebook_edit',
  'edit_file',
  'create_file',
  'delete_file',
]);

export const URL_TOOLS = new Set(['read_url_content', 'open_browser_url']);

// MCP resource reads. Not read-only in the sense the set above means: the URI
// is chosen by the agent, and reading one can reach a remote server or a file
// that no other rule here sees — a `file://` URI never passes through the
// credential check, which reads path arguments, not URIs. So they are reviewed
// like every other MCP call, with `mcp.allow` able to name them.
export const MCP_RESOURCE_TOOLS = new Set(['read_resource', 'list_resources']);

export const BROWSER_ACTION_TOOLS = new Set([
  'browser_click_element',
  'click_browser_pixel',
  'browser_input',
  'browser_press_key',
  'browser_select_option',
  'browser_drag_pixel_to_pixel',
  'browser_mouse_down',
  'browser_mouse_up',
  'browser_move_mouse',
  'browser_mouse_wheel',
  'execute_browser_javascript',
]);

/**
 * Every tool name `classify` has a rule for, so `autoagy status` can say when a
 * `tools.allow` entry names one of them and therefore does nothing.
 *
 * Built from the sets above rather than written out again — a name added to one
 * of them must not quietly become "unknown" here. The `mcp_` prefix is not a
 * name and is handled by its own branch, so a caller checking a pattern has to
 * ask about that separately.
 */
export const KNOWN_TOOL_NAMES = new Set([
  ...READ_ONLY_TOOLS,
  ...CONTENT_READ_TOOLS,
  ...AGENT_TOOLS,
  ...PERMISSION_ASK_TOOLS,
  ...OUTSIDE_RUNTIME_TOOLS,
  ...FILE_EDIT_TOOLS,
  ...URL_TOOLS,
  ...MCP_RESOURCE_TOOLS,
  ...BROWSER_ACTION_TOOLS,
  'run_command',
  'send_command_input',
  'invoke_subagent',
  'call_mcp_tool',
  'notebook_execution',
  'define_subagent',
]);

const PATH_ARG_RE = /^(TargetFile|TargetFiles|File|FilePath|Path|AbsolutePath|NotebookPath|TargetPath|DestinationPath|DestinationFile|SourceFile|Files)$/i;

/**
 * @typedef {'allow' | 'review' | 'deny'} Verdict
 * @typedef {{ verdict: Verdict, category: string, reason: string }} Classification
 */

const allow = (category, reason = '') => ({ verdict: 'allow', category, reason });
const review = (category, reason) => ({ verdict: 'review', category, reason });
const deny = (category, reason) => ({ verdict: 'deny', category, reason });

/**
 * Classifies one tool call.
 * @param {import('./context.mjs').HookContext} ctx
 * @param {{ escalatedCommandApproved?: boolean }} [state]
 * @returns {Classification}
 */
export function classify(ctx, state = {}) {
  const name = ctx.toolName;
  if (ctx.role === 'guardian') return classifyGuardianTool(ctx);
  // A search is egress: the query is the agent's own text and agy makes the
  // request, so nothing here — not even autoagy's own sandbox — sits between it
  // and the search engine. Codex does not put its hosted web search through the
  // approval flow either; it gates it by configuration, which is what this
  // switch is. The default follows Codex and allows it.
  if (name === 'search_web' && ctx.config.webSearch === 'review') {
    return review('network', 'Sends the agent\'s query, which is agent-written text, to a search engine. No sandbox here covers that request.');
  }
  if (READ_ONLY_TOOLS.has(name)) return classifyRead(ctx, state);
  if (name === 'invoke_subagent') return classifySubagents(ctx);
  if (PERMISSION_ASK_TOOLS.has(name)) return classifyPermissionAsk(ctx);
  if (AGENT_TOOLS.has(name)) return allow('agent-coordination');
  if (OUTSIDE_RUNTIME_TOOLS.has(name)) return classifyOutsideRuntime(ctx);
  if (FILE_EDIT_TOOLS.has(name)) return classifyFileEdit(ctx, state);
  if (name === 'run_command') return classifyCommand(ctx, state);
  if (name === 'send_command_input') {
    // Only autoagy's own sandbox is evidence that the terminal the keystrokes
    // reach is confined: config.sandbox "on" is a declaration, and Antigravity's
    // sandbox leaves .git and the conversation log writable.
    if (ctx.ownSandbox.active && !state.escalatedCommandApproved && !state.untrusted) {
      return allow('terminal-input', 'input to a terminal inside autoagy\'s own sandbox');
    }
    return review('terminal-input', 'Input to a running terminal that is not confined by autoagy\'s own sandbox.');
  }
  if (URL_TOOLS.has(name)) return classifyUrl(ctx);
  if (BROWSER_ACTION_TOOLS.has(name)) {
    if (ctx.config.browser === 'allow') return allow('browser-action');
    return review('browser-action', 'Interactive browser action (click, typing or script execution) with possible external side effects.');
  }
  if (name === 'call_mcp_tool' || name.startsWith('mcp_') || MCP_RESOURCE_TOOLS.has(name)) return classifyMcp(ctx);
  if (name === 'notebook_execution') {
    if (ctx.config.notebooks === 'allow') return allow('notebook-execution');
    // Deliberately not "outside the terminal sandbox", which is what this said
    // before and what nobody established. What is known: agy holds no notebook
    // kernel of its own, and its one sandbox component lives under the command
    // subsystem, which neither the notebook tool nor its handler mentions. So the
    // reviewer is told that the confinement is unknown, rather than told a fact.
    return review(
      'code-execution',
      'Executes the notebook\'s code. Whether anything confines it is not established — agy carries no notebook kernel of its own, and its terminal sandbox belongs to the command subsystem, which the notebook tool does not go through — so treat it as code running with the agent\'s full access.',
    );
  }
  if (name === 'define_subagent') {
    return review(
      'agent-definition',
      'Defines a new subagent. A subagent that does not inherit customizations (or excludes default components) would run without these auto-review hooks.',
    );
  }
  // The one place `tools.allow` applies: a tool autoagy has no rule for. Every
  // branch above has already returned, so a listed name that autoagy does
  // classify cannot reach this and keeps its own rule — which is the intent, and
  // why `status` reports such an entry as having no effect instead of letting it
  // read like a way to switch off the command or edit rules.
  if ((ctx.config.tools?.allow ?? []).some((glob) => globToRegExp(String(glob)).test(name))) {
    return allow('tool-allowed', `Tool "${name}" is listed in tools.allow.`);
  }
  return review('unknown-tool', `Tool "${name || '(unnamed)'}" is not known to autoagy, so it is reviewed.`);
}

/**
 * The decision used when autoagy cannot classify a call itself: its own internal
 * error, or the hook watchdog firing before the decision was ready.
 *
 * Reads and the coordination tools stay usable — blocking them would wedge the
 * session for no gain. Everything else is refused, and a conversation whose
 * paths were already swapped also loses its content reads: after a swap a read
 * follows the symlink to wherever it now points.
 *
 * @param {{ toolCall?: { name?: string } }} payload
 * @param {{ untrusted?: boolean, reason: string, config?: object | null }} options
 */
export function failOpenOutput(payload, { untrusted = false, reason, config = null } = {}) {
  const name = payload?.toolCall?.name;
  if (FAIL_OPEN_TOOLS.has(name)) return { decision: 'allow' };
  // A search the operator asked to have reviewed stays reviewed on this path
  // too. This is the branch taken when autoagy cannot answer at all, and the
  // switch exists to keep agent-written queries from leaving the machine — an
  // operator who set it should not have it quietly stop applying exactly when
  // supervision is weakest.
  if (name === 'search_web' && config?.webSearch === 'review') return { decision: 'deny', reason };
  if (READ_ONLY_TOOLS.has(name) && !(untrusted && CONTENT_READ_TOOLS.has(name))) return { decision: 'allow' };
  return { decision: 'deny', reason };
}

/**
 * Custom agent definitions agy can start. agy 1.2.7 loads user-level agents
 * (~/.gemini/config/agents, ~/.gemini/agents) and plugin agents, but not
 * workspace ones; all of these live under ~/.gemini, which agents cannot
 * write without a review.
 */
export function customAgentDefinitions(home) {
  const dirs = [path.join(home, '.gemini', 'config', 'agents'), path.join(home, '.gemini', 'agents')];
  const plugins = path.join(home, '.gemini', 'config', 'plugins');
  try {
    for (const plugin of fs.readdirSync(plugins)) dirs.push(path.join(plugins, plugin, 'agents'));
  } catch {
    // no plugins
  }
  const defs = [];
  for (const dir of dirs) {
    let files = [];
    try {
      files = fs.readdirSync(dir).filter((f) => f.endsWith('.md'));
    } catch {
      continue;
    }
    for (const file of files) {
      let text = '';
      try {
        text = fs.readFileSync(path.join(dir, file), 'utf8');
      } catch {
        continue;
      }
      const front = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)?.[1] ?? '';
      const name = (/^name:\s*(.+?)\s*$/m.exec(front)?.[1] ?? file.slice(0, -'.md'.length)).replace(/^["']|["']$/g, '');
      defs.push({
        name,
        file: path.join(dir, file),
        // YAML spells false several ways; anything else counts as inheriting.
        inherits: !/^inheritCustomizations:\s*["']?(false|no|off)["']?\s*(#.*)?$/im.test(front),
        toolless: /^tools:\s*\[\s*\]\s*$/m.test(front),
      });
    }
  }
  return defs;
}

/**
 * A subagent that does not inherit customizations runs without these hooks, so
 * its tool calls would skip review (and the setup grants let them through
 * silently). Starting one that has tools is reviewed. The agent's name is
 * looked for anywhere in the arguments, so a change in their shape does not
 * turn this check off.
 */
function classifySubagents(ctx) {
  const args = JSON.stringify(ctx.args);
  for (const def of customAgentDefinitions(ctx.home)) {
    if (def.inherits || def.toolless || !args.includes(JSON.stringify(def.name))) continue;
    return review(
      'subagent-without-review',
      `Starts subagent "${def.name}" (${def.file}), which does not inherit customizations: its tool calls would run without autoagy's review.`,
    );
  }
  return allow('agent-coordination');
}

/**
 * The agent asking for a permission.
 *
 * `ask_permission` carries a command (agy refuses it for a dangerous one and
 * tells the agent to use `run_command` instead, which is how it shows up in the
 * binary's own strings), and `ask_custom_permission` carries a grant of the
 * shape `git.read({...})`. So the answer decides whether something happens, and
 * the answer is supposed to be the user's.
 *
 * It is only a question if someone can answer it. Under
 * `--dangerously-skip-permissions` agy accepts every tool permission by itself
 * — its own strings say `auto-approving all tool permissions` — and where the
 * agy arguments cannot be read, that flag cannot be ruled out. Then nothing
 * between the agent and the grant is human, and the request goes to the
 * reviewer, whose policy counts widening the agent's own oversight as a
 * persistent weakening of a sensitive boundary.
 *
 * These are the same two conditions `withoutUnanswerablePrompt` (hook.mjs) uses
 * for autoagy's own prompts — a change to either belongs in both.
 */
function classifyPermissionAsk(ctx) {
  const skip = ctx.host?.flags?.skipPermissions === true;
  const unknowable = !ctx.host && !HOST_INSPECTABLE_PLATFORMS.includes(process.platform);
  if (!skip && !unknowable) return allow('agent-coordination');
  const why = skip ? 'agy runs with --dangerously-skip-permissions' : `the agy arguments cannot be read on ${process.platform}`;
  return review('self-permission', `Asks for a permission nobody can answer (${why}), so Antigravity would grant it without a user.`);
}

/**
 * Agent tools that reach outside the agent runtime. The coordination allow does
 * not cover them: a browser subagent navigates, clicks and types on its own, so
 * none of that passes through this policy; image generation writes to a path the
 * policy never sees; deleting knowledge is not recoverable from the workspace.
 */
function classifyOutsideRuntime(ctx) {
  const name = ctx.toolName;
  if (name === 'browser_subagent') {
    if (ctx.config.browser === 'allow') return allow('browser-subagent');
    return review(
      'browser-subagent',
      'Starts a subagent that drives the browser itself. Its navigation and clicks are not classified one by one here, so the browser-action rules cannot see them.',
    );
  }
  if (name === 'delete_knowledge') {
    return review('destructive-knowledge', 'Deletes stored knowledge. Nothing in the workspace can restore it.');
  }
  return review('image-generation', 'Writes an image to a path this policy does not see, so it cannot check that it lands inside a writable root.');
}

function classifyGuardianTool(ctx) {
  const name = ctx.toolName;
  if (READ_ONLY_TOOLS.has(name) && !name.includes('browser')) return allow('guardian-read');
  if (name === 'run_command' && ctx.args.BypassSandbox !== true && ctx.sandbox.active && isKnownSafeCommandLine(String(ctx.args.CommandLine ?? ''))) {
    return allow('guardian-read');
  }
  return deny('guardian-read-only', 'autoagy: approval review sessions may only use read-only tools.');
}

function pathArgs(args) {
  const out = [];
  for (const [key, value] of Object.entries(args)) {
    if (!PATH_ARG_RE.test(key)) continue;
    if (typeof value === 'string') out.push(value);
    else if (Array.isArray(value)) out.push(...value.filter((v) => typeof v === 'string'));
  }
  return out;
}

function classifyRead(ctx, state = {}) {
  if (!CONTENT_READ_TOOLS.has(ctx.toolName)) return allow('read');
  // Reading follows symlinks, so in a conversation where part of a path was
  // already swapped, a read of a file that looks harmless can land anywhere.
  if (state.untrusted) {
    return review('untrusted-read', 'Reads are reviewed from here on: an earlier action in this conversation changed what a path resolves to, so this read may not land where it appears to.');
  }
  const candidates = [...pathArgs(ctx.args), ctx.args.SearchPath].filter((p) => typeof p === 'string');
  for (const raw of candidates) {
    const abs = toAbsolute(raw, ctx.baseDir, ctx.home);
    if (!abs) continue;
    // Judge a symlink by what it points to.
    for (const p of new Set([abs, resolveReal(abs)])) {
      if (isCredentialPath(ctx, p)) {
        return review('credential-read', `Reads a file that commonly holds credentials or secrets (${p}).`);
      }
      // A search reads every file below its directory.
      const inside = ctx.toolName === 'grep_search' ? ctx.credentialLocations.find((loc) => isWithin(loc, p)) : null;
      if (inside) return review('credential-read', `Searches ${p}, which contains ${inside}, a location that commonly holds credentials or secrets.`);
      // The same reach, through the one directory that holds a secret per
      // process. `list_dir` never gets here (it returns names, not contents),
      // and a single read of a file there is still judged by
      // `isProcessInfoPath`, so `/proc/self/environ` is caught and
      // `/proc/self/status` is not.
      if (ctx.toolName === 'grep_search' && isProcessTreePath(p) && walkReachesProcessInfo(p)) {
        return review('credential-read', `Searches ${p}, inside /proc, where a walk reaches every process's environment and command line.`);
      }
    }
  }
  return allow('read');
}

/**
 * `/proc/<pid>/environ` and `/proc/<pid>/cmdline`: what a process was started
 * with. The hook inherits agy's environment, which normally holds the API keys
 * the user exported before starting it, so one unreviewed read here hands the
 * agent the same secrets the credential list exists to protect. It matters
 * exactly where autoagy's own sandbox is not the thing doing the reading: the
 * file tools never run in a sandbox at all, and that sandbox is the only path
 * with `--clearenv` (it also mounts a fresh /proc, so nothing there is hidden).
 *
 * Matched on the path rather than by glob so a symlink resolved in
 * `resolveReal` — `/proc/self/environ` becomes `/proc/<pid>/environ` — still
 * counts.
 */
function isProcessInfoPath(abs) {
  const parts = String(abs).split(/[\\/]/);
  // parts[0] === '' is what makes this an absolute POSIX path: `/proc/...`, and
  // not `C:\proc\...`, `work/proc/...` or a path that merely contains `proc`.
  if (parts[0] !== '' || parts[1] !== 'proc') return false;
  const last = parts[parts.length - 1];
  return last === 'environ' || last === 'cmdline';
}

/**
 * True for `/proc` and anything under it — the tree holding every process's
 * environment and command line.
 *
 * Separate from `isProcessInfoPath` because the two answer different questions.
 * Reading `/proc/self/status` is one harmless file; *searching* `/proc` reads
 * every file below it, environ files included, because a search has the reach
 * of a directory walk. A command naming the directory gets that reach without
 * naming anything that looks like a secret, and nothing in a command line says
 * which files a command will open — so a path here is judged as reaching the
 * tree, not the file.
 */
function isProcessTreePath(abs) {
  const parts = String(abs).split(/[\\/]/);
  return parts[0] === '' && parts[1] === 'proc';
}

/**
 * Whether a *walk* of this path would read a process's environment or command
 * line: the tree's root, any directory inside it, and anything that cannot be
 * looked at from here.
 *
 * The distinction is what keeps the check usable. `/proc/cpuinfo` and
 * `/proc/self/status` are ordinary files and stay allowed, while `/proc` and
 * `/proc/self` are directories whose contents include an environ file for every
 * process visible to the reader — and a command line naming one says nothing
 * about which files the command will open, so the directory is what is judged.
 */
function walkReachesProcessInfo(abs) {
  if (isProcessInfoPath(abs)) return true;
  try {
    return fs.statSync(abs).isDirectory();
  } catch {
    // Gone, or not visible from here: no way to tell, so treat it as a walk.
    return true;
  }
}

export function isCredentialPath(ctx, abs) {
  const { credentialPaths, credentialPathExceptions } = ctx.config;
  if (matchesAnyGlob(abs, credentialPathExceptions, ctx.home)) return false;
  if (isProcessInfoPath(abs)) return true;
  return matchesAnyGlob(abs, credentialPaths, ctx.home) || ctx.credentialLocations.some((loc) => isWithin(abs, loc));
}

/**
 * True when a read of `abs` is already prevented by autoagy's own sandbox, so
 * that reviewing it would only cost the user a prompt for a read that cannot
 * happen. That sandbox mounts a private /proc and masks every credential store
 * it can name by location.
 *
 * "Private" is not enough on its own, and it was once wrong: bwrap stays inside
 * as PID 1, and `/proc/1/environ` held agy's whole environment until the line
 * started bwrap under `env -i`. The /proc answer below holds because nothing
 * the command can see was started with more than the allowlist — which
 * `detectOwnSandbox` makes a condition of the sandbox existing at all.
 *
 * Location, not pattern: the `id_ed25519` pattern matches the key in `~/.ssh`
 * (masked) and a copy someone made inside the workspace (not masked), and only
 * the mount list says which one a given path is.
 *
 * The file tools never reach this — they run outside every sandbox, which is why
 * `/proc` is only a shortcut for commands (see `credentialArgument`).
 */
function hiddenByOwnSandbox(ctx, abs) {
  if (isProcessTreePath(abs)) return true;
  return ctx.credentialLocations.some((loc) => isWithin(abs, loc));
}

/**
 * A credential store that a command names as an argument or redirect target
 * (best effort: only literal paths, `~` and `$HOME` are resolved).
 *
 * The patterns without a fixed location count here as much as the anchored
 * ones: `cat .env` reads the same secrets as `read_file .env`, which has always
 * been reviewed, and nothing masks it inside autoagy's own sandbox either.
 * `hiddenBySandbox` drops the reads that sandbox does prevent.
 */
/** The literal arguments of every command in the line, plus write-redirect targets. */
function literalWords(analysis) {
  const words = analysis.segments.flatMap((s) => s.argv.slice(1));
  for (const command of analysis.parsed.commands) {
    for (const r of command.redirects) if (!r.op.startsWith('<<')) words.push(r.target);
  }
  return words;
}

/**
 * A path `protectedPaths` asks to review that a command names, or null.
 *
 * The setting is documented as "paths that need review to modify", and it
 * reached only the edit tools: `echo x > .husky/pre-commit` was
 * `allow | sandboxed-command` with or without a matching entry, which matters
 * because the class it exists for — `.husky/`, `.envrc`, a `postinstall` script,
 * a `Makefile` — is exactly the "written now, executed later outside the sandbox"
 * one, and the sandbox is where a command writes from.
 *
 * Best effort in the same way the rest of the command analysis is: a literal
 * path, `~` and `$HOME` are resolved, and a path assembled at runtime or reached
 * by a tool that reads its own configuration file is not found. Globs that name a
 * directory are matched by their literal prefix, so `**\/.husky/**` catches
 * `rm -rf .husky` as well as a file inside it.
 *
 * @returns {string | null} the path that matched, for the reason
 */
function protectedArgument(ctx, analysis, cwd) {
  const globs = ctx.protectedGlobs ?? [];
  if (globs.length === 0) return null;
  const base = typeof cwd === 'string' && cwd ? toAbsolute(cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  for (const word of literalWords(analysis)) {
    const value = word.replace(/^~(?=$|\/)/, ctx.home).replace(/\$\{HOME\}|\$HOME\b/g, ctx.home);
    if (/[$`]/.test(value)) continue;
    const abs = toAbsolute(value, base, ctx.home);
    if (!abs) continue;
    for (const p of new Set([abs, resolveReal(abs)])) {
      if (matchesAnyGlob(p, globs, ctx.home)) return p;
    }
  }
  return null;
}

function credentialArgument(ctx, analysis, cwd, { hiddenBySandbox = false } = {}) {
  const base = typeof cwd === 'string' && cwd ? toAbsolute(cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  const words = literalWords(analysis);
  for (const word of words) {
    // PowerShell's `Env:` provider is the environment, and *any* command name
    // can reach it — `ls`, `cat` and `type` are the cmdlets' aliases, and a
    // whitelist of names cannot enumerate its own aliases. So this is judged on
    // the argument as written, before resolution: on Windows `\` is a separator
    // and the provider name would be gone by the time a path is formed.
    //
    // `env*` is the same provider reached by wildcard. It costs a review for a
    // POSIX `cat env*` too, which is the direction this list is supposed to err
    // in, and it is the only form the aliases cannot dodge.
    if (/^env:/i.test(word) || /^env\*$/i.test(word)) return word;
    let value = word.replace(/^~(?=$|\/)/, ctx.home).replace(/\$\{HOME\}|\$HOME\b/g, ctx.home);
    if (/[$`]/.test(value)) continue;
    // For a glob, the directory before the first wildcard.
    const wildcard = value.search(/[*?[]/);
    if (wildcard >= 0) value = value.slice(0, wildcard).replace(/[^\\/]*$/, '') || '.';
    const abs = toAbsolute(value, base, ctx.home);
    if (!abs) continue;
    // A credential store by name, or a path under /proc a walk would take into
    // one. `/proc/cpuinfo` is neither and stays allowed.
    const credential = isCredentialPath(ctx, abs);
    if (!credential && !(isProcessTreePath(abs) && walkReachesProcessInfo(abs))) continue;
    if (hiddenBySandbox && hiddenByOwnSandbox(ctx, abs)) continue;
    return abs;
  }
  return null;
}

/**
 * What a command would read out of the environment agy was started with, or null.
 *
 * The hook inherits agy's environment, which normally holds whatever API keys
 * the user exported before starting it, and exactly two things take that away
 * from a command: the own sandbox's `--clearenv` and the `commandEnv: "scrub"`
 * rewrite into `env -i`. Where neither runs — macOS, Windows, a Linux box
 * without bubblewrap, the IDE without `ownSandbox: "on"` — a command that prints
 * the environment hands over the whole credential list at once, and unlike every
 * other credential read it names no path, so `credentialArgument` cannot see it.
 *
 * Two ways in, and the second is the reason this is not just a command list:
 *
 * - a command whose job is to print it (`printenv`, a bare `env`, `ps auxe`,
 *   `jq env`) — see `printsEnvironment`;
 * - any `$NAME` the line expands, where the sandbox allowlist would not have
 *   passed `NAME` through and the hook's environment actually holds it. That
 *   phrasing is the whole point: `$PATH` and `$HOME` are on the allowlist and
 *   stay free, `$f` in a loop is not in the environment at all and stays free,
 *   and `$OPENAI_API_KEY` is neither. `ownSandboxEnvPassThrough` widens this the
 *   same way it widens the sandbox, so the two cannot disagree about which
 *   variables a command is allowed to see.
 *
 * Best effort in the same way the rest of the command analysis is: a name built
 * at runtime (`eval`, `base64 | sh`) is not a literal `$NAME` and is not found.
 *
 * @param {import('./context.mjs').HookContext} ctx
 * @param {import('./command-safety.mjs').CommandAnalysis} analysis
 * @returns {string | null}
 */
export function environmentExposure(ctx, analysis) {
  for (const segment of analysis.segments) {
    const what = printsEnvironment(segment.argv);
    if (what) return what;
  }
  const passThrough = ctx.config.ownSandboxEnvPassThrough ?? [];
  const env = ctx.env ?? {};
  const exposed = (name) => !envNameAllowed(name, passThrough) && Object.hasOwn(env, name);
  // `declare -p NAME` prints that one variable's value. The command line holds
  // no `$NAME` for the rule below to see — the name is a bare argument — so the
  // same test is applied to it here.
  for (const segment of analysis.segments) {
    for (const name of printedVariableNames(segment.argv)) {
      if (exposed(name)) return `\`${executableName(segment.argv[0])} -p ${name}\`, which prints that variable's value`;
    }
  }
  for (const name of analysis.variables ?? []) {
    if (!exposed(name)) continue;
    return `$${name}, a name the sandbox environment allowlist does not pass through`;
  }
  return null;
}

/**
 * Antigravity's own conversation logs (…/brain/<id>/.system_generated/…) are the
 * reviewer's evidence; forging a "user" message there must be impossible.
 */
function isConversationLog(ctx, p) {
  return Boolean(ctx.appDataDir) && isWithin(p, ctx.appDataDir) && p.split(/[\\/]/).includes('.system_generated');
}

/** Where a write lands, from the most to the least restrictive answer. */
export function classifyWriteTarget(ctx, abs) {
  const real = resolveReal(abs);
  const either = (roots) => roots.some((root) => isWithin(abs, root) || isWithin(real, root));
  if (either(ctx.selfPaths)) return 'self';
  if (isConversationLog(ctx, abs) || isConversationLog(ctx, real)) return 'evidence';
  if (matchesAnyGlob(abs, ctx.protectedGlobs, ctx.home) || matchesAnyGlob(real, ctx.protectedGlobs, ctx.home)) return 'protected';
  // A `.git` anywhere in the path, before anything else can answer: it is the
  // one name that is never legitimate inside a scratch area, so keeping it
  // first means no ordering below can lose it.
  if (abs.split(/[\\/]/).includes('.git') || real.split(/[\\/]/).includes('.git')) return 'protected';
  // Roots nest, in both directions, so the innermost one decides. A checkout
  // under `/tmp` is a workspace inside a managed root, and its `.agents` has to
  // stay protected; Antigravity's artifact directory is a managed directory
  // inside `~/.gemini`, and it has to stay writable even when `~` was declared.
  // Both roots contain the path, so only which one is deeper tells them apart —
  // and since both contain it, one is a prefix of the other, which makes the
  // longer string the deeper root.
  // Membership is judged by where the path really lands, never by how it was
  // spelled: a symlink inside the workspace that points out of it is outside.
  // (The protected answers above use `either`, because either spelling
  // reaching a control surface is enough to protect it.)
  const deepest = (roots) => roots.filter((root) => isWithin(real, root)).sort((a, b) => b.length - a.length)[0] ?? null;
  const managedRoot = deepest(ctx.managedWritableRoots);
  const contentRoot = deepest([...ctx.workspaceRoots, ...ctx.declaredWritableRoots]);
  // Antigravity owns this directory and expects the agent to write in it.
  if (managedRoot && (!contentRoot || managedRoot.length > contentRoot.length)) return 'managed';
  // Like Codex's read-only subpaths, agent metadata stays protected at the top
  // of every root that holds content — the workspace, and the ones
  // `writableRoots` declares.
  if (either(ctx.metadataControlPaths)) return 'protected';
  // `~/.gemini`, `~/.codex`, `~/.claude`. A declared writable root used to be
  // answered *before* this, and that did not widen the directory — it switched
  // the protection off for everything inside it. Measured with
  // `writableRoots: ["~"]`: `~/.gemini/antigravity-cli/settings.json` was
  // `allow | write-workspace`, and that file is where `detectOwnSandbox` reads
  // the `command(*)` grant, so an edit to it drops autoagy back to
  // Antigravity's sandbox, where `.git` and the conversation log are writable.
  // A declared writable root is a statement about the ordinary files in a
  // directory, never about the control surfaces that happen to sit inside it.
  if (either(ctx.homeControlPaths)) return 'protected';
  if (!contentRoot) return 'outside';
  return ctx.workspaceRoots.includes(contentRoot) ? 'workspace' : 'managed';
}

function classifyFileEdit(ctx, state = {}) {
  const raws = pathArgs(ctx.args);
  // Checked before the target walk, so a workspace path that would normally be
  // auto-approved is still reviewed once the conversation is untrusted.
  if (state.untrusted && raws.length > 0) {
    return review('untrusted-write', 'Edits are reviewed from here on: an earlier action in this conversation changed what a path resolves to, and agy writes edited files itself, outside every sandbox.');
  }
  if (raws.length === 0) return review('write-unknown-target', 'Could not determine which file this edit targets.');
  let sawOutside = null;
  let sawProtected = null;
  for (const raw of raws) {
    const abs = toAbsolute(raw, ctx.baseDir, ctx.home);
    if (!abs) return review('write-unknown-target', `Could not resolve the edit target "${raw}" to an absolute path.`);
    const where = classifyWriteTarget(ctx, abs);
    if (where === 'self') {
      return deny(
        'self-protection',
        `autoagy: editing ${abs} would modify the auto-review safeguard itself. This is never auto-approved; ask the user to make the change.`,
      );
    }
    if (where === 'evidence') {
      return deny(
        'self-protection',
        `autoagy: ${abs} is part of Antigravity's conversation log, which the auto-reviewer relies on. Agents may not edit it.`,
      );
    }
    if (where === 'protected') sawProtected = sawProtected ?? abs;
    if (where === 'outside') sawOutside = sawOutside ?? abs;
  }
  if (sawProtected) {
    return review('write-protected', `Edits protected metadata or agent configuration (${sawProtected}), e.g. .git, .agents, or ~/.gemini.`);
  }
  if (sawOutside) {
    // In print mode agy auto-denies a write that needs a permission it cannot
    // prompt for, so the answer is already settled and a review can only spend
    // its 4-12 seconds arriving at it. Interactively the user *is* asked and the
    // write can still succeed, which is why this is narrowed to the one case
    // where the outcome is fixed — and why the review stays everywhere else, as
    // it does in Codex, whose `assess_patch_safety` sends a patch outside the
    // writable roots to the guardian too.
    if (ctx.host?.flags?.headless && ctx.outsideWriteNeedsGrant(sawOutside)) {
      return deny(
        'write-outside-workspace',
        `autoagy: ${sawOutside} is outside the workspace, and agy refuses such a write in print mode because it cannot ask — no review changes that. ` +
          'Either work inside the workspace, or ask the user to add that directory to `writableRoots` in ~/.gemini/autoagy/config.json and re-run `autoagy setup`, which grants it.',
      );
    }
    if (ctx.workspaceRoots.length === 0) {
      return review('write-outside-workspace', `Edits ${sawOutside}; the workspace root could not be determined.`);
    }
    return review('write-outside-workspace', `Edits ${sawOutside}, outside the workspace (${ctx.workspaceRoots.join(', ')}).`);
  }
  return allow('write-workspace');
}

/**
 * Where the targets of a file-editing tool resolve to right now, resolved the
 * same way `classifyFileEdit` resolves them. agy performs the write itself,
 * outside any sandbox, so `handlePostToolUse` resolves them again afterwards
 * and compares: a difference means a command swapped part of the path for a
 * symlink between the check and the write.
 * @returns {{ abs: string, real: string }[]}
 */
export function editTargets(ctx, args = ctx.args) {
  return resolvedTargets(ctx, pathArgs(args));
}

/**
 * The same question for the tools that return file contents.
 *
 * A read follows symlinks exactly as a write does, and it runs outside every
 * sandbox for exactly the same reason — agy performs it itself. The difference
 * is which way the damage points: a write that lands elsewhere can be cleaned
 * up, while a read that lands elsewhere has already put that file in the model's
 * context, and nothing takes that back. So this is worth catching at least as
 * much as the write is.
 *
 * `SearchPath` is included here and not in `PATH_ARG_RE`: that pattern is shared
 * with the edit tools and with the planned action the reviewer sees, and
 * widening it would change what those two do. `classifyRead` treats the search
 * path the same way, for the same reason — a search reads every file beneath it.
 * @returns {{ abs: string, real: string }[]}
 */
export function readTargets(ctx, args = ctx.args) {
  return resolvedTargets(ctx, [...pathArgs(args), args.SearchPath]);
}

/**
 * The path arguments whose parent directories resolve somewhere else, in the
 * shape an `overwrite` takes — or null when none do.
 *
 * Handing agy the already-resolved path takes one variant of the check-to-use
 * race off the table: with the symlink followed in advance, re-pointing it
 * afterwards no longer moves the call. Be clear about which variant. It does
 * **not** cover a real directory in the path being replaced by a symlink after
 * the check, because the call has to traverse that directory whatever it now
 * is; only agy opening the file could catch that one.
 *
 * The everyday reason is the same mechanism seen from the other side. Tools
 * that rebuild symlink trees in the background — pnpm's `node_modules`, build
 * caches — re-point links constantly, and an edit or read that happened to run
 * beside one would otherwise be reported as a swapped target and cost the user
 * an `autoagy trust` for nothing.
 *
 * Only arguments that actually change are returned, so an ordinary call is not
 * rewritten and the agent is not shown "a pre-tool hook changed the arguments"
 * for no reason. Measured on agy 1.2.7: `overwrite` applies to the edit tools
 * and to the read tools alike.
 * @returns {object | null}
 */
export function canonicalPathArgs(ctx) {
  const out = {};
  for (const [key, value] of Object.entries(ctx.args)) {
    // `SearchPath` is a read's target and is deliberately outside PATH_ARG_RE
    // (see readTargets), so it is named here as well.
    if (!PATH_ARG_RE.test(key) && key !== 'SearchPath') continue;
    if (typeof value === 'string') {
      const canonical = canonicalTarget(ctx, value);
      if (canonical) out[key] = canonical;
    } else if (Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string')) {
      const mapped = value.map((v) => canonicalTarget(ctx, v) ?? v);
      if (mapped.some((v, i) => v !== value[i])) out[key] = mapped;
    }
  }
  return Object.keys(out).length > 0 ? out : null;
}

/** One path argument resolved, when that differs from the path as written. */
function canonicalTarget(ctx, raw) {
  const abs = toAbsolute(raw, ctx.baseDir, ctx.home);
  if (!abs) return null;
  const real = resolveReal(abs);
  // Comparing against the absolute form, not the raw one: turning a relative
  // path into an absolute one is not a resolution and is not worth a rewrite.
  if (real === abs) return null;
  // A link at or above the base is not rewritten either, and the reason is what
  // it costs, not that it would buy nothing: handing agy the resolved path does
  // pin the base's own link, the same way it pins one inside the target's path.
  // What it costs is that agy tells the agent "a pre-tool hook changed the
  // arguments" whenever `overwrite` is present — and on a host whose workspace
  // path goes through a link (macOS `/tmp` and `/var/folders`, a symlinked
  // home) that is every edit and every read. That notice is the only signal the
  // agent gets when a rewrite is real, so it cannot be spent on calls where
  // nothing moved. What is given up is the narrower half: a link above the
  // workspace is a system path the agent cannot re-point — it is outside the
  // workspace, so writing it needs a review, and agy refuses the write outright
  // under `allowNonWorkspaceAccess: false` — and a swap that happens after the
  // call is still caught by the PostToolUse comparison.
  //
  // What is worth reporting is a difference below the base: a link in the
  // target's own path.
  const base = ctx.baseDir;
  if (base && isWithin(abs, base)) {
    const expected = path.join(resolveReal(base), path.relative(base, abs));
    if (real === expected) return null;
  }
  return real;
}

function resolvedTargets(ctx, raws) {
  const out = [];
  for (const raw of raws) {
    if (typeof raw !== 'string') continue;
    const abs = toAbsolute(raw, ctx.baseDir, ctx.home);
    if (abs) out.push({ abs, real: resolveReal(abs) });
  }
  return out;
}

// Assignments that relocate the harness or `~` for whatever the command starts.
// An assignment rather than a bare substring: `XDG_CONFIG_HOME=` must not match.
const ENV_ASSIGNMENT_RE = /(?:^|[\s;&|(])(HOME|AGY_[A-Z_]*|ANTIGRAVITY_[A-Z_]*|JETSKI_[A-Z_]*)=/;

function mentionsSelf(ctx, commandLine) {
  if (ENV_ASSIGNMENT_RE.test(commandLine)) return true;
  // AUTOAGY_*: variables such as AUTOAGY_HOME relocate autoagy's config for an agy the command starts.
  const needles = new Set(['.system_generated', 'AUTOAGY_']);
  for (const p of ctx.selfPaths) {
    needles.add(p);
    if (p.startsWith(ctx.home)) {
      const rest = p.slice(ctx.home.length);
      // All three spellings of the same path. `${HOME}` is the one that was
      // missing, and the argument-side checks in this file
      // (`credentialArgument`, `plantedHookTarget`) have always expanded it —
      // a needle list that is narrower than they are is a hole with no reason.
      needles.add(`~${rest}`);
      needles.add(`$HOME${rest}`);
      needles.add(`\${HOME}${rest}`);
    }
  }
  return [...needles].some((n) => n.length > 3 && commandLine.includes(n));
}

/**
 * The planted-hook record a command would run into, or null.
 *
 * A hook planted in a nested `.git` runs outside every sandbox the next time git
 * runs in that repository — a writing git command has to `BypassSandbox` to work
 * at all — and a review is the only lever left, because the sandbox cannot mount
 * a `.git` it had no way to know would exist. That is why the repository is what
 * gets matched rather than a command name: `{CommandLine: "git commit", Cwd:
 * "<repo>"}` executes the hook while the line itself names nothing but `git`.
 *
 * Two ways in, for that reason. The command line is scanned for the paths as
 * text (the `mentionsSelf` habit, which is what catches the `~`/`$HOME`
 * spellings), and every literal argument, redirect target and the call's `Cwd` is
 * resolved and tested against the repository (the `credentialArgument` habit,
 * which is what catches a `Cwd` the line never spells out).
 *
 * Best effort in the same way the rest of the command analysis is: `cd $d && git
 * commit` builds the path at runtime and is not found.
 *
 * @param {import('./context.mjs').HookContext} ctx
 * @param {import('./command-safety.mjs').CommandAnalysis} analysis
 * @param {string|undefined} cwd the call's Cwd
 * @param {object[]|undefined} planted state.plantedHooks, absent in an old state file
 * @returns {object | null} the record that matched, so the reason can name it
 */
function plantedHookTarget(ctx, analysis, cwd, planted) {
  if (!Array.isArray(planted) || planted.length === 0) return null;
  const commandLine = typeof ctx.args.CommandLine === 'string' ? ctx.args.CommandLine : '';
  const base = typeof cwd === 'string' && cwd ? toAbsolute(cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  const words = analysis.segments.flatMap((s) => s.argv.slice(1));
  for (const command of analysis.parsed.commands) {
    for (const r of command.redirects) if (!r.op.startsWith('<<')) words.push(r.target);
  }
  for (const entry of planted) {
    if (typeof entry?.path !== 'string' || typeof entry?.dir !== 'string') continue;
    const needles = new Set([entry.path, entry.dir]);
    if (entry.dir.startsWith(ctx.home)) {
      needles.add(`~${entry.dir.slice(ctx.home.length)}`);
      needles.add(`$HOME${entry.dir.slice(ctx.home.length)}`);
    }
    if ([...needles].some((n) => n.length > 3 && commandLine.includes(n))) return entry;
    // The repository itself is covered by one test: `isWithin` is true for the
    // equal path, so a command whose Cwd *is* the repository matches too, and so
    // does one that names a file under its `.git`.
    if (base && isWithin(base, entry.dir)) return entry;
    for (const word of words) {
      const value = word.replace(/^~(?=$|\/)/, ctx.home).replace(/\$\{HOME\}|\$HOME\b/g, ctx.home);
      if (/[$`]/.test(value)) continue;
      const abs = toAbsolute(value, base, ctx.home);
      if (abs && isWithin(abs, entry.dir)) return entry;
    }
  }
  return null;
}

/**
 * The path a known-safe command would actually run, when it lands inside a
 * writable root.
 *
 * Only asked where no sandbox confines the command. There a workspace `PATH`
 * entry, or a `./script` argument, decides which file runs — while the
 * known-safe allowlist judges the *name* alone. `cat` is safe as `/usr/bin/cat`;
 * it is not safe as a script the agent just wrote into `node_modules/.bin`, and
 * that chain reaches the reviewer by no other route, because a known-safe
 * command is allowed without one. Inside autoagy's own sandbox it does not
 * matter: the sandbox bounds whatever the binary can reach.
 *
 * @returns {string|null} the path that would run, when it is agent-writable
 */
function executableFromWritableRoot(ctx, analysis) {
  if (ctx.writableRoots.length === 0) return null;
  const writable = (p) => ctx.writableRoots.some((root) => isWithin(p, root) || isWithin(resolveReal(p), root));
  for (const segment of analysis.segments ?? []) {
    const argv0 = segment.argv?.[0];
    if (!argv0) continue;
    // A name containing a separator is a path and resolves where it says;
    // otherwise it is looked up in PATH, in order, and the first match is what
    // a shell would run.
    const resolved = /[\\/]/.test(argv0) ? toAbsolute(argv0, ctx.baseDir, ctx.home) : findExecutable(argv0, ctx.env.PATH, []);
    if (resolved && writable(resolved)) return resolved;
  }
  return null;
}

function classifyCommand(ctx, state = {}) {
  const commandLine = ctx.args.CommandLine;
  if (typeof commandLine !== 'string' || commandLine.trim() === '') {
    return review('command-unparseable', 'The command line is missing or empty.');
  }
  const bypass = ctx.args.BypassSandbox === true;
  const analysis = analyzeCommandLine(commandLine);
  const selfNote = mentionsSelf(ctx, commandLine)
    ? ' The command references autoagy’s own files or environment variables, or Antigravity’s conversation logs, which are security controls and review evidence.'
    : '';
  // In an untrusted conversation the review evidence is exactly what is in
  // doubt, so a command that reaches for it is refused rather than judged.
  if (selfNote && state.untrusted) {
    return deny('touches-security-controls', `autoagy: refused because this conversation is no longer trusted.${selfNote} Ask the user to look at what changed on disk first.`);
  }
  // autoagy's own sandbox masks the credential stores it can locate by path and
  // gives the command a private /proc, so a read it prevents there is not worth
  // a review. Everywhere else — including a command that asked to leave the
  // sandbox — naming a store is enough.
  const credential = credentialArgument(ctx, analysis, ctx.args.Cwd, { hiddenBySandbox: ctx.ownSandbox.active && !bypass });
  const credentialNote = credential ? ` The command names ${credential}, a location that commonly holds credentials or secrets.` : '';
  // Reading the environment is a credential read that names no path. It is only
  // a question where nothing rebuilds that environment for the command: with the
  // own sandbox's `--clearenv` or the `commandEnv: "scrub"` rewrite in force the
  // command sees the allowlist, and reviewing it would cost a prompt for a read
  // that cannot happen. An escalated command is judged with its environment
  // intact, which is part of what escalation means.
  const envExposure = ctx.envScrubbed && !bypass ? null : environmentExposure(ctx, analysis);
  const envNote = envExposure
    ? ` The command reads ${envExposure}: the hook inherits the environment agy was started with, which commonly holds exported API keys, and nothing rebuilds it for this command.`
    : '';

  // `protectedPaths` names paths the operator wants reviewed before they change;
  // it reached the edit tools only, so a command writing one of them — the case
  // the setting exists for, since a command is what writes inside the sandbox —
  // was allowed without a look.
  const protectedHit = protectedArgument(ctx, analysis, ctx.args.Cwd);
  const protectedNote = protectedHit ? ` The command names ${protectedHit}, which protectedPaths asks to review before it changes.` : '';

  // A planted hook runs outside every sandbox — the writing git command that
  // reaches it has to `BypassSandbox` to work at all — and nothing can mount a
  // `.git` that did not exist when the command line was built. So the repository
  // is handed to the reviewer instead of the command being judged on its own.
  const planted = plantedHookTarget(ctx, analysis, ctx.args.Cwd, state.plantedHooks);
  const plantedNote = planted
    ? ` The command touches ${planted.dir}, where ${planted.path} appeared while a sandboxed command ran. Whatever git will execute from there runs outside every sandbox, and the reviewer has been given what is in it.`
    : '';

  const rules = evaluateRules(analysis, ctx.config.rules);
  if (rules.decision === 'forbidden') {
    return deny('rule-forbidden', `autoagy: blocked by rule ${describeRule(rules.rule)} (matched \`${rules.argv.join(' ')}\`).`);
  }
  if (rules.decision === 'prompt') {
    return review('rule-prompt', `Matches a rule that requires approval: ${describeRule(rules.rule)}.${selfNote}${credentialNote}${envNote}${plantedNote}`);
  }
  // An operator wrote those rules before there was a plant; the allow is not
  // evidence that anyone looked at this.
  if (rules.decision === 'allow' && !selfNote && !credential && !envExposure && !planted && !protectedHit) return allow('rule-allow', describeRule(rules.rule));

  if (bypass) {
    // `plantedNote` belongs here most of all: leaving the sandbox is how a hook
    // planted in a nested repository gets to run at all, and `git commit` with a
    // `Cwd` inside it names nothing the reviewer could connect on its own.
    return review(
      'sandbox-escalation',
      `The agent asked to run this command outside the terminal sandbox (BypassSandbox: true).${selfNote}${credentialNote}${envNote}${plantedNote}`,
    );
  }
  // The sandbox may mount the conversation's artifact directory writable, so
  // never wave through commands that touch autoagy or the conversation logs.
  if (selfNote) return review('touches-security-controls', selfNote.trim());
  if (credential) return review('credential-read', credentialNote.trim());
  if (envExposure) return review('environment-read', envNote.trim());
  if (protectedHit) return review('protected-path', `${protectedNote.trim()} It would change inside the sandbox, where nothing else reviews it.`);
  // Starting another Antigravity is never routine: whether these hooks are
  // loaded at all is decided by that instance's own configuration and
  // environment, and this call can set both. Placed after the categories above
  // so no existing verdict changes.
  const started = (analysis.segments ?? []).find((s) => /^agy(\.exe)?$/i.test(executableName(s.argv?.[0] ?? '')));
  if (started) {
    return review('starts-antigravity', `Starts another Antigravity instance (\`${started.argv.join(' ')}\`). Whether autoagy reviews that session depends on configuration and environment this call can choose.`);
  }
  // Placed above the sandbox branches on purpose, so neither allowlist can wave
  // it through: `ls sub` is `known-safe-command` where no sandbox confines it,
  // and that exit is inside the block below. After the categories above, so no
  // existing verdict changes.
  if (planted) return review('planted-hook', plantedNote.trim());
  if (!ctx.sandbox.active) {
    if (isKnownSafeCommandLine(analysis)) {
      const shadowed = executableFromWritableRoot(ctx, analysis);
      if (!shadowed) return allow('known-safe-command');
      return review(
        'command-from-writable-root',
        `This is one of the known read-only commands, but the file that would run is ${shadowed}, inside a directory the agent can write, and nothing here confines it.`,
      );
    }
    return review('unsandboxed-command', `Commands are not confined by the terminal sandbox here (${ctx.sandbox.detail}).`);
  }
  if (analysis.error) {
    return review('command-unparseable', `autoagy could not fully parse this command (${analysis.error}), so it cannot rule out destructive effects.`);
  }
  const danger = findDangerousCommand(analysis);
  if (danger) {
    return review('dangerous-command', `Potentially destructive command inside the sandbox: ${danger.description}.`);
  }
  return allow('sandboxed-command');
}

export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export function isTrustedHost(host, trustedDomains) {
  if (!host) return false;
  return (trustedDomains ?? []).some((domain) => {
    const d = String(domain).toLowerCase().replace(/^\*\./, '');
    return host === d || host.endsWith(`.${d}`);
  });
}

/**
 * Fetching a URL and navigating a browser to it are not the same exposure. A
 * fetch returns text to the model; a navigation loads a page whose scripts run
 * in an unsandboxed, networked browser, and a local development server usually
 * serves files the agent may have edited without review. So the two keep
 * separate allowlists, and the browser one is empty by default.
 */
function classifyUrl(ctx) {
  const url = ctx.args.Url ?? ctx.args.URL ?? ctx.args.url;
  const host = typeof url === 'string' ? hostOf(url) : null;
  const browser = ctx.toolName === 'open_browser_url';
  const list = browser ? ctx.config.browserTrustedDomains : ctx.config.trustedDomains;
  if (host && isTrustedHost(host, list)) return allow('network-trusted', host);
  return review('network', `Network access to ${host ?? 'an unknown host'}${typeof url === 'string' ? ` (${url})` : ''}.`);
}

export function mcpTarget(ctx) {
  const a = ctx.args;
  if (ctx.toolName === 'call_mcp_tool') {
    const server = a.ServerName ?? a.Server ?? a.server_name ?? a.server ?? a.McpServerName ?? '';
    const tool = a.ToolName ?? a.Tool ?? a.tool_name ?? a.tool ?? a.Name ?? a.name ?? '';
    return { server: String(server), tool: String(tool), args: a.Arguments ?? a.Args ?? a.arguments ?? a.Input ?? a.input };
  }
  if (MCP_RESOURCE_TOOLS.has(ctx.toolName)) {
    const server = a.ServerName ?? a.Server ?? a.server_name ?? a.server ?? a.McpServerName ?? '';
    return { server: String(server), tool: ctx.toolName, args: stripMeta(a) };
  }
  const rest = ctx.toolName.slice('mcp_'.length);
  return { server: '', tool: rest, args: stripMeta(a) };
}

function classifyMcp(ctx) {
  const { server, tool } = mcpTarget(ctx);
  const id = server ? `${server}/${tool}` : tool;
  // The same glob engine every other path-shaped setting uses. It had its own
  // dialect here — `*` crossed `/`, and `{a,b}` was matched literally, so
  // `github/{get,list}_*` silently matched nothing while looking like the
  // `credentialPaths` patterns it was copied from.
  const allowed = (ctx.config.mcp?.allow ?? []).some((glob) => {
    const re = globToRegExp(String(glob));
    return re.test(id) || re.test(ctx.toolName);
  });
  if (allowed) return allow('mcp-allowed', id);
  // Codex's rule, from the servers' own annotations, and only when the config says
  // to believe them. Placed after `mcp.allow` because that list is the user's own
  // judgement and needs no server's cooperation; placed before the resource reads
  // below because those are not tools and carry no annotations.
  if (ctx.config.mcp?.annotations === 'trust' && !MCP_RESOURCE_TOOLS.has(ctx.toolName)) {
    const claim = annotationVerdict(ctx.mcpCache, { server, tool, toolName: ctx.toolName });
    if (claim === 'read-only') return allow('mcp-read-only', id);
    // Both remaining answers are reviewed, as in Codex — but the reviewer is told
    // which one it is, because "the server calls this destructive" and "no server
    // claims anything about this" are different pieces of evidence.
    if (claim === 'destructive') {
      return review('mcp', `Calls MCP tool ${id || ctx.toolName}, which its server annotates as destructive.`);
    }
    return review(
      'mcp',
      `Calls MCP tool ${id || ctx.toolName}. No annotation for it was found in the scan${ctx.mcpCache ? '' : ' (no scan has been recorded — run `autoagy mcp-scan`)'}, so it is reviewed.`,
    );
  }
  if (MCP_RESOURCE_TOOLS.has(ctx.toolName)) {
    const uri = ctx.args.Uri ?? ctx.args.URI ?? ctx.args.uri ?? ctx.args.ResourceUri ?? ctx.args.resource_uri;
    return review(
      'mcp-resource',
      `Reads MCP resource ${id}${typeof uri === 'string' ? ` (${uri})` : ''}: the URI is chosen by the agent, and reading one can reach a remote server or a file the path rules never see.`,
    );
  }
  return review('mcp', `Calls MCP tool ${id || ctx.toolName}; MCP tools are reviewed unless listed in mcp.allow.`);
}

function stripMeta(args) {
  if (!args || typeof args !== 'object') return args;
  const { toolAction, toolSummary, ...rest } = args;
  return rest;
}

// ---------------------------------------------------------------------------
// Planned action JSON (the reviewer's view of the request)

const MAX_ACTION_STRING_BYTES = 16_000 * 4;

export function truncateMiddle(text, maxBytes) {
  if (typeof text !== 'string' || Buffer.byteLength(text) <= maxBytes) return text;
  const omittedTokens = Math.ceil((Buffer.byteLength(text) - maxBytes) / 4);
  const marker = `<truncated omitted_approx_tokens="${omittedTokens}" />`;
  const keep = Math.max(0, maxBytes - marker.length);
  const head = Math.floor(keep / 2);
  return `${text.slice(0, head)}${marker}${text.slice(text.length - (keep - head))}`;
}

function truncateDeep(value) {
  if (typeof value === 'string') return truncateMiddle(value, MAX_ACTION_STRING_BYTES);
  if (Array.isArray(value)) return value.map(truncateDeep);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, truncateDeep(v)]));
  return value;
}

const DELETING_COMMANDS = new Set(['rm', 'rmdir', 'shred', 'unlink']);
const WINDOWS_REMOVE = new Set(['del', 'erase', 'rd', 'rmdir.exe']);

/** The positional arguments of `argv.slice(1)`, honouring `--`. */
function positionalArgs(rest, withValue = new Set()) {
  const out = [];
  let options = true;
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (options && arg === '--') {
      options = false;
      continue;
    }
    if (options && arg.startsWith('-') && arg !== '-') {
      if (withValue.has(arg)) i++;
      continue;
    }
    out.push(arg);
  }
  return out;
}

/**
 * The paths a destructive command would act on, and what each one is to it.
 *
 * The facts exist because the reviewer has no tools: Codex's guardian inspects
 * a deletion target with read-only calls, so autoagy looks first and hands the
 * answers over. The list used to be `rm`/`rmdir`/`shred`/`unlink` alone, while
 * the dangerous-command table has always been wider — so `git clean -xdf`,
 * `find . -delete` and `git rm -f` reached the reviewer with nothing but their
 * command line, against a policy that says to stay conservative when the scope
 * cannot be established. Those three are routine (a clean before a build, a
 * sweep of stale files), and "conservative because I cannot see" is the most
 * expensive way to be wrong about them.
 *
 * `role` says what the path is when it is not simply the thing being removed —
 * a search root or a repository is a very different scope, and the reviewer
 * cannot tell from the path alone.
 *
 * @returns {{ arg: string, role?: string }[] | null} null when this command deletes nothing by path
 */
function deletionTargetArgs(argv) {
  const name = executableName(argv[0]);
  const rest = argv.slice(1);
  const plain = (args) => args.map((arg) => ({ arg }));
  if (DELETING_COMMANDS.has(name) || WINDOWS_REMOVE.has(name)) return plain(positionalArgs(rest));
  // `truncate -s 0 file` discards the contents without removing the file.
  if (name === 'truncate') return plain(positionalArgs(rest, new Set(['-s', '--size', '-r', '--reference', '-o', '--io-blocks'])));
  if (name === 'dd') return plain(rest.filter((a) => a.startsWith('of=')).map((a) => a.slice(3)));
  if (name === 'find') {
    // The roots are the leading words before the first expression; `-delete`
    // removes what matches *below* them, so the scope is the subtree.
    if (!rest.includes('-delete')) return null;
    const roots = [];
    for (const arg of rest) {
      if (arg.startsWith('-') || arg === '(' || arg === '!') break;
      roots.push(arg);
    }
    return (roots.length > 0 ? roots : ['.']).map((arg) => ({ arg, role: 'search root; `-delete` removes matching entries below it' }));
  }
  if (name === 'git') {
    const { subcommand, args } = gitSubcommand(argv);
    if (subcommand === 'rm') return plain(positionalArgs(args));
    if (subcommand === 'clean') {
      const paths = positionalArgs(args);
      return (paths.length > 0 ? paths : ['.']).map((arg) => ({ arg, role: 'pathspec; `git clean` removes untracked files below it' }));
    }
    return null;
  }
  return null;
}
const MAX_INSPECTED_TARGETS = 10;

/** Expands `~`, `$HOME` and `${HOME}`; returns null when other expansions remain. */
function expandPathArgument(arg, home) {
  let value = arg.replace(/^~(?=$|\/)/, home).replace(/\$\{HOME\}|\$HOME\b/g, home);
  if (/[$`*?[]/.test(value)) return null;
  return value;
}

/**
 * Read-only facts about the paths a deleting command targets. Codex's reviewer
 * inspects targets with read-only tools; the autoagy reviewer has no tools, so
 * autoagy gathers the same facts up front.
 */
export function inspectDeletionTargets(ctx, commandLine, cwd) {
  const analysis = analyzeCommandLine(commandLine);
  const base = typeof cwd === 'string' && cwd ? toAbsolute(cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  const facts = [];
  for (const segment of analysis.segments) {
    const targets = deletionTargetArgs(segment.argv);
    if (!targets) continue;
    for (const { arg, role } of targets) {
      if (facts.length >= MAX_INSPECTED_TARGETS) break;
      const expanded = expandPathArgument(arg, ctx.home);
      if (expanded === null) {
        facts.push({ argument: arg, ...(role ? { role } : {}), note: 'contains variables or globs that autoagy cannot resolve' });
        continue;
      }
      const abs = toAbsolute(expanded, base, ctx.home);
      if (!abs) {
        facts.push({ argument: arg, ...(role ? { role } : {}), note: 'relative path with unknown working directory' });
        continue;
      }
      // What the command actually deletes: symlinks in parent directories are
      // always followed; the last component only with a trailing slash
      // (`rm -r link/` deletes the target's contents, `rm link` just the link).
      const lexical = abs.length > 1 ? abs.replace(/[\\/]+$/, '') : abs;
      const effective = /[\\/]\.?$/.test(expanded) ? resolveReal(lexical) : path.join(resolveReal(path.dirname(lexical)), path.basename(lexical));
      const roots = ctx.workspaceRoots.flatMap((root) => [root, resolveReal(root)]);
      const fact = { argument: arg, ...(role ? { role } : {}), path: abs, inside_workspace: roots.some((root) => isWithin(effective, root)) };
      if (effective !== lexical) fact.resolves_to = effective;
      try {
        const stat = fs.lstatSync(effective);
        fact.exists = true;
        fact.type = stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'directory' : 'file';
        if (fact.type === 'directory') {
          const entries = fs.readdirSync(effective);
          fact.entries = entries.length;
          fact.is_git_repository = entries.includes('.git');
        } else if (fact.type === 'file') {
          fact.bytes = stat.size;
        } else {
          fact.link_target = fs.readlinkSync(effective);
        }
      } catch {
        fact.exists = fact.exists ?? false;
      }
      if ([abs, lexical, effective].some((p) => p === ctx.home || p === path.parse(p).root)) fact.note = 'this is the home directory or filesystem root';
      facts.push(fact);
    }
  }
  return facts.length > 0 ? facts : undefined;
}

/**
 * The action as the reviewer sees it (Codex "Planned action JSON").
 * @param {import('./context.mjs').HookContext} ctx
 */
export function plannedAction(ctx) {
  const a = ctx.args;
  const justification = [a.toolSummary, a.toolAction].filter((s) => typeof s === 'string' && s.trim()).join(' — ') || undefined;
  let action;
  if (ctx.toolName === 'run_command') {
    action = {
      tool: 'run_command',
      command: a.CommandLine,
      cwd: a.Cwd ?? ctx.baseDir ?? undefined,
      sandbox: a.BypassSandbox === true ? 'bypass_requested' : ctx.sandbox.active ? 'sandboxed' : 'unsandboxed',
      justification,
    };
    if (typeof a.CommandLine === 'string') {
      const targets = inspectDeletionTargets(ctx, a.CommandLine, a.Cwd);
      if (targets) action.deletion_targets = targets;
    }
  } else if (FILE_EDIT_TOOLS.has(ctx.toolName)) {
    const files = pathArgs(a).map((p) => toAbsolute(p, ctx.baseDir, ctx.home) ?? p);
    action = { tool: ctx.toolName, files, ...stripMeta(a), justification };
  } else if (URL_TOOLS.has(ctx.toolName)) {
    const url = a.Url ?? a.URL ?? a.url;
    action = { tool: ctx.toolName, url, host: typeof url === 'string' ? hostOf(url) : undefined, justification };
  } else if (ctx.toolName === 'call_mcp_tool' || ctx.toolName.startsWith('mcp_')) {
    const { server, tool, args } = mcpTarget(ctx);
    action = { tool: 'mcp_tool_call', server: server || undefined, tool_name: tool, arguments: args, justification };
  } else {
    action = { tool: ctx.toolName, arguments: stripMeta(a), justification };
  }
  return truncateDeep(JSON.parse(JSON.stringify(action)));
}
