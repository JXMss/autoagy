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
import { analyzeCommandLine, findDangerousCommand, isKnownSafeCommandLine, printsEnvironment, executableName } from './command-safety.mjs';
import { evaluateRules, describeRule } from './exec-rules.mjs';
import { HOST_INSPECTABLE_PLATFORMS } from './context.mjs';
import { envNameAllowed } from './confine.mjs';
import { toAbsolute, resolveReal, isWithin, matchesAnyGlob, findExecutable } from './paths.mjs';

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
  if (name === 'notebook_execution') return review('code-execution', 'Executes notebook code outside the terminal sandbox.');
  if (name === 'define_subagent') {
    return review(
      'agent-definition',
      'Defines a new subagent. A subagent that does not inherit customizations (or excludes default components) would run without these auto-review hooks.',
    );
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
function credentialArgument(ctx, analysis, cwd, { hiddenBySandbox = false } = {}) {
  const base = typeof cwd === 'string' && cwd ? toAbsolute(cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  const words = analysis.segments.flatMap((s) => s.argv.slice(1));
  for (const command of analysis.parsed.commands) {
    for (const r of command.redirects) if (!r.op.startsWith('<<')) words.push(r.target);
  }
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
  for (const name of analysis.variables ?? []) {
    if (envNameAllowed(name, passThrough)) continue;
    if (!Object.hasOwn(env, name)) continue;
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
  // Like Codex's read-only subpaths, .git and agent metadata stay protected in every writable root.
  if (either(ctx.workspaceControlPaths) || abs.split(/[\\/]/).includes('.git') || real.split(/[\\/]/).includes('.git')) return 'protected';
  if (ctx.managedWritableRoots.some((root) => isWithin(real, root))) return 'managed';
  if (either(ctx.homeControlPaths)) return 'protected';
  if (ctx.workspaceRoots.some((root) => isWithin(real, root))) return 'workspace';
  return 'outside';
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
export function editTargets(ctx) {
  const out = [];
  for (const raw of pathArgs(ctx.args)) {
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
      needles.add(`~${p.slice(ctx.home.length)}`);
      needles.add(`$HOME${p.slice(ctx.home.length)}`);
    }
  }
  return [...needles].some((n) => n.length > 3 && commandLine.includes(n));
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

  const rules = evaluateRules(analysis, ctx.config.rules);
  if (rules.decision === 'forbidden') {
    return deny('rule-forbidden', `autoagy: blocked by rule ${describeRule(rules.rule)} (matched \`${rules.argv.join(' ')}\`).`);
  }
  if (rules.decision === 'prompt') {
    return review('rule-prompt', `Matches a rule that requires approval: ${describeRule(rules.rule)}.${selfNote}${credentialNote}${envNote}`);
  }
  if (rules.decision === 'allow' && !selfNote && !credential && !envExposure) return allow('rule-allow', describeRule(rules.rule));

  if (bypass) {
    return review('sandbox-escalation', `The agent asked to run this command outside the terminal sandbox (BypassSandbox: true).${selfNote}${credentialNote}${envNote}`);
  }
  // The sandbox may mount the conversation's artifact directory writable, so
  // never wave through commands that touch autoagy or the conversation logs.
  if (selfNote) return review('touches-security-controls', selfNote.trim());
  if (credential) return review('credential-read', credentialNote.trim());
  if (envExposure) return review('environment-read', envNote.trim());
  // Starting another Antigravity is never routine: whether these hooks are
  // loaded at all is decided by that instance's own configuration and
  // environment, and this call can set both. Placed after the categories above
  // so no existing verdict changes.
  const started = (analysis.segments ?? []).find((s) => /^agy(\.exe)?$/i.test(executableName(s.argv?.[0] ?? '')));
  if (started) {
    return review('starts-antigravity', `Starts another Antigravity instance (\`${started.argv.join(' ')}\`). Whether autoagy reviews that session depends on configuration and environment this call can choose.`);
  }
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
  const allowed = (ctx.config.mcp?.allow ?? []).some((glob) => {
    const re = new RegExp(`^${String(glob).replace(/[.+^$()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
    return re.test(id) || re.test(ctx.toolName);
  });
  if (allowed) return allow('mcp-allowed', id);
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
    if (!DELETING_COMMANDS.has(executableName(segment.argv[0]))) continue;
    let options = true;
    for (const arg of segment.argv.slice(1)) {
      if (options && arg === '--') {
        options = false;
        continue;
      }
      if (options && arg.startsWith('-')) continue;
      if (facts.length >= MAX_INSPECTED_TARGETS) break;
      const expanded = expandPathArgument(arg, ctx.home);
      if (expanded === null) {
        facts.push({ argument: arg, note: 'contains variables or globs that autoagy cannot resolve' });
        continue;
      }
      const abs = toAbsolute(expanded, base, ctx.home);
      if (!abs) {
        facts.push({ argument: arg, note: 'relative path with unknown working directory' });
        continue;
      }
      // What the command actually deletes: symlinks in parent directories are
      // always followed; the last component only with a trailing slash
      // (`rm -r link/` deletes the target's contents, `rm link` just the link).
      const lexical = abs.length > 1 ? abs.replace(/[\\/]+$/, '') : abs;
      const effective = /[\\/]\.?$/.test(expanded) ? resolveReal(lexical) : path.join(resolveReal(path.dirname(lexical)), path.basename(lexical));
      const roots = ctx.workspaceRoots.flatMap((root) => [root, resolveReal(root)]);
      const fact = { argument: arg, path: abs, inside_workspace: roots.some((root) => isWithin(effective, root)) };
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
