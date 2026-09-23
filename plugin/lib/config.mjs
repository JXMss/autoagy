// autoagy configuration: defaults, loading, validation and env overrides.
//
// The config lives in `$AUTOAGY_HOME/config.json` (default
// `~/.gemini/autoagy/config.json`). Only a global config is read: a
// workspace-level file could be rewritten by the very agent it is meant to
// constrain.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { toAbsolute, expandHome } from './paths.mjs';

export const DEFAULT_CONFIG = Object.freeze({
  // "auto": Codex "Approve for me" — risky actions are judged by the reviewer model.
  // "ask":  Codex "Ask for approval" — risky actions go to the human (Antigravity prompt).
  // "off":  no review; Antigravity's own permission flow applies, except that the actions
  //         covered by the grants `autoagy setup` added still prompt the user.
  mode: 'auto',
  // Whether sandboxed run_command calls are really confined by Antigravity's terminal
  // sandbox: "auto" detects it from the Antigravity CLI settings and flags.
  sandbox: 'auto',
  // autoagy's own terminal sandbox (Linux, bubblewrap), which keeps .git, agent
  // metadata and the conversation logs read-only, as Codex does:
  // "auto": used when bubblewrap works and the CLI settings grant command(*);
  // "on":   always (commands are reviewed when it is unavailable); "off": never.
  ownSandbox: 'auto',
  reviewer: {
    // "agy": a tool-less Antigravity agent in headless mode (uses your Antigravity login).
    // "openai": any OpenAI-compatible Chat Completions endpoint (OpenAI, Gemini, DeepSeek, ...).
    // "none": no reviewer model; behaves like mode "ask".
    backend: 'agy',
    // The whole review, retries included, must answer inside the pre-tool-use
    // hook's own timeout (150s in hooks.json), which is what caps this.
    timeoutSec: 140,
    // One attempt's budget: Codex's deadline, kept as the point where a stalled
    // attempt is killed and asked again.
    attemptTimeoutSec: 90,
    maxAttempts: 3,
    agy: {
      command: 'agy',
      agent: 'autoagy-guardian',
      model: null,
      effort: 'low',
    },
    openai: {
      baseUrl: 'https://api.openai.com/v1',
      apiKeyEnv: 'OPENAI_API_KEY',
      model: 'gpt-5-mini',
      headers: {},
      jsonMode: true,
    },
    // "mock" (tests only): a fixed reply ("allow", "deny", "critical", "error",
    // "timeout", "sleep:<ms>:<spec>" or raw text); `capture` appends each prompt to a file.
    mock: {
      response: 'allow',
      capture: null,
    },
  },
  // What to do when the reviewer denies, times out, or fails.
  // "deny" is Codex behavior; "ask" hands the decision to the human instead.
  onDenied: 'deny',
  onTimeout: 'deny',
  onError: 'deny',
  // Domains a web fetch may reach without review.
  trustedDomains: ['localhost', '127.0.0.1', '[::1]'],
  // Whether `autoagy setup` also writes Antigravity a `read_url(<domain>)` grant
  // for each `trustedDomains` entry.
  //
  // It has to be a switch, because a `read_url` rule is two things at once
  // (measured): permission for the fetch tool, and an entry in the *terminal
  // sandbox's* network allowlist. That is why `read_url(*)` is written only
  // under the explicit "all" below, and what it does to agy's sandbox is handled.
  //
  // "none" (default) keeps today's behavior: autoagy can approve a fetch, but agy
  // still asks for its own permission the first time a domain comes up, and that
  // prompt is the one thing autoagy cannot answer — a hook `allow` does not
  // override it (measured). For someone whose reason for installing this is "stop
  // asking me", that prompt is the most likely one left.
  //
  // "trusted-domains" hands agy the list the user already wrote, so those fetches
  // stop prompting. What it costs depends on whether autoagy's own sandbox is
  // running: with it, nothing, because a confined command has no network at all
  // (`--unshare-net`, and the seccomp filter allows only AF_UNIX sockets) — the
  // allowlist applies to agy's terminal sandbox, which is the one autoagy's
  // rewrite takes the command out of. Without it (macOS, Windows, no bubblewrap,
  // `ownSandbox: "off"`) an unreviewed sandboxed command can reach those specific
  // hosts, which is Codex's network-allowlist model rather than a departure from
  // it. Entries are taken as written minus a leading `*.`, and an entry that
  // still holds a wildcard is skipped rather than widened.
  //
  // "all" writes `read_url(*)`, so no fetch prompts at all; every fetch outside
  // `trustedDomains` is still reviewed, which is how Codex treats a network
  // request. The grant also gives agy's terminal sandbox the whole network, so
  // once it is in the settings autoagy stops counting that sandbox as one
  // (`detectSandbox`): with autoagy's own sandbox running this costs nothing,
  // since commands run there, without network; without it every command off
  // the known read-only list is reviewed. More reviews, never an unreviewed
  // networked command. Meant for Linux with bubblewrap.
  //
  // "auto" (default): "all" where autoagy's own sandbox can run when `setup` is
  // run (Linux, bubblewrap starts, `ownSandbox` not "off"), "none" elsewhere.
  // Decided at setup time because the grant is written then; if bubblewrap
  // stops working later, the rule above still keeps a networked sandbox from
  // counting as one.
  networkGrants: 'auto',
  // Domains browser navigation may reach without review. Empty by default: a
  // navigation runs the page's scripts in a networked, unsandboxed browser, and
  // a local dev server usually serves files the agent may have edited without
  // review, so the fetch allowlist above is not evidence that it is safe to load.
  browserTrustedDomains: [],
  // Extra directories the agent may edit without review.
  writableRoots: [],
  // Extra environment variables a sandboxed command receives, beyond the
  // built-in allowlist (names, or `PREFIX_*` patterns). The sandbox drops the
  // rest, so anything listed here is readable by commands that run without
  // review — treat it as weakening the sandbox.
  ownSandboxEnvPassThrough: [],
  // Extra paths whose modification always needs review.
  protectedPaths: [],
  // Reads of these paths need review (credential probing). `~` is expanded.
  credentialPaths: [
    '~/.ssh/**',
    '~/.aws/**',
    '~/.gnupg/**',
    '~/.azure/**',
    '~/.config/gcloud/**',
    '~/.config/gh/hosts.yml',
    '~/.kube/config',
    '~/.docker/config.json',
    '~/.netrc',
    '~/.git-credentials',
    '~/.npmrc',
    '~/.pypirc',
    '~/.gemini/*/antigravity-oauth-token',
    '~/.gemini/oauth_creds.json',
    '~/.codex/auth.json',
    '~/.claude/.credentials.json',
    '**/.env',
    '**/.env.*',
    '**/*.pem',
    '**/id_rsa*',
    '**/id_ed25519*',
    '**/id_ecdsa*',
  ],
  credentialPathExceptions: ['**/.env.example', '**/.env.sample', '**/.env.template', '**/.env.dist'],
  // Codex execpolicy-style prefix rules:
  // { "pattern": ["git", "push"], "decision": "allow" | "prompt" | "forbidden", "justification": "..." }
  rules: [],
  mcp: {
    // MCP tool names (globs over "server/tool") that are read-only and need no review.
    allow: [],
    // Whether to believe the servers' own tool annotations, which is Codex's rule
    // (`destructive_hint` -> approval, `read_only_hint` -> none, otherwise
    // approval). "ignore" is the default: every MCP call is reviewed unless
    // `allow` names it, which trusts nobody but the user. "trust" uses the
    // snapshot `autoagy mcp-scan` took — the annotation is written by whoever
    // wrote the server, so believing it is a decision, and taking the snapshot is
    // a command the user runs rather than something the hook does behind them.
    annotations: 'ignore',
  },
  tools: {
    // Tool names (globs) that need no review *where autoagy has no rule of its
    // own* — the `unknown-tool` fallback. Nothing else: a name autoagy already
    // classifies keeps its rule, so listing `run_command` here does nothing
    // (`autoagy status` says so). The escape hatch exists because the tool lists
    // are a snapshot of agy 1.2.x and agy updates itself: a tool added next month
    // is reviewed every time it is called, and until now the only way out was
    // editing the plugin, which is a path the policy refuses to let anything
    // write.
    allow: [],
  },
  // What a path that resolved somewhere else between the check and the call costs.
  //
  // agy performs edits and reads itself, outside every sandbox, so autoagy can
  // only resolve the target before the call and again after it. A difference means
  // something replaced part of that path in between.
  //
  // "sticky" (default) is what every version so far did: the whole conversation
  // stops being trusted, every later edit and content read is reviewed, and only
  // `autoagy trust` clears it — because a swapped symlink does not revert just
  // because a new turn started, and only a person can say what is on disk now.
  //
  // "graded" asks *where it landed*. Still inside the workspace (or an
  // agy-managed scratch/artifact/temp directory), and not a credential store, not
  // `.git` or other protected metadata, not autoagy's own files, not the
  // conversation log: the call reached a file the agent could already have named
  // outright, so the turn still stops and the drift is still logged, but the
  // conversation is not marked. Anywhere else — outside the workspace, a
  // credential path, a control surface — is marked exactly as before.
  //
  // What that gives up, stated plainly: a file inside the workspace that some
  // other tool executes later (`.envrc`, `.husky/`, a `Makefile`) is an ordinary
  // workspace file by this test, so a drift onto one of those no longer sticks.
  // `protectedPaths` is the answer to that — those entries are excluded here, and
  // on Linux they are mounted read-only besides.
  pathDrift: 'sticky',
  // Whether executing a notebook needs review.
  //
  // "review" is the default and stays conservative, because what confines a
  // notebook's code is *not established*: agy carries no notebook kernel of its
  // own (no jupyter/kernel symbols in the binary at all) and its only sandbox
  // component sits under the command subsystem, which neither the notebook tool
  // nor its handler references. That is evidence, not proof, so the reason given
  // to the reviewer says as much instead of asserting where the code runs.
  // "allow" is for someone who has decided their notebooks are theirs — it is
  // arbitrary code, so it is the widest switch here.
  notebooks: 'review',
  // Which `command(...)` grant autoagy's own sandbox runs under.
  //
  // "wildcard": `command(*)`, which is what the rewritten call needs to leave
  //   Antigravity's sandbox — and which keeps working after the hook stops
  //   running. That is the fail-open the README opens with.
  // "executor": `command(<$AUTOAGY_HOME/bin/exec-confined.mjs>)`. The rewritten
  //   call redeems a one-shot token the hook wrote into a directory the agent
  //   cannot write, so no hook means no tokens and the grant is worth nothing.
  //   Needs `autoagy setup` to have installed the executor and written that
  //   grant; see tokens.mjs for what the guarantee rests on.
  // "auto" (default): "executor" on Linux, where it was measured end to end on
  //   a real install (design.md, twentieth round); "wildcard" elsewhere. On
  //   Windows the executor cannot run as a program at all, and on macOS nobody
  //   has run it yet — set it there by hand to try it. Resolved by loadConfig,
  //   so the rest of the code only ever sees the two concrete values.
  commandGrant: 'auto',
  // Whether `autoagy setup` also grants Antigravity `read_file(/)`.
  //
  // setup turns off `allowNonWorkspaceAccess`, the one check agy makes at the
  // moment it writes, and that check covers reads too: measured on agy 1.2.7,
  // `view_file /etc/hostname` asked "Reason: outside workspace" after autoagy
  // had allowed it. Without a read grant every read outside the workspace —
  // library sources, system headers — prompts, and in print mode fails. Codex
  // reads anywhere without asking, and autoagy still reviews credential reads
  // itself before agy is asked.
  // "anywhere" (default): `read_file(/)`; writes outside the workspace stay capped.
  // "none": no read grant, so reads outside the workspace prompt, as agy does.
  readGrant: 'anywhere',
  // "review": clicks/typing/JS in the browser are reviewed; "allow": not reviewed.
  browser: 'review',
  // A web search sends the agent's query off the machine, and unlike a command
  // it goes through no sandbox: agy makes the request itself. Codex keeps its
  // hosted web search out of the approval flow and gates it by configuration
  // instead (`web_search` mode, and `allowed_web_search_modes` in a managed
  // requirements.toml), so the default here is the same — allowed. Set
  // "review" to send every search to the reviewer.
  webSearch: 'allow',
  // What environment a command runs with where autoagy has no sandbox of its
  // own. "inherit" is the default and is what Codex does by default too: the
  // command gets the environment the hook inherited, which holds whatever the
  // user exported before starting agy (`shell_environment_policy` has the same
  // default — inherit everything, default excludes off). "scrub" starts it from
  // the allowlist the own sandbox already uses, plus `ownSandboxEnvPassThrough`,
  // by rewriting the command line to run under `env -i`. The own sandbox always
  // scrubs; this switch is for the platforms where it does not exist.
  commandEnv: { mode: 'inherit' },
  circuitBreaker: {
    maxConsecutiveDenials: 3,
    maxRecentDenials: 10,
    window: 50,
  },
  policy: {
    // Path to a Markdown file replacing the default tenant policy (Codex `policy.md`).
    file: null,
    // Extra organization-specific policy text appended to the tenant policy.
    extra: '',
  },
  log: {
    // Also record auto-allowed low-risk actions (verbose).
    allowed: false,
    // Keep full reviewer prompts and responses under logs/reviews/.
    reviews: false,
  },
});

const ENUMS = {
  mode: ['auto', 'ask', 'off'],
  sandbox: ['auto', 'on', 'off'],
  ownSandbox: ['auto', 'on', 'off'],
  'reviewer.backend': ['agy', 'openai', 'none', 'mock'],
  onDenied: ['deny', 'ask'],
  onTimeout: ['deny', 'ask'],
  onError: ['deny', 'ask'],
  browser: ['review', 'allow'],
  notebooks: ['review', 'allow'],
  pathDrift: ['sticky', 'graded'],
  'mcp.annotations': ['ignore', 'trust'],
  networkGrants: ['auto', 'none', 'trusted-domains', 'all'],
  webSearch: ['allow', 'review'],
  'commandEnv.mode': ['inherit', 'scrub'],
  commandGrant: ['auto', 'wildcard', 'executor'],
  readGrant: ['anywhere', 'none'],
};

/** Directory holding config.json, state/ and logs/. */
export function autoagyHome(env = process.env, home = os.homedir()) {
  return env.AUTOAGY_HOME ? path.resolve(env.AUTOAGY_HOME) : path.join(home, '.gemini', 'autoagy');
}

/** Always inside autoagyHome, which agents may not modify. */
export function configPath(env = process.env, home = os.homedir()) {
  return path.join(autoagyHome(env, home), 'config.json');
}

/**
 * A path out of the config, resolved the way it will be used: `~` expanded, and
 * required to be absolute.
 *
 * Every reader of a config-supplied path comes through here, because they
 * drifted apart once and it cost a crash. `policy.file` had three readers — the
 * read itself, the guard that decides whether it may be loaded, and
 * `selfPaths` — and each resolved it its own way: one took the string as
 * written, one resolved it against the cwd, one required an absolute path and
 * fed the null it got for a relative value into `resolveReal`, which threw on
 * every tool call. They cannot disagree about which file they mean now.
 *
 * A relative path returns null rather than being resolved against the cwd. The
 * hook's cwd is the agent's workspace, while `autoagy review` runs wherever the
 * user is — so the same setting would name different files depending on who
 * asked, for a value that decides how the agent is judged. Callers treat a
 * value that is set and unusable as a refusal, not as a default.
 *
 * @param {unknown} value
 * @param {{ home?: string }} [options]
 * @returns {string | null} null when it is unset, not a string, empty, or relative
 */
export function resolveConfigPath(value, { home = os.homedir() } = {}) {
  return toAbsolute(value, null, home);
}

/**
 * Whether a glob out of the config can ever match, given that it is tested
 * against absolute paths.
 *
 * `matchesAnyGlob` compares against an absolute path, so a pattern that names a
 * directory relatively — `.husky/**`, `src/secrets/**` — is anchored to a root
 * it never reaches and matches nothing, silently. The two forms that do work
 * are an absolute pattern and a location-independent one (`**\/.husky/**`,
 * `*.pem`), and the difference is invisible unless someone says so: the setting
 * looks accepted, and the only symptom is a path that was never protected.
 *
 * A pattern with no separator is a basename match anywhere, so it is fine.
 * @param {string} glob already `~`-expanded
 */
export function configGlobCanMatch(glob) {
  if (!glob.includes('/') && !glob.includes('\\')) return true;
  if (path.isAbsolute(glob)) return true;
  return glob.startsWith('**/') || glob.startsWith('**\\');
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/** Deep-merges `override` into `base`; arrays and scalars replace. */
function merge(base, override, warnings, prefix = '') {
  for (const [key, value] of Object.entries(override)) {
    const keyPath = prefix ? `${prefix}.${key}` : key;
    if (!(key in base)) {
      warnings.push(`unknown config key "${keyPath}" ignored`);
      continue;
    }
    const current = base[key];
    if (isPlainObject(current)) {
      if (isPlainObject(value)) merge(current, value, warnings, keyPath);
      else warnings.push(`config key "${keyPath}" must be an object`);
      continue;
    }
    if (Array.isArray(current)) {
      if (Array.isArray(value)) base[key] = value;
      else warnings.push(`config key "${keyPath}" must be an array`);
      continue;
    }
    if (current === null || typeof current === typeof value || value === null) {
      base[key] = value;
    } else {
      warnings.push(`config key "${keyPath}" has the wrong type`);
    }
  }
}

function getPath(obj, keyPath) {
  return keyPath.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}

function setPath(obj, keyPath, value) {
  const keys = keyPath.split('.');
  const last = keys.pop();
  const target = keys.reduce((o, k) => o[k], obj);
  target[last] = value;
}

function validate(config, warnings, home = os.homedir()) {
  // Path-shaped keys are normalised here, once, for the same reason
  // `resolveConfigPath` exists: `writableRoots` had two readers that disagreed
  // — the policy dropped a relative entry and `autoagy setup` resolved it
  // against whatever directory it happened to run in, so a declared root was
  // never honoured while a grant nobody could see accumulated in the Antigravity
  // settings. Resolving before either of them reads it means there is nothing
  // left to disagree about.
  config.writableRoots = (config.writableRoots ?? []).flatMap((p, i) => {
    const resolved = resolveConfigPath(p, { home });
    if (resolved) return [resolved];
    warnings.push(`writableRoots[${i}] (${JSON.stringify(p)}) is not an absolute path; ignored — a relative one would name a different directory depending on where the process runs`);
    return [];
  });
  // Globs are not resolved (a location-independent pattern is the point of
  // them) but they are checked, because one that cannot match fails silently.
  for (const key of ['protectedPaths', 'credentialPaths', 'credentialPathExceptions']) {
    config[key] = (config[key] ?? []).filter((p, i) => {
      if (typeof p !== 'string' || p === '') {
        warnings.push(`${key}[${i}] is not a non-empty string; ignored`);
        return false;
      }
      if (configGlobCanMatch(expandHome(p, home))) return true;
      warnings.push(`${key}[${i}] (${JSON.stringify(p)}) is relative, so it can never match an absolute path; ignored — write it absolute, or prefix it with "**/"`);
      return false;
    });
  }
  // Glob lists over names rather than paths. Unvalidated, a non-string entry
  // reached `globToRegExp(String(glob))` and became a pattern nobody wrote.
  for (const keyPath of ['mcp.allow', 'tools.allow']) {
    const list = getPath(config, keyPath);
    if (!Array.isArray(list)) {
      warnings.push(`config key "${keyPath}" must be an array of name patterns; using default`);
      setPath(config, keyPath, []);
      continue;
    }
    setPath(
      config,
      keyPath,
      list.filter((g, i) => {
        if (typeof g === 'string' && g !== '') return true;
        warnings.push(`${keyPath}[${i}] is not a non-empty string; ignored`);
        return false;
      }),
    );
  }
  for (const [keyPath, allowed] of Object.entries(ENUMS)) {
    const value = getPath(config, keyPath);
    if (!allowed.includes(value)) {
      warnings.push(`config key "${keyPath}" must be one of ${allowed.join(', ')}; using default`);
      setPath(config, keyPath, getPath(DEFAULT_CONFIG, keyPath));
    }
  }
  const r = config.reviewer;
  if (!(Number.isFinite(r.timeoutSec) && r.timeoutSec >= 5 && r.timeoutSec <= 600)) {
    warnings.push('reviewer.timeoutSec must be between 5 and 600; using default');
    r.timeoutSec = DEFAULT_CONFIG.reviewer.timeoutSec;
  }
  if (!(Number.isFinite(r.attemptTimeoutSec) && r.attemptTimeoutSec >= 5 && r.attemptTimeoutSec <= 600)) {
    warnings.push('reviewer.attemptTimeoutSec must be between 5 and 600; using default');
    r.attemptTimeoutSec = DEFAULT_CONFIG.reviewer.attemptTimeoutSec;
  }
  if (!(Number.isInteger(r.maxAttempts) && r.maxAttempts >= 1 && r.maxAttempts <= 5)) {
    r.maxAttempts = DEFAULT_CONFIG.reviewer.maxAttempts;
  }
  config.rules = (config.rules ?? []).filter((rule, i) => {
    const ok =
      isPlainObject(rule) &&
      Array.isArray(rule.pattern) &&
      rule.pattern.length > 0 &&
      rule.pattern.every((t) => typeof t === 'string' || (Array.isArray(t) && t.length > 0 && t.every((a) => typeof a === 'string'))) &&
      ['allow', 'prompt', 'forbidden'].includes(rule.decision);
    if (!ok) warnings.push(`rules[${i}] is invalid (needs pattern: string[] and decision: allow|prompt|forbidden); ignored`);
    return ok;
  });
  if (!Array.isArray(config.ownSandboxEnvPassThrough) || config.ownSandboxEnvPassThrough.some((n) => typeof n !== 'string')) {
    warnings.push('ownSandboxEnvPassThrough must be an array of variable names; ignoring it');
    config.ownSandboxEnvPassThrough = DEFAULT_CONFIG.ownSandboxEnvPassThrough;
  }
  const cb = config.circuitBreaker;
  for (const key of ['maxConsecutiveDenials', 'maxRecentDenials', 'window']) {
    if (!(Number.isInteger(cb[key]) && cb[key] >= 1)) cb[key] = DEFAULT_CONFIG.circuitBreaker[key];
  }
}

/**
 * Loads the effective configuration.
 * @returns {{ config: typeof DEFAULT_CONFIG, warnings: string[], path: string, exists: boolean }}
 */
export function loadConfig({ env = process.env, home = os.homedir(), platform = process.platform } = {}) {
  const warnings = [];
  const config = clone(DEFAULT_CONFIG);
  const file = configPath(env, home);
  let exists = false;
  try {
    const text = fs.readFileSync(file, 'utf8');
    exists = true;
    const parsed = JSON.parse(text);
    if (isPlainObject(parsed)) merge(config, parsed, warnings);
    else warnings.push(`${file} must contain a JSON object`);
  } catch (err) {
    if (err.code !== 'ENOENT') warnings.push(`could not read ${file}: ${err.message}`);
  }
  // The mock backend answers every review the same way, so it must not be
  // reachable by editing config.json alone. It is selected only by that file
  // (the config directory is inside selfPaths, where writes are refused), so
  // requiring an explicit opt-in here means a stray "mock" fails closed into a
  // reviewer that errors rather than one that approves everything.
  if (config.reviewer.backend === 'mock' && env.AUTOAGY_UNSAFE_MOCK_REVIEWER !== '1') {
    warnings.push('reviewer.backend "mock" is only for tests; using the default reviewer instead');
    config.reviewer.backend = DEFAULT_CONFIG.reviewer.backend;
  }
  // No environment variable may weaken the policy: the hook inherits agy's
  // environment, which an escalated command can set for an agy it starts.
  validate(config, warnings, home);
  // "auto" is resolved here, so every reader sees "executor" or "wildcard";
  // `resolved` keeps what was asked for, for `status` to say so.
  const resolved = {};
  if (config.commandGrant === 'auto') {
    resolved.commandGrant = 'auto';
    config.commandGrant = platform === 'linux' ? 'executor' : 'wildcard';
  }
  // The hook runner caps the review deadline so it always answers inside the hook timeout.
  const cap = Number(env.AUTOAGY_REVIEW_TIMEOUT_CAP);
  if (Number.isFinite(cap) && cap > 0) config.reviewer.timeoutSec = Math.min(config.reviewer.timeoutSec, cap);
  return { config, warnings, path: file, exists, resolved };
}

/** The default config file written by `autoagy setup`. */
export function defaultConfigFileText() {
  const { mode, sandbox, ownSandbox, commandGrant, readGrant, onDenied, onTimeout, onError, trustedDomains, browserTrustedDomains, writableRoots, rules, mcp, browser, webSearch, commandEnv } = DEFAULT_CONFIG;
  const { mock, ...reviewer } = DEFAULT_CONFIG.reviewer;
  return `${JSON.stringify({ mode, sandbox, ownSandbox, commandGrant, readGrant, reviewer, onDenied, onTimeout, onError, trustedDomains, browserTrustedDomains, writableRoots, rules, mcp, browser, webSearch, commandEnv }, null, 2)}\n`;
}
