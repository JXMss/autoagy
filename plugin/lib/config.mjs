// autoagy configuration: defaults, loading, validation and env overrides.
//
// The config lives in `$AUTOAGY_HOME/config.json` (default
// `~/.gemini/autoagy/config.json`). Only a global config is read: a
// workspace-level file could be rewritten by the very agent it is meant to
// constrain.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

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
    timeoutSec: 90,
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
  },
  // "review": clicks/typing/JS in the browser are reviewed; "allow": not reviewed.
  browser: 'review',
  // A web search sends the agent's query off the machine, and unlike a command
  // it goes through no sandbox: agy makes the request itself. Codex keeps its
  // hosted web search out of the approval flow and gates it by configuration
  // instead (`web_search` mode, and `allowed_web_search_modes` in a managed
  // requirements.toml), so the default here is the same — allowed. Set
  // "review" to send every search to the reviewer.
  webSearch: 'allow',
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
  webSearch: ['allow', 'review'],
};

/** Directory holding config.json, state/ and logs/. */
export function autoagyHome(env = process.env, home = os.homedir()) {
  return env.AUTOAGY_HOME ? path.resolve(env.AUTOAGY_HOME) : path.join(home, '.gemini', 'autoagy');
}

/** Always inside autoagyHome, which agents may not modify. */
export function configPath(env = process.env, home = os.homedir()) {
  return path.join(autoagyHome(env, home), 'config.json');
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

function validate(config, warnings) {
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
export function loadConfig({ env = process.env, home = os.homedir() } = {}) {
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
  validate(config, warnings);
  // The hook runner caps the review deadline so it always answers inside the hook timeout.
  const cap = Number(env.AUTOAGY_REVIEW_TIMEOUT_CAP);
  if (Number.isFinite(cap) && cap > 0) config.reviewer.timeoutSec = Math.min(config.reviewer.timeoutSec, cap);
  return { config, warnings, path: file, exists };
}

/** The default config file written by `autoagy setup`. */
export function defaultConfigFileText() {
  const { mode, sandbox, ownSandbox, onDenied, onTimeout, onError, trustedDomains, browserTrustedDomains, writableRoots, rules, mcp, browser, webSearch } = DEFAULT_CONFIG;
  const { mock, ...reviewer } = DEFAULT_CONFIG.reviewer;
  return `${JSON.stringify({ mode, sandbox, ownSandbox, reviewer, onDenied, onTimeout, onError, trustedDomains, browserTrustedDomains, writableRoots, rules, mcp, browser, webSearch }, null, 2)}\n`;
}
