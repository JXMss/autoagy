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
  },
  // What to do when the reviewer denies, times out, or fails.
  // "deny" is Codex behavior; "ask" hands the decision to the human instead.
  onDenied: 'deny',
  onTimeout: 'deny',
  onError: 'deny',
  // Domains that web fetches / browser navigation may reach without review.
  trustedDomains: ['localhost', '127.0.0.1', '[::1]'],
  // Extra directories the agent may edit without review.
  writableRoots: [],
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
  'reviewer.backend': ['agy', 'openai', 'none'],
  onDenied: ['deny', 'ask'],
  onTimeout: ['deny', 'ask'],
  onError: ['deny', 'ask'],
  browser: ['review', 'allow'],
};

/** Directory holding config.json, state/ and logs/. */
export function autoagyHome(env = process.env, home = os.homedir()) {
  return env.AUTOAGY_HOME ? path.resolve(env.AUTOAGY_HOME) : path.join(home, '.gemini', 'autoagy');
}

export function configPath(env = process.env, home = os.homedir()) {
  return env.AUTOAGY_CONFIG ? path.resolve(env.AUTOAGY_CONFIG) : path.join(autoagyHome(env, home), 'config.json');
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
  if (env.AUTOAGY_MODE) config.mode = env.AUTOAGY_MODE;
  if (env.AUTOAGY_SANDBOX) config.sandbox = env.AUTOAGY_SANDBOX;
  if (env.AUTOAGY_REVIEWER) config.reviewer.backend = env.AUTOAGY_REVIEWER;
  validate(config, warnings);
  // The hook runner caps the review deadline so it always answers inside the hook timeout.
  const cap = Number(env.AUTOAGY_REVIEW_TIMEOUT_CAP);
  if (Number.isFinite(cap) && cap > 0) config.reviewer.timeoutSec = Math.min(config.reviewer.timeoutSec, cap);
  return { config, warnings, path: file, exists };
}

/** The default config file written by `autoagy setup`. */
export function defaultConfigFileText() {
  const { mode, sandbox, ownSandbox, reviewer, onDenied, onTimeout, onError, trustedDomains, writableRoots, rules, mcp, browser } = DEFAULT_CONFIG;
  return `${JSON.stringify({ mode, sandbox, ownSandbox, reviewer, onDenied, onTimeout, onError, trustedDomains, writableRoots, rules, mcp, browser }, null, 2)}\n`;
}
