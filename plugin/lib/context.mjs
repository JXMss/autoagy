// Everything the policy needs to know about where a hook call comes from:
// the Antigravity product and app-data directory, the host process (for the
// CLI: the `agy` process, whose cwd is the user's workspace), workspace and
// writable roots, protected paths, and whether the terminal sandbox confines
// sandboxed commands.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { autoagyHome } from './config.mjs';
import { toAbsolute, uniquePaths, expandHome, expandAnchoredGlob, resolveReal, findExecutable } from './paths.mjs';
import { detectOwnSandbox, probeBwrap, hostBuildId, envBinaryPath, envScrubDisabled } from './confine.mjs';

export const PLUGIN_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Workspace-level directories that hold agent configuration, VCS metadata or
// other agents' settings. Codex keeps `.git`, `.agents` and `.codex` read-only;
// Antigravity also reads `.agent`, `_agents`, `_agent` and `.gemini`.
export const PROTECTED_WORKSPACE_DIRS = ['.git', '.agents', '.agent', '_agents', '_agent', '.gemini', '.codex', '.claude'];

// Bounds for the search for nested repositories (see HookContext.nestedGitPaths).
// A workspace can hold a node_modules tree with tens of thousands of directories,
// and this runs in a hook that has to answer inside its budget, so the walk is
// bounded on every axis and skips the directories that are large by convention.
const NESTED_SCAN_MAX_DEPTH = 5;
const NESTED_SCAN_MAX_DIRS = 1500;
const NESTED_SCAN_SKIP = new Set([
  'node_modules', 'target', 'dist', 'build', 'out', 'vendor', 'venv', '.venv', 'env',
  '__pycache__', '.cache', '.next', '.nuxt', '.tox', '.gradle', '.mypy_cache', '.pytest_cache',
]);

/**
 * `.git` entries below `root` (not the one at `root` itself, which the protected
 * workspace directories already cover): submodules and nested repositories.
 *
 * Breadth-first so the shallow ones — where a submodule actually lives — are
 * found before the budget runs out.
 * @param {string} root
 * @returns {string[]}
 */
export function findNestedGitPaths(root) {
  const out = [];
  const queue = [[root, 0]];
  let visited = 0;
  while (queue.length > 0) {
    const [dir, depth] = queue.shift();
    if (visited++ >= NESTED_SCAN_MAX_DIRS) break;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const child = path.join(dir, entry.name);
      if (entry.name === '.git') {
        // A submodule's `.git` is a file pointing into the superproject's
        // `.git/modules`, which is read-only already; binding the file keeps the
        // pointer itself from being redirected.
        if (dir !== root) out.push(child);
        continue;
      }
      if (!entry.isDirectory() || depth + 1 > NESTED_SCAN_MAX_DEPTH) continue;
      if (NESTED_SCAN_SKIP.has(entry.name)) continue;
      queue.push([child, depth + 1]);
    }
  }
  return out;
}

/** Derives the product app-data dir (e.g. ~/.gemini/antigravity-cli) from hook paths. */
export function appDataDirFromPayload(payload) {
  for (const candidate of [payload?.artifactDirectoryPath, payload?.transcriptPath]) {
    if (typeof candidate !== 'string' || candidate === '') continue;
    const normalized = candidate.replace(/\\/g, '/');
    const idx = normalized.lastIndexOf('/brain/');
    if (idx > 0) return path.normalize(candidate.slice(0, idx));
  }
  return null;
}

/** Reads pid, ppid, argv and cwd of a process (Linux via /proc, macOS via ps/lsof). */
export function readProcessInfo(pid) {
  if (!Number.isInteger(pid) || pid <= 1) return null;
  if (process.platform === 'linux') {
    try {
      const argv = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter((a, i, all) => a !== '' || i < all.length - 1);
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
      let cwd = null;
      try {
        cwd = fs.readlinkSync(`/proc/${pid}/cwd`);
      } catch {
        cwd = null;
      }
      return { pid, ppid, argv, cwd };
    } catch {
      return null;
    }
  }
  if (process.platform === 'darwin') {
    try {
      const out = execFileSync('ps', ['-o', 'ppid=', '-o', 'command=', '-p', String(pid)], { encoding: 'utf8', timeout: 2000 }).trim();
      const match = /^(\d+)\s+(.*)$/.exec(out);
      if (!match) return null;
      let cwd = null;
      try {
        const lsof = execFileSync('lsof', ['-a', '-p', String(pid), '-d', 'cwd', '-Fn'], { encoding: 'utf8', timeout: 2000 });
        cwd = lsof.split('\n').find((l) => l.startsWith('n'))?.slice(1) ?? null;
      } catch {
        cwd = null;
      }
      return { pid, ppid: Number(match[1]), argv: match[2].split(/\s+/), cwd };
    } catch {
      return null;
    }
  }
  return null;
}

/** Recognizes the Antigravity CLI / language server among a hook's ancestors. */
export function findHostProcess(startPid = process.ppid, maxDepth = 8) {
  let pid = startPid;
  for (let i = 0; i < maxDepth && pid > 1; i++) {
    const info = readProcessInfo(pid);
    if (!info) return null;
    const exe = path.basename(info.argv[0] ?? '');
    if (/^agy(\.exe)?$/i.test(exe)) return { ...info, kind: 'cli', flags: parseHostFlags(info.argv) };
    if (/language_server|antigravity/i.test(exe)) return { ...info, kind: 'app', flags: parseHostFlags(info.argv) };
    pid = info.ppid;
  }
  return null;
}

/** The file a process runs (Linux: /proc/<pid>/exe; macOS: an absolute argv[0]), or null. */
export function processExecutable(info) {
  if (!info?.pid) return null;
  if (process.platform === 'linux') {
    try {
      return fs.realpathSync(`/proc/${info.pid}/exe`);
    } catch {
      return null;
    }
  }
  const argv0 = info.argv?.[0];
  return typeof argv0 === 'string' && path.isAbsolute(argv0) ? argv0 : null;
}

/** Extracts the permission-relevant flags of an `agy` invocation. */
export function parseHostFlags(argv) {
  const flags = { skipPermissions: false, sandbox: false, addDirs: [], mode: null, agent: null };
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i].replace(/^-{1,2}/, '--');
    const [name, inline] = arg.includes('=') ? [arg.slice(0, arg.indexOf('=')), arg.slice(arg.indexOf('=') + 1)] : [arg, undefined];
    const value = () => (inline !== undefined ? inline : argv[++i]);
    switch (name) {
      case '--dangerously-skip-permissions':
        flags.skipPermissions = inline === undefined || inline === 'true';
        break;
      case '--sandbox':
        flags.sandbox = inline === undefined || inline === 'true';
        break;
      case '--add-dir': {
        const dir = value();
        if (dir) flags.addDirs.push(dir);
        break;
      }
      case '--mode':
        flags.mode = value() ?? null;
        break;
      case '--agent':
        flags.agent = value() ?? null;
        break;
      default:
        break;
    }
  }
  return flags;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

/** Platforms where a hook can read the host process's arguments at all. */
export const HOST_INSPECTABLE_PLATFORMS = ['linux', 'darwin'];

/**
 * Decides whether sandboxed run_command calls are confined by a terminal sandbox:
 * autoagy's own when active, otherwise Antigravity's.
 * @returns {{ active: boolean, source: string, detail: string }}
 */
export function detectSandbox({ config, host, appDataDir, own, platform = process.platform }) {
  if (own?.active) {
    return { active: true, source: 'autoagy', detail: `${own.detail}; workspace and temp dirs writable, .git and agent metadata read-only, no network` };
  }
  if (own?.required) return { active: false, source: 'autoagy', detail: `ownSandbox is "on" but unavailable: ${own.detail}` };
  if (config.sandbox === 'on') return { active: true, source: 'config', detail: 'sandbox: "on" in autoagy config' };
  if (config.sandbox === 'off') return { active: false, source: 'config', detail: 'sandbox: "off" in autoagy config' };
  if (host?.flags?.skipPermissions) {
    return { active: false, source: 'flag', detail: 'agy was started with --dangerously-skip-permissions (terminal sandbox bypassed)' };
  }
  if (host?.flags?.sandbox) return { active: true, source: 'flag', detail: 'agy was started with --sandbox' };
  const settings = appDataDir ? readJson(path.join(appDataDir, 'settings.json')) : null;
  // The settings file records what the CLI was configured to do, not what it is
  // doing. It is the only signal the IDE path can offer, so it is used — but
  // only where the process arguments could have been read to confirm or
  // contradict it. Where they cannot (Windows), trusting it would report a
  // sandbox that --dangerously-skip-permissions has already defeated, since
  // autoagy setup writes the very values the file is checked for.
  if (settings && HOST_INSPECTABLE_PLATFORMS.includes(platform)) {
    const enabled = settings.enableTerminalSandbox === true;
    const permission = settings.toolPermission ?? 'proceed-in-sandbox';
    const detail = `enableTerminalSandbox=${settings.enableTerminalSandbox ?? '(unset)'}, toolPermission=${permission}`;
    return { active: enabled && permission === 'proceed-in-sandbox', source: 'settings', detail };
  }
  if (!HOST_INSPECTABLE_PLATFORMS.includes(platform)) {
    return {
      active: false,
      source: 'platform',
      detail: `autoagy cannot read the agy process arguments on ${platform}, so it cannot tell whether the terminal sandbox is really in force; only known read-only commands run unreviewed`,
    };
  }
  return { active: false, source: 'unknown', detail: 'could not determine the terminal sandbox state; assuming commands run unsandboxed' };
}

/** Lazily computed view of a hook invocation. */
export class HookContext {
  /**
   * @param {object} payload hook stdin payload
   * @param {{ config: object, env?: NodeJS.ProcessEnv, home?: string, pluginDir?: string, host?: object | null, tempRoots?: string[], bwrapProbe?: Function }} options
   */
  constructor(payload, { config, env = process.env, home = os.homedir(), pluginDir = PLUGIN_DIR, host, tempRoots, bwrapProbe = probeBwrap } = {}) {
    this.payload = payload ?? {};
    this.config = config;
    this.env = env;
    this.home = home;
    this.pluginDir = pluginDir;
    this.autoagyHome = autoagyHome(env, home);
    this.toolName = typeof this.payload.toolCall?.name === 'string' ? this.payload.toolCall.name : '';
    const args = this.payload.toolCall?.args;
    this.args = args && typeof args === 'object' && !Array.isArray(args) ? args : {};
    this.conversationId = this.payload.conversationId || env.ANTIGRAVITY_CONVERSATION_ID || 'unknown';
    this.stepIdx = this.payload.stepIdx ?? null;
    this.transcriptPath = this.payload.transcriptPath || null;
    this.artifactDir = this.payload.artifactDirectoryPath ? path.normalize(this.payload.artifactDirectoryPath) : null;
    this.appDataDir = appDataDirFromPayload(this.payload);
    this.product = this.appDataDir ? path.basename(this.appDataDir) : null;
    this.role = env.AUTOAGY_ROLE === 'guardian' ? 'guardian' : 'agent';
    // Codex's workspace-write sandbox also lets the agent write /tmp and $TMPDIR.
    this.tempRoots = tempRoots ?? [os.tmpdir(), process.platform === 'win32' ? null : '/tmp', env.TMPDIR ? path.resolve(env.TMPDIR) : null];
    this._host = host;
    this._bwrapProbe = bwrapProbe;
    this._memo = new Map();
  }

  memo(key, compute) {
    if (!this._memo.has(key)) this._memo.set(key, compute());
    return this._memo.get(key);
  }

  get host() {
    if (this._host === undefined) this._host = findHostProcess();
    return this._host;
  }

  /** Directories the user opened as the workspace. */
  get workspaceRoots() {
    return this.memo('workspaceRoots', () => {
      const roots = [];
      for (const p of Array.isArray(this.payload.workspacePaths) ? this.payload.workspacePaths : []) {
        roots.push(toAbsolute(p, null, this.home));
      }
      const host = this.host;
      if (host?.kind === 'cli' && host.cwd) {
        roots.push(host.cwd);
        for (const dir of host.flags.addDirs) roots.push(toAbsolute(dir, host.cwd, this.home));
      }
      return uniquePaths(roots);
    });
  }

  /** Workspace roots plus the places Antigravity itself expects the agent to write. */
  get writableRoots() {
    return this.memo('writableRoots', () => {
      const extra = [
        this.artifactDir,
        this.appDataDir ? path.join(this.appDataDir, 'scratch') : null,
        ...this.tempRoots,
        ...(this.config.writableRoots ?? []).map((p) => toAbsolute(p, null, this.home)),
      ];
      return uniquePaths([...this.workspaceRoots, ...extra]);
    });
  }

  /** Antigravity-managed writable locations outside the workspace (artifacts, scratch, temp). */
  get managedWritableRoots() {
    return this.memo('managedWritableRoots', () => {
      const roots = new Set(this.workspaceRoots);
      return this.writableRoots.filter((p) => !roots.has(p));
    });
  }

  /** Paths the agent must never modify: autoagy itself, and the agy binaries that run its hooks and reviews. */
  get selfPaths() {
    return this.memo('selfPaths', () => {
      const reviewer = this.config.reviewer?.backend === 'agy' ? this.reviewerExecutable : null;
      return uniquePaths([
        this.autoagyHome,
        this.pluginDir,
        this.appDataDir ? path.join(this.appDataDir, 'plugin_data', 'autoagy') : null,
        this.hostExecutable,
        reviewer,
        reviewer ? resolveReal(reviewer) : null,
        this.hookInterpreter,
        // The interpreter this hook is running under right now. hooks.json
        // names it too (see hookInterpreter), but that file is unpinned until
        // `autoagy setup` runs, and a hook started by something else than the
        // pinned command — the test suite, `autoagy review` — still runs under
        // this one.
        process.execPath,
      ]);
    });
  }

  /**
   * The Node interpreter the pinned hook commands run, as `autoagy setup` wrote
   * it into hooks.json.
   *
   * hooks.json itself is in selfPaths, but the file it names is not, and that
   * file is the code every hook runs: replacing it replaces the review. Node is
   * often installed by a version manager under `~` (`~/.nvm`, `~/.volta`,
   * `~/.local/share/fnm`), so when the workspace root is `~` — starting `agy`
   * in the home directory does that — it lands inside a writable root and a
   * plain edit would otherwise be auto-approved.
   * @returns {string | null}
   */
  get hookInterpreter() {
    return this.memo('hookInterpreter', () => {
      const hooks = readJson(path.join(this.pluginDir, 'hooks.json'));
      let found = null;
      const visit = (value) => {
        if (found || !value || typeof value !== 'object') return;
        if (Array.isArray(value)) {
          for (const item of value) visit(item);
          return;
        }
        if (typeof value.command === 'string') {
          const text = value.command.trim();
          const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(text);
          let token = quoted ? quoted[1] : text.split(/\s+/)[0];
          if (quoted) {
            try {
              token = JSON.parse(`"${quoted[1]}"`);
            } catch {
              // keep the raw contents
            }
          }
          // A bare `node` (the source tree before setup pins it) is a PATH
          // lookup, not a path: only an absolute one can be protected.
          if (token && path.isAbsolute(token)) found = token;
        }
        for (const item of Object.values(value)) visit(item);
      };
      visit(hooks);
      return found;
    });
  }

  /** The agy CLI executable running this conversation (it loads the hooks). */
  get hostExecutable() {
    return this.memo('hostExecutable', () => (this.host?.kind === 'cli' ? processExecutable(this.host) : null));
  }

  /**
   * The binary the agy reviewer runs: `reviewer.agy.command` when it is an
   * absolute path, else the agy CLI running this conversation, else the
   * command looked up on PATH outside the directories agents can write. Never
   * a plain PATH lookup: a PATH entry inside the workspace (a virtualenv's
   * bin, node_modules/.bin) would let an unreviewed edit replace the reviewer.
   * @returns {string | null}
   */
  get reviewerExecutable() {
    return this.memo('reviewerExecutable', () => {
      const command = this.config.reviewer?.agy?.command;
      if (typeof command !== 'string' || command.trim() === '') return null;
      if (path.isAbsolute(command)) return command;
      if (/[\\/]/.test(command)) return null;
      if (/^agy(\.exe)?$/i.test(command) && this.hostExecutable) return this.hostExecutable;
      return findExecutable(command, this.env.PATH, this.writableRoots);
    });
  }

  /** Agent configuration in the user's home; Antigravity's own artifact dirs live inside ~/.gemini. */
  get homeControlPaths() {
    return this.memo('homeControlPaths', () =>
      uniquePaths([path.join(this.home, '.gemini'), path.join(this.home, '.codex'), path.join(this.home, '.claude')]),
    );
  }

  /**
   * `.git` of every repository nested inside the workspace (submodules, vendored
   * checkouts). autoagy's own sandbox keeps these read-only for the same reason
   * it keeps the top-level one read-only: a command that plants a hook there has
   * it executed by the next `git` that runs outside the sandbox, and a git
   * command that writes has to leave the sandbox to work at all. The edit tools
   * already refuse any path with a `.git` component (`classifyWriteTarget`), so
   * without this the command side would be the weaker of the two.
   *
   * Best effort, and deliberately so: the walk is bounded, so a repository
   * buried deeper than `NESTED_SCAN_MAX_DEPTH` or behind a skipped directory is
   * not found. Nothing depends on the list being complete — a missing entry
   * leaves that `.git` as writable as it was before this existed.
   */
  get nestedGitPaths() {
    return this.memo('nestedGitPaths', () => uniquePaths(this.workspaceRoots.flatMap((root) => findNestedGitPaths(root))));
  }

  /**
   * Whether a command that is not asking to escalate gets an environment built
   * from the sandbox allowlist rather than the one agy was started with.
   *
   * Two mechanisms do it and they are the only two: the own sandbox's
   * `--clearenv`, and the `commandEnv: "scrub"` rewrite into `env -i`. The
   * second needs a trusted `env` to exist and its own self-check to still hold,
   * so both are asked here rather than trusting the setting alone. Escalated
   * commands are out of scope: they are reviewed as full-privilege actions, and
   * the environment is part of what that means.
   */
  get envScrubbed() {
    return this.memo('envScrubbed', () => {
      if (this.ownSandbox.active) return true;
      if (this.config.commandEnv?.mode !== 'scrub') return false;
      if (!envBinaryPath()) return false;
      return !envScrubDisabled(this.autoagyHome, this.hostBuild);
    });
  }

  /** Protected metadata directories at the top of each workspace root. */
  get workspaceControlPaths() {
    return this.memo('workspaceControlPaths', () => {
      const paths = [];
      for (const root of this.workspaceRoots) {
        for (const dir of PROTECTED_WORKSPACE_DIRS) paths.push(path.join(root, dir));
      }
      return uniquePaths(paths);
    });
  }

  /**
   * Existing credential stores named by the anchored `credentialPaths` globs
   * (`~/.ssh/**`, `~/.netrc`, ...), with symlinks resolved as well. Patterns
   * without a fixed location (`**\/.env`) cannot be listed and are left out.
   */
  get credentialLocations() {
    return this.memo('credentialLocations', () => {
      const out = [];
      for (const glob of this.config.credentialPaths ?? []) {
        if (typeof glob !== 'string') continue;
        const expanded = expandHome(glob, this.home);
        if (!path.isAbsolute(expanded)) continue;
        for (const p of expandAnchoredGlob(expanded)) out.push(p, resolveReal(p));
      }
      return uniquePaths(out);
    });
  }

  get protectedGlobs() {
    return (this.config.protectedPaths ?? []).map((p) => expandHome(p, this.home));
  }

  /** The running agy executable, which self-check results are tied to. */
  get hostBuild() {
    return this.memo('hostBuild', () => hostBuildId(this.host));
  }

  /** autoagy's own bubblewrap sandbox (see confine.mjs). */
  get ownSandbox() {
    return this.memo('ownSandbox', () =>
      detectOwnSandbox({
        config: this.config,
        host: this.host,
        appDataDir: this.appDataDir,
        autoagyHome: this.autoagyHome,
        build: this.hostBuild,
        probe: this._bwrapProbe,
      }),
    );
  }

  get sandbox() {
    return this.memo('sandbox', () => detectSandbox({ config: this.config, host: this.host, appDataDir: this.appDataDir, own: this.ownSandbox }));
  }

  /** Base directory for resolving relative paths in tool arguments. */
  get baseDir() {
    return this.workspaceRoots[0] ?? this.host?.cwd ?? null;
  }
}
