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
import { toAbsolute, uniquePaths, expandHome } from './paths.mjs';
import { detectOwnSandbox, probeBwrap } from './confine.mjs';

export const PLUGIN_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Workspace-level directories that hold agent configuration, VCS metadata or
// other agents' settings. Codex keeps `.git`, `.agents` and `.codex` read-only;
// Antigravity also reads `.agent`, `_agents`, `_agent` and `.gemini`.
export const PROTECTED_WORKSPACE_DIRS = ['.git', '.agents', '.agent', '_agents', '_agent', '.gemini', '.codex', '.claude'];

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

/**
 * Decides whether sandboxed run_command calls are confined by a terminal sandbox:
 * autoagy's own when active, otherwise Antigravity's.
 * @returns {{ active: boolean, source: string, detail: string }}
 */
export function detectSandbox({ config, host, appDataDir, own }) {
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
  if (settings) {
    const enabled = settings.enableTerminalSandbox === true;
    const permission = settings.toolPermission ?? 'proceed-in-sandbox';
    const detail = `enableTerminalSandbox=${settings.enableTerminalSandbox ?? '(unset)'}, toolPermission=${permission}`;
    return { active: enabled && permission === 'proceed-in-sandbox', source: 'settings', detail };
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

  /** Paths the agent must never modify: autoagy itself. */
  get selfPaths() {
    return this.memo('selfPaths', () =>
      uniquePaths([
        this.autoagyHome,
        this.pluginDir,
        this.appDataDir ? path.join(this.appDataDir, 'plugin_data', 'autoagy') : null,
      ]),
    );
  }

  /** Agent configuration in the user's home; Antigravity's own artifact dirs live inside ~/.gemini. */
  get homeControlPaths() {
    return this.memo('homeControlPaths', () =>
      uniquePaths([path.join(this.home, '.gemini'), path.join(this.home, '.codex'), path.join(this.home, '.claude')]),
    );
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

  get protectedGlobs() {
    return (this.config.protectedPaths ?? []).map((p) => expandHome(p, this.home));
  }

  /** autoagy's own bubblewrap sandbox (see confine.mjs). */
  get ownSandbox() {
    return this.memo('ownSandbox', () =>
      detectOwnSandbox({ config: this.config, host: this.host, appDataDir: this.appDataDir, autoagyHome: this.autoagyHome, probe: this._bwrapProbe }),
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
