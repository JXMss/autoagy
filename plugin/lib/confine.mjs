// autoagy's own terminal sandbox (Linux, bubblewrap).
//
// Antigravity's terminal sandbox leaves `.git` and the conversation logs
// (brain/<id>/.system_generated) writable (measured on agy 1.2.6), so an
// unreviewed sandboxed command could plant a git hook that later runs outside
// the sandbox, or forge the transcript the reviewer trusts. When bubblewrap
// works, autoagy rewrites every sandboxed run_command (PreToolUse `overwrite`)
// into a call that leaves Antigravity's sandbox and runs inside autoagy's own,
// with Codex's workspace-write rules: everything is read-only except the
// workspace roots, temp dirs and Antigravity's artifact/scratch dirs; `.git`,
// agent metadata, autoagy itself and the conversation logs stay read-only;
// credential stores in the home directory are hidden; and there is no network.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolveReal, uniquePaths, isWithin } from './paths.mjs';
import { withLock } from './state.mjs';
import { seccompProgramFile, seccompSupported } from './seccomp.mjs';

// Only root-owned system binaries: a `bwrap` or shell found through PATH could
// be a script the agent planted in a directory it can write.
const BWRAP_CANDIDATES = ['/usr/bin/bwrap', '/usr/local/bin/bwrap', '/bin/bwrap'];
const SHELL_CANDIDATES = ['/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh'];
const PROBE_TTL_MS = 24 * 3600 * 1000;

// No network, a private /proc, /dev and IPC namespace, and nothing outlives the
// sandbox. `--new-session` detaches the terminal (bwrap's TIOCSTI protection).
const BASE_ARGS = [
  '--ro-bind', '/', '/',
  '--dev', '/dev',
  '--proc', '/proc',
  '--unshare-net',
  '--unshare-pid',
  '--unshare-ipc',
  '--new-session',
  '--die-with-parent',
];

// The descriptor `bwrap --seccomp` reads the filter from; the generated command
// opens it with a plain shell redirection.
export const SECCOMP_FD = 3;

// The environment the sandbox starts from. Everything else the hook inherited is
// dropped: the hook runs inside agy's environment, which holds the API keys and
// tokens of whatever the user has exported, and a sandboxed command could read
// them without review and carry them into the transcript. An allowlist rather
// than a denylist, because a denylist's failure mode is a secret leaking.
const ENV_ALLOWLIST = ['PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'TERM', 'TMPDIR', 'TZ', 'PWD', 'LANG'];
const ENV_ALLOWLIST_PREFIXES = ['LC_'];
/** Long values only inflate the tool-call payload the agent sees. */
const ENV_VALUE_MAX = 4096;
const PATH_FALLBACK = '/usr/local/bin:/usr/bin:/bin';

/** True for the names `sandboxEnv` passes through by default. */
export function envNameAllowed(name, passThrough = []) {
  if (ENV_ALLOWLIST.includes(name) || ENV_ALLOWLIST_PREFIXES.some((p) => name.startsWith(p))) return true;
  return passThrough.some((pattern) => (pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern));
}

/**
 * A PATH with the entries an unreviewed command could have written removed. A
 * `node_modules/.bin` or `.venv/bin` entry inside a writable root is a
 * write-then-execute primitive: the agent edits a file, then any command
 * resolves it through PATH.
 */
export function safePath(value, writableRoots = []) {
  const kept = String(value ?? '')
    .split(path.delimiter)
    .filter((entry) => entry && path.isAbsolute(entry))
    .filter((entry) => {
      const real = resolveReal(entry);
      return !writableRoots.some((root) => isWithin(entry, root) || isWithin(real, root));
    });
  return kept.length > 0 ? kept.join(path.delimiter) : PATH_FALLBACK;
}

/**
 * The environment variables the sandboxed command starts with.
 * @param {NodeJS.ProcessEnv} env the hook's environment (not process.env, so tests can inject)
 * @param {{ writableRoots?: string[], passThrough?: string[] }} options
 * @returns {[string, string][]} name/value pairs, in a stable order
 */
export function sandboxEnv(env = {}, { writableRoots = [], passThrough = [] } = {}) {
  const out = [];
  for (const name of Object.keys(env).sort()) {
    if (!envNameAllowed(name, passThrough)) continue;
    const value = String(env[name] ?? '');
    out.push([name, name === 'PATH' ? safePath(value, writableRoots) : value.slice(0, ENV_VALUE_MAX)]);
  }
  return out;
}

function trustedBinary(candidates) {
  for (const file of candidates) {
    try {
      const stat = fs.statSync(file);
      if (stat.isFile() && stat.uid === 0 && (stat.mode & 0o022) === 0) return { file, stat };
    } catch {
      // try the next location
    }
  }
  return null;
}

const shellPath = () => trustedBinary(SHELL_CANDIDATES)?.file ?? '/bin/sh';

/**
 * Whether bubblewrap can create autoagy's sandbox here (it cannot where
 * unprivileged user namespaces are disabled). Cached per binary and kernel.
 * @returns {{ ok: boolean, bwrap?: string, detail: string }}
 */
export function probeBwrap(autoagyHome) {
  const bin = trustedBinary(BWRAP_CANDIDATES);
  if (!bin) return { ok: false, detail: 'bubblewrap (bwrap) is not installed as a root-owned binary in /usr/bin' };
  // Without a filter for this architecture the sandbox would leave Unix sockets
  // reachable, so it is not offered at all and commands are reviewed instead.
  if (!seccompSupported()) return { ok: false, detail: `autoagy has no seccomp filter for ${process.arch}, so its sandbox is unavailable` };
  const key = `${bin.file}:${bin.stat.mtimeMs}:${os.release()}`;
  const cacheFile = path.join(autoagyHome, 'state', 'bwrap-probe.json');
  try {
    const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    // Only the verdict is cached; the binary path is always the one found above.
    if (cached.key === key && Date.now() - cached.time < PROBE_TTL_MS) return { ok: cached.ok === true, bwrap: bin.file, detail: String(cached.detail) };
  } catch {
    // no usable cache
  }
  let res;
  let filterFd;
  try {
    filterFd = fs.openSync(seccompProgramFile(autoagyHome), 'r');
    res = spawnSync(bin.file, [...BASE_ARGS, '--seccomp', String(SECCOMP_FD), '--', shellPath(), '-c', 'true'], {
      encoding: 'utf8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'pipe', filterFd],
    });
  } catch (err) {
    // The filter could not be written next to the rest of autoagy's state.
    return { ok: false, detail: `could not prepare the seccomp filter: ${err.message}` };
  } finally {
    if (filterFd !== undefined) fs.closeSync(filterFd);
  }
  const ok = res.status === 0;
  const detail = ok ? `bubblewrap at ${bin.file}` : `${bin.file} cannot create a sandbox here: ${(res.stderr || res.error?.message || `exit ${res.status}`).trim()}`;
  try {
    fs.mkdirSync(path.dirname(cacheFile), { recursive: true });
    fs.writeFileSync(cacheFile, JSON.stringify({ key, time: Date.now(), ok, detail }));
  } catch {
    // caching is best effort
  }
  return { ok, bwrap: bin.file, detail };
}

// ---------------------------------------------------------------------------
// Self-check. The sandbox relies on agy behavior that is measured, not
// documented, and agy updates itself. PostToolUse sees the arguments that
// actually ran, so every rewritten command is compared with what autoagy
// asked for; one mismatch disables the own sandbox for that agy build.

const checkFile = (autoagyHome) => path.join(autoagyHome, 'state', 'own-sandbox-check.json');

/** Identity of the running agy executable, so a self-check result applies to one build. */
export function hostBuildId(host) {
  if (!host?.pid || process.platform !== 'linux') return 'unknown';
  try {
    const stat = fs.statSync(`/proc/${host.pid}/exe`);
    return `${stat.dev}:${stat.ino}:${stat.size}:${Math.round(stat.mtimeMs)}`;
  } catch {
    return 'unknown';
  }
}

export const commandHash = (commandLine) => crypto.createHash('sha256').update(String(commandLine)).digest('hex').slice(0, 16);

export function readSandboxCheck(autoagyHome) {
  try {
    return JSON.parse(fs.readFileSync(checkFile(autoagyHome), 'utf8'));
  } catch {
    return null;
  }
}

function updateSandboxCheck(autoagyHome, mutate) {
  const file = checkFile(autoagyHome);
  return withLock(file, () => {
    const next = mutate(readSandboxCheck(autoagyHome));
    if (next) fs.writeFileSync(file, JSON.stringify(next, null, 2));
    return next;
  });
}

/** Records one comparison; `problem` is null when agy ran exactly the rewritten command. */
export function recordSandboxCheck(autoagyHome, build, problem) {
  return updateSandboxCheck(autoagyHome, (prev) => {
    const same = prev?.build === build;
    if (problem) return { build, status: 'broken', detail: problem, time: new Date().toISOString(), notified: false };
    // A build that failed once stays disabled; its later commands are no longer rewritten anyway.
    if (same && prev.status === 'broken') return null;
    return { build, status: 'verified', verified: (same ? prev.verified ?? 0 : 0) + 1, time: new Date().toISOString() };
  });
}

/** Returns the broken check once, so the user hears about it a single time per build. */
export function takeSandboxNotice(autoagyHome, build) {
  let notice = null;
  updateSandboxCheck(autoagyHome, (prev) => {
    if (prev?.build !== build || prev.status !== 'broken' || prev.notified) return null;
    notice = prev;
    return { ...prev, notified: true };
  });
  return notice;
}

function commandGrantPresent(appDataDir) {
  if (!appDataDir) return false;
  try {
    const allow = JSON.parse(fs.readFileSync(path.join(appDataDir, 'settings.json'), 'utf8'))?.permissions?.allow;
    return Array.isArray(allow) && allow.includes('command(*)');
  } catch {
    return false;
  }
}

/**
 * Decides whether sandboxed commands run inside autoagy's own sandbox.
 * `required` is set when the config demands it, so callers fail closed if it is unavailable.
 * @returns {{ active: boolean, required: boolean, bwrap?: string, detail: string }}
 */
export function detectOwnSandbox({ config, host, appDataDir, autoagyHome, build = 'unknown', platform = process.platform, probe = probeBwrap }) {
  const mode = config.ownSandbox;
  if (mode === 'off') return { active: false, required: false, detail: 'ownSandbox: "off" in autoagy config' };
  const required = mode === 'on';
  if (platform !== 'linux') return { active: false, required, detail: "autoagy's own sandbox needs Linux with bubblewrap" };
  // The rewritten call leaves Antigravity's sandbox, which Antigravity only
  // allows without prompting under a command grant; without one, every
  // command would prompt, so "auto" stays with Antigravity's sandbox.
  if (!required && !host?.flags?.skipPermissions && !commandGrantPresent(appDataDir)) {
    return { active: false, required, detail: 'command(*) is not granted in the Antigravity CLI settings (see `autoagy setup`)' };
  }
  const check = readSandboxCheck(autoagyHome);
  if (check?.status === 'broken' && check.build === build) {
    return { active: false, required, broken: true, detail: `disabled for this agy build by the self-check: ${check.detail}` };
  }
  const result = probe(autoagyHome);
  if (!result.ok) return { active: false, required, detail: result.detail };
  return { active: true, required, bwrap: result.bwrap, detail: `autoagy's bubblewrap sandbox (${result.bwrap})` };
}

const quote = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** Paths that stay read-only inside the sandbox even when they lie in a writable root. */
export function readOnlyPaths(ctx) {
  const logs = [ctx.artifactDir ? path.join(ctx.artifactDir, '.system_generated') : null, ctx.transcriptPath ? path.dirname(ctx.transcriptPath) : null];
  return [...ctx.workspaceControlPaths, ...ctx.selfPaths, ...logs].filter(Boolean);
}

/**
 * Protected workspace directories (`.git`, `.agents`, ...) that do not exist
 * yet. `--ro-bind-try` skips missing paths, and the workspace root around them
 * is writable, so an unreviewed command could simply create one — and a later
 * tool outside the sandbox would load whatever it put there. Each is given an
 * empty mount point for the duration of the command, which bwrap then mounts a
 * read-only tmpfs on; `removeControlPlaceholders` takes the mount points away
 * again afterwards. Codex stages the same placeholder for the same reason.
 * @returns {string[]} the mount points that were created
 */
export function missingControlPaths(ctx) {
  const out = [];
  for (const p of ctx.workspaceControlPaths) {
    // Only a directory the command could create: one inside a writable root,
    // whose parent is there already.
    if (fs.existsSync(p) || !fs.existsSync(path.dirname(p))) continue;
    if (!ctx.writableRoots.some((root) => isWithin(p, root))) continue;
    out.push(p);
  }
  return out;
}

/** Creates the mount points `missingControlPaths` found, for bwrap to mount over. */
export function controlPlaceholders(ctx) {
  const made = [];
  for (const p of missingControlPaths(ctx)) {
    try {
      fs.mkdirSync(p);
      made.push(p);
    } catch {
      // Left unprotected rather than failing the command; the mount below would
      // fail too, since bwrap cannot mount on a directory that is not there.
    }
  }
  return made;
}

/**
 * Removes the mount points `controlPlaceholders` made, if nothing is in them.
 *
 * A mount point that still has entries is not noise: bwrap mounts its tmpfs
 * inside the child's own mount namespace, so the directory on the host stays
 * empty for the whole command. Anything found in it was written through a path
 * the mount did not cover, which is the only signal that the rewrite failed to
 * protect the directory.
 *
 * @returns {{ removed: string[], dirty: string[] }}
 */
export function removeControlPlaceholders(paths) {
  const removed = [];
  const dirty = [];
  for (const p of paths ?? []) {
    try {
      fs.rmdirSync(p);
      removed.push(p);
    } catch (err) {
      // Gone already, or something the command left in it.
      if (err?.code === 'ENOTEMPTY' || err?.code === 'EEXIST') dirty.push(p);
    }
  }
  return { removed, dirty };
}

/**
 * The command line that runs `commandLine` inside autoagy's sandbox.
 * @param {import('./context.mjs').HookContext} ctx
 * @param {string} commandLine
 * @param {{ placeholders?: string[] }} [options] `placeholders` collects the mount
 *   points created for protected directories that do not exist yet, for cleanup.
 */
export function confinedCommandLine(ctx, commandLine, { placeholders } = {}) {
  const args = [...BASE_ARGS];
  // Later mounts win, so the read-only paths go on top of the writable roots.
  for (const root of ctx.writableRoots) args.push('--bind-try', root, root);
  for (const p of readOnlyPaths(ctx)) args.push('--ro-bind-try', p, p);
  const made = controlPlaceholders(ctx);
  for (const p of made) args.push('--perms', '555', '--tmpfs', p, '--remount-ro', p);
  if (placeholders) placeholders.push(...made);
  // Credential stores in the home directory are hidden behind an empty
  // directory or /dev/null. Mount on real paths: the destination must not be a symlink.
  for (const p of uniquePaths(ctx.credentialLocations.map(resolveReal))) {
    try {
      args.push(...(fs.statSync(p).isDirectory() ? ['--tmpfs', p] : ['--ro-bind', '/dev/null', p]));
    } catch {
      // gone since it was listed
    }
  }
  // --clearenv must come before every --setenv, or it clears the values back
  // out again. The mounts above are already in place; the environment comes last
  // so the ordering is visible in one place.
  args.push('--clearenv');
  // HOME comes from the policy's home, not the inherited one, so the command's
  // `~` is the same `~` the credential list and the protected paths are built
  // from even when the environment says otherwise.
  const env = { ...ctx.env, HOME: ctx.home ?? ctx.env.HOME };
  for (const [name, value] of sandboxEnv(env, { writableRoots: ctx.writableRoots, passThrough: ctx.config.ownSandboxEnvPassThrough })) {
    args.push('--setenv', name, value);
  }
  const filter = seccompProgramFile(ctx.autoagyHome);
  const call = [ctx.ownSandbox.bwrap, ...args, '--seccomp', String(SECCOMP_FD), '--', shellPath(), '-c', commandLine];
  // The filter is handed to bwrap as an inherited descriptor, opened by the
  // shell that execs it; autoagy's own directory is read-only in the sandbox, so
  // the file it points at cannot be swapped while the command runs.
  return `exec ${call.map(quote).join(' ')} ${SECCOMP_FD}<${quote(filter)}`;
}
