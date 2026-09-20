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
import { executorPath, executorInstalled } from './tokens.mjs';

// Only root-owned system binaries: a `bwrap` or shell found through PATH could
// be a script the agent planted in a directory it can write.
const BWRAP_CANDIDATES = ['/usr/bin/bwrap', '/usr/local/bin/bwrap', '/bin/bwrap'];
const SHELL_CANDIDATES = ['/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh'];
const FLOCK_CANDIDATES = ['/usr/bin/flock', '/bin/flock', '/usr/local/bin/flock'];
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

/** True for the names `sandboxEnv` passes through by default. */
export function envNameAllowed(name, passThrough = []) {
  if (ENV_ALLOWLIST.includes(name) || ENV_ALLOWLIST_PREFIXES.some((p) => name.startsWith(p))) return true;
  return passThrough.some((pattern) => (pattern.endsWith('*') ? name.startsWith(pattern.slice(0, -1)) : name === pattern));
}

/**
 * The environment variables the sandboxed command starts with.
 *
 * PATH is passed through unchanged. Filtering out entries inside a writable
 * root buys nothing here: the workspace is bound read-write with exec
 * unrestricted, so a sandboxed command can run any file in it by path with or
 * without a PATH entry — while dropping those entries breaks ordinary
 * toolchains (.venv/bin, node_modules/.bin) or picks the wrong interpreter.
 * The place a workspace PATH entry is actually dangerous is a command that runs
 * *outside* this sandbox, and that is not this function.
 *
 * @param {NodeJS.ProcessEnv} env the hook's environment (not process.env, so tests can inject)
 * @param {{ passThrough?: string[] }} options
 * @returns {[string, string][]} name/value pairs, in a stable order
 */
export function sandboxEnv(env = {}, { passThrough = [] } = {}) {
  const out = [];
  for (const name of Object.keys(env).sort()) {
    if (!envNameAllowed(name, passThrough)) continue;
    out.push([name, String(env[name] ?? '').slice(0, ENV_VALUE_MAX)]);
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

/** `flock`, when a root-owned one exists — autoagy never looks it up in PATH. */
export const flockPath = () => trustedBinary(FLOCK_CANDIDATES)?.file ?? null;

/**
 * The lock file that records whether any of a workspace's sandboxed commands is
 * still running.
 *
 * autoagy never starts bwrap, so it holds no pid and cannot ask the kernel which
 * commands are alive. What it can do is have every rewritten command line hold a
 * shared lock for as long as bwrap runs, and take the exclusive lock itself when
 * it wants to know that nothing is running. The lock lives under autoagy's own
 * home, which the sandbox mounts read-only: a lock file inside a writable root
 * could be unlinked and recreated by the command, and the probe would then
 * report "idle" while a command was still running — the one direction that must
 * not be wrong.
 *
 * @returns {string|null}
 */
export function workspaceLockFile(ctx) {
  // The workspace roots, and only those: the writable-root fallback would pull
  // in this conversation's artifact and temp directories, so two conversations
  // in the same workspace would compute different names and never share the
  // lock — the property the whole scheme rests on. With no workspace to name,
  // say so and let the caller fall back rather than invent an identity.
  const roots = (ctx.workspaceRoots.length > 0 ? ctx.workspaceRoots : [ctx.host?.cwd]).filter(Boolean).map(resolveReal).sort();
  if (roots.length === 0) return null;
  const file = path.join(ctx.autoagyHome, 'state', `ws-${crypto.createHash('sha1').update(roots.join('\n')).digest('hex').slice(0, 16)}.lock`);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    // flock needs the file to exist; opening it read-only in the sandbox is
    // enough for both the shared and the exclusive lock.
    fs.closeSync(fs.openSync(file, 'a'));
  } catch {
    return null;
  }
  return file;
}

/**
 * Whether no sandboxed command is currently running, from the lock that every
 * rewritten command line holds while bwrap runs.
 *
 * @returns {boolean|null} true when nothing holds it, false when something does,
 *   null when this host cannot tell (no trusted `flock`, or no lock file) —
 *   callers must then fall back to guessing rather than assume it is idle.
 */
export function lockQuiescent(ctx, { flock = flockPath(), lockFile = null } = {}) {
  const file = lockFile ?? workspaceLockFile(ctx);
  if (!flock || !file) return null;
  const res = spawnSync(flock, ['-n', '-x', file, '-c', 'true'], { encoding: 'utf8', timeout: 5000 });
  if (res.error || res.status === null) return null;
  return res.status === 0;
}

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
// asked for; one mismatch disables that rewrite for that agy build. The
// env-scrub rewrite (no own sandbox) is measured the same way and keeps its
// own record: the two fail independently.

const CHECK_FILES = { sandbox: 'own-sandbox-check.json', envScrub: 'command-env-check.json' };
const checkFile = (autoagyHome, kind = 'sandbox') => path.join(autoagyHome, 'state', CHECK_FILES[kind] ?? CHECK_FILES.sandbox);

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

export function readSandboxCheck(autoagyHome, kind = 'sandbox') {
  try {
    return JSON.parse(fs.readFileSync(checkFile(autoagyHome, kind), 'utf8'));
  } catch {
    return null;
  }
}

function updateSandboxCheck(autoagyHome, mutate, kind = 'sandbox') {
  const file = checkFile(autoagyHome, kind);
  return withLock(file, () => {
    const next = mutate(readSandboxCheck(autoagyHome, kind));
    if (next) fs.writeFileSync(file, JSON.stringify(next, null, 2));
    return next;
  });
}

/** Records one comparison; `problem` is null when agy ran exactly the rewritten command. */
export function recordSandboxCheck(autoagyHome, build, problem, kind = 'sandbox') {
  return updateSandboxCheck(
    autoagyHome,
    (prev) => {
      const same = prev?.build === build;
      if (problem) return { build, status: 'broken', detail: problem, time: new Date().toISOString(), notified: false };
      // A build that failed once stays disabled; its later commands are no longer rewritten anyway.
      if (same && prev.status === 'broken') return null;
      return { build, status: 'verified', verified: (same ? prev.verified ?? 0 : 0) + 1, time: new Date().toISOString() };
    },
    kind,
  );
}

/** Returns the broken check once, so the user hears about it a single time per build. */
export function takeSandboxNotice(autoagyHome, build, kind = 'sandbox') {
  let notice = null;
  updateSandboxCheck(
    autoagyHome,
    (prev) => {
      if (prev?.build !== build || prev.status !== 'broken' || prev.notified) return null;
      notice = prev;
      return { ...prev, notified: true };
    },
    kind,
  );
  return notice;
}

/** True when the env-scrub rewrite failed its self-check for this agy build. */
export function envScrubDisabled(autoagyHome, build) {
  const check = readSandboxCheck(autoagyHome, 'envScrub');
  return Boolean(check && check.status === 'broken' && check.build === build);
}

/**
 * The `command(...)` grant the rewritten call will need, which depends on how
 * `commandGrant` is set: the wildcard, or the one program that redeems tokens.
 */
export function wantedCommandGrant(config, autoagyHome) {
  return config.commandGrant === 'executor' ? `command(${executorPath(autoagyHome)})` : 'command(*)';
}

function commandGrantPresent(appDataDir, wanted) {
  if (!appDataDir) return false;
  try {
    const allow = JSON.parse(fs.readFileSync(path.join(appDataDir, 'settings.json'), 'utf8'))?.permissions?.allow;
    return Array.isArray(allow) && allow.includes(wanted);
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
  // In executor mode the rewritten call redeems a token, so the program that
  // redeems it has to be there. Failing here rather than falling back to the
  // wildcard rewrite is the point: that rewrite needs a grant this
  // configuration deliberately does not have, and agy would refuse it with an
  // error that says nothing about why.
  if (config.commandGrant === 'executor' && !executorInstalled(autoagyHome)) {
    return { active: false, required, detail: 'commandGrant is "executor" but bin/exec-confined.mjs is not installed (run `autoagy setup`)' };
  }
  // The rewritten call leaves Antigravity's sandbox, which Antigravity only
  // allows without prompting under a command grant; without one, every
  // command would prompt, so "auto" stays with Antigravity's sandbox.
  const wanted = wantedCommandGrant(config, autoagyHome);
  if (!required && !host?.flags?.skipPermissions && !commandGrantPresent(appDataDir, wanted)) {
    return { active: false, required, detail: `${wanted} is not granted in the Antigravity CLI settings (see \`autoagy setup\`)` };
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

/** The absolute `env` a scrubbed command line runs under, or null when there is none. */
export const envBinaryPath = () => trustedBinary(['/usr/bin/env', '/bin/env'])?.file ?? null;

/**
 * The command line with a scrubbed environment: `env -i NAME=VALUE … sh -c '<command>'`.
 *
 * Where autoagy has no sandbox of its own, this is the one part of the
 * `--clearenv` idea that still applies: agy applies an `overwrite` that leaves
 * `BypassSandbox` unset (measured, design.md), so the rewritten command runs
 * inside Antigravity's sandbox with an environment built from the same
 * allowlist. The inner command goes through a shell because the original line is
 * a shell command — pipes, redirections and all — and it was going to be run by
 * one anyway.
 *
 * The values are written into the command line verbatim, which the agent can
 * read, so `ownSandboxEnvPassThrough` must not name a secret. Same caveat as the
 * sandbox's `--setenv`.
 *
 * @returns {string | null} null when no trusted `env` can be found
 */
export function scrubbedCommandLine(ctx, commandLine) {
  const env = envBinaryPath();
  if (!env) return null;
  const parts = [quote(env), '-i'];
  // HOME comes from the policy's home, not the inherited one, for the same
  // reason the sandbox does it: the command's `~` has to be the `~` the
  // credential list and the protected paths were built from, even when the
  // environment says otherwise. `autoagy setup` pins that home into hooks.json.
  const source = { ...ctx.env, HOME: ctx.home ?? ctx.env.HOME };
  for (const [name, value] of sandboxEnv(source, { passThrough: ctx.config.ownSandboxEnvPassThrough })) {
    parts.push(quote(`${name}=${value}`));
  }
  return `${parts.join(' ')} ${quote(shellPath())} -c ${quote(commandLine)}`;
}

/** Paths that stay read-only inside the sandbox even when they lie in a writable root. */
export function readOnlyPaths(ctx) {
  const logs = [ctx.artifactDir ? path.join(ctx.artifactDir, '.system_generated') : null, ctx.transcriptPath ? path.dirname(ctx.transcriptPath) : null];
  // `nestedGitPaths`: a submodule or vendored checkout keeps its own `.git`, and
  // a hook planted there runs on the next git command in that directory — which
  // has to leave this sandbox to write anything, so it runs outside it. Only the
  // top-level one is in the metadata list.
  //
  // `metadataControlPaths`, not `workspaceControlPaths`: it covers the roots
  // `writableRoots` declares as well, and the edit tools already refuse those
  // (`classifyWriteTarget`). Measured before this line said so: with a declared
  // root, a sandboxed `echo > <declared>/.git/hooks/pre-commit` reached the
  // host, while the same write inside the workspace got `Read-only file
  // system`. Two paths to the same decision and the weaker one was the sandbox,
  // which is the shape the fourth round already called a bug.
  return [...ctx.metadataControlPaths, ...ctx.nestedGitPaths, ...ctx.selfPaths, ...logs].filter(Boolean);
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
/** The protected workspace directories this command could create, given its writable roots. */
export function writableControlPaths(ctx) {
  return ctx.metadataControlPaths.filter((p) => ctx.writableRoots.some((root) => isWithin(p, root)) && tmpfsMountable(p));
}

/**
 * Whether the empty read-only `--tmpfs` mount can be put at this path.
 *
 * It needs a directory to mount on, and bwrap will not make one out of a file:
 * measured, `bwrap: Can't mkdir <ws>/.git: Not a directory`, exit 1 — for every
 * command, in every workspace where one of the protected names is a regular
 * file. That is not exotic: `git worktree add` and a checked-out submodule both
 * leave `.git` as a *file* holding `gitdir: …`. The command failed while the
 * self-check still recorded `verified`, because agy did run the line autoagy
 * rewrote — so `status` reported a working sandbox over a repository where
 * nothing ran.
 *
 * Skipping the mount costs nothing here: the read-only bind further down is
 * emitted for the same path and binds the file, and a sandboxed command cannot
 * remove the file through it to put a directory in its place.
 */
function tmpfsMountable(p) {
  let stat;
  try {
    stat = fs.statSync(p); // follows a symlink to wherever it points
  } catch {
    try {
      fs.lstatSync(p);
      // Something is there and it does not resolve to anything — nothing to mount on.
      return false;
    } catch {
      // Absent: bwrap creates the mount point, which is the case this exists for.
      return true;
    }
  }
  return stat.isDirectory();
}

function missingControlPaths(ctx) {
  const out = [];
  for (const p of ctx.metadataControlPaths) {
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
  // Protected workspace directories are mounted twice, in this order. The empty
  // read-only mount comes first; the bind of the real directory comes after and
  // therefore wins when the directory is there. That gives the conditional the
  // protection needs: `.git` stays readable inside the sandbox, while a
  // directory that vanished between this line being built and bwrap starting —
  // another step reclaiming a mount point, say — still ends up mounted instead
  // of falling through to the writable workspace bind underneath. A single
  // `--ro-bind-try` would silently skip a missing path, and a single `--tmpfs`
  // would hide the real directory. Measured on bwrap 0.9.0: the source of the
  // later bind resolves against the original root, not the fresh tmpfs.
  for (const p of writableControlPaths(ctx)) args.push('--perms', '555', '--tmpfs', p, '--remount-ro', p);
  for (const p of readOnlyPaths(ctx)) args.push('--ro-bind-try', p, p);
  // The mount points also have to exist on the host, so bwrap has somewhere to
  // mount and so they can be recorded and cleaned up afterwards.
  const made = controlPlaceholders(ctx);
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
  for (const [name, value] of sandboxEnv(env, { passThrough: ctx.config.ownSandboxEnvPassThrough })) {
    args.push('--setenv', name, value);
  }
  const filter = seccompProgramFile(ctx.autoagyHome);
  const call = [ctx.ownSandbox.bwrap, ...args, '--seccomp', String(SECCOMP_FD), '--', shellPath(), '-c', commandLine];
  // The filter is handed to bwrap as an inherited descriptor, opened by the
  // shell that execs it; autoagy's own directory is read-only in the sandbox, so
  // the file it points at cannot be swapped while the command runs.
  const line = `exec ${call.map(quote).join(' ')} ${SECCOMP_FD}<${quote(filter)}`;
  // Hold a shared lock for as long as bwrap runs, so `lockQuiescent` can tell
  // whether any command is still alive. `flock` execs bwrap as its child and
  // waits, and passes the inherited seccomp descriptor through untouched.
  const flock = flockPath();
  const lockFile = flock ? workspaceLockFile(ctx) : null;
  if (!flock || !lockFile) return line;
  return `exec ${quote(flock)} -s ${quote(lockFile)} ${line.slice('exec '.length)}`;
}
