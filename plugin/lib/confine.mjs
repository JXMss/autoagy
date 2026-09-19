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
// agent metadata, autoagy itself and the conversation logs stay read-only; and
// there is no network.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// Only root-owned system binaries: a `bwrap` or shell found through PATH could
// be a script the agent planted in a directory it can write.
const BWRAP_CANDIDATES = ['/usr/bin/bwrap', '/usr/local/bin/bwrap', '/bin/bwrap'];
const SHELL_CANDIDATES = ['/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh'];
const PROBE_TTL_MS = 24 * 3600 * 1000;

// No network, a private /proc and /dev, and nothing outlives the sandbox.
const BASE_ARGS = ['--ro-bind', '/', '/', '--dev', '/dev', '--proc', '/proc', '--unshare-net', '--unshare-pid', '--die-with-parent'];

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
  const key = `${bin.file}:${bin.stat.mtimeMs}:${os.release()}`;
  const cacheFile = path.join(autoagyHome, 'state', 'bwrap-probe.json');
  try {
    const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    // Only the verdict is cached; the binary path is always the one found above.
    if (cached.key === key && Date.now() - cached.time < PROBE_TTL_MS) return { ok: cached.ok === true, bwrap: bin.file, detail: String(cached.detail) };
  } catch {
    // no usable cache
  }
  const res = spawnSync(bin.file, [...BASE_ARGS, '--', shellPath(), '-c', 'true'], { encoding: 'utf8', timeout: 5000 });
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
export function detectOwnSandbox({ config, host, appDataDir, autoagyHome, platform = process.platform, probe = probeBwrap }) {
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
 * The command line that runs `commandLine` inside autoagy's sandbox.
 * @param {import('./context.mjs').HookContext} ctx
 */
export function confinedCommandLine(ctx, commandLine) {
  const args = [...BASE_ARGS];
  // Later mounts win, so the read-only paths go on top of the writable roots.
  for (const root of ctx.writableRoots) args.push('--bind-try', root, root);
  for (const p of readOnlyPaths(ctx)) args.push('--ro-bind-try', p, p);
  return `exec ${[ctx.ownSandbox.bwrap, ...args, '--', shellPath(), '-c', commandLine].map(quote).join(' ')}`;
}
