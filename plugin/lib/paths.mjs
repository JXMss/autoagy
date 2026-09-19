// Path helpers shared by the policy engine.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CASE_INSENSITIVE = process.platform === 'win32' || process.platform === 'darwin';

/** Expands a leading `~` against `home`. */
export function expandHome(p, home = os.homedir()) {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) return path.join(home, p.slice(2));
  return p;
}

/**
 * Turns a tool argument into an absolute, normalized path.
 * Accepts file:// URIs, `~`, and paths relative to `base`.
 * @returns {string | null}
 */
export function toAbsolute(p, base, home = os.homedir()) {
  if (typeof p !== 'string') return null;
  let value = p.trim();
  if (value === '') return null;
  if (value.startsWith('file://')) {
    try {
      value = fileURLToPath(value);
    } catch {
      value = decodeURIComponent(value.slice('file://'.length));
    }
  }
  value = expandHome(value, home);
  if (!path.isAbsolute(value)) {
    if (!base) return null;
    value = path.join(base, value);
  }
  return path.normalize(value);
}

/**
 * Resolves symlinks in the longest existing prefix of `p`, so that a path
 * written through a symlink inside the workspace is judged by where it lands.
 */
export function resolveReal(p) {
  let current = p;
  const rest = [];
  for (let i = 0; i < 64; i++) {
    try {
      const real = fs.realpathSync.native(current);
      return rest.length ? path.join(real, ...rest.reverse()) : real;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return p;
      rest.push(path.basename(current));
      current = parent;
    }
  }
  return p;
}

function comparable(p) {
  const normalized = path.normalize(p).replace(/[\\/]+$/, '') || path.sep;
  return CASE_INSENSITIVE ? normalized.toLowerCase() : normalized;
}

/** True when `child` equals `parent` or lies inside it. */
export function isWithin(child, parent) {
  if (!child || !parent) return false;
  const c = comparable(child);
  const p = comparable(parent);
  if (c === p) return true;
  const rel = path.relative(p, c);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/** Returns the first root that contains `p`, or null. */
export function findContainingRoot(p, roots) {
  for (const root of roots) {
    if (isWithin(p, root)) return root;
  }
  return null;
}

/** Deduplicates normalized absolute paths, dropping empty values. */
export function uniquePaths(paths) {
  const seen = new Set();
  const out = [];
  for (const p of paths) {
    if (!p) continue;
    const key = comparable(p);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(path.normalize(p));
  }
  return out;
}

/**
 * Converts a glob into a RegExp over forward-slash paths.
 * Supports `**`, `*`, `?`, and `{a,b}`. Patterns without a slash match a
 * basename anywhere (like .gitignore).
 */
export function globToRegExp(glob) {
  let pattern = glob.replace(/\\/g, '/');
  const anchored = pattern.includes('/');
  // `dir/**` also matches `dir` itself.
  const dirAndContents = pattern.endsWith('/**');
  if (dirAndContents) pattern = pattern.slice(0, -3);
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        const slashAfter = pattern[i + 2] === '/';
        re += slashAfter ? '(?:.*/)?' : '.*';
        i += slashAfter ? 2 : 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const end = pattern.indexOf('}', i);
      if (end > i) {
        const alternatives = pattern.slice(i + 1, end).split(',').map((a) => a.replace(/[.+^$()|[\]\\]/g, '\\$&'));
        re += `(?:${alternatives.join('|')})`;
        i = end;
      } else {
        re += '\\{';
      }
    } else {
      re += c.replace(/[.+^$()|[\]\\]/g, '\\$&');
    }
  }
  if (dirAndContents) re += '(?:/.*)?';
  const body = anchored ? `^${re}$` : `(?:^|/)${re}$`;
  return new RegExp(body, CASE_INSENSITIVE ? 'i' : '');
}

/** True when absolute path `p` matches any of the globs (`~` expanded). */
export function matchesAnyGlob(p, globs, home = os.homedir()) {
  if (!p) return false;
  const target = p.replace(/\\/g, '/');
  for (const glob of globs ?? []) {
    if (typeof glob !== 'string' || glob === '') continue;
    const expanded = expandHome(glob, home).replace(/\\/g, '/');
    if (globToRegExp(expanded).test(target)) return true;
  }
  return false;
}
