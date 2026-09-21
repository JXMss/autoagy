// Installing and removing the tripwire (see bin/tripwire.mjs for what it does).
//
// It lives in two places at once, and both matter:
//
//   ~/.gemini/config/hooks.json     the registration. Measured on agy 1.2.7:
//                                   this file is loaded, and unlike a plugin's
//                                   it survives `agy plugin disable` and
//                                   `agy plugin install`.
//   $AUTOAGY_HOME/bin/tripwire.mjs  the program. Not in the plugin directory,
//                                   because the plugin directory going away is
//                                   one of the things it has to keep noticing.
//
// The registration is merged into that file rather than written over it: it is
// a user-level file and may hold hooks that have nothing to do with autoagy.
// The key is autoagy's own name plus a suffix, because two files registering
// the *same* name both run (measured) — a second copy of autoagy's real hooks
// would double every decision and wrap every command twice.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const TRIPWIRE_KEY = 'autoagy-tripwire';
const SOURCE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'tripwire.mjs');

/** The user-level hooks file agy loads outside the plugin system. */
export function userHooksPath(home = os.homedir()) {
  return path.join(home, '.gemini', 'config', 'hooks.json');
}

export function tripwirePath(autoagyHome) {
  return path.join(autoagyHome, 'bin', 'tripwire.mjs');
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.autoagy-tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

/**
 * True when the registration is in the user hooks file, whatever became of the
 * program it names.
 *
 * The two halves fail apart in both directions, and the interesting one is a
 * registration with no program: the hook runs a command that is not there, so
 * every tool call fails, and it is still registered — which is a state someone
 * has to be told about, not a state to report as "nothing to do".
 */
export function tripwireRegistered({ home = os.homedir() } = {}) {
  return Boolean(readJson(userHooksPath(home))?.[TRIPWIRE_KEY]);
}

/**
 * The program the registration runs, or null.
 *
 * The registration is the half that decides whether anything is still refusing
 * tool calls, and it names the program by absolute path — which makes it the
 * ground truth for where that program is. Nothing else survives an uninstall
 * that took the plugin directory with it, and the home a command happens to
 * resolve can differ from the one `autoagy setup` pinned (a launcher, `sudo`,
 * an exported `AUTOAGY_HOME`), so guessing from the environment is exactly the
 * mistake this avoids.
 */
export function registeredTripwirePath(home = os.homedir()) {
  const entry = readJson(userHooksPath(home))?.[TRIPWIRE_KEY];
  const command = entry?.PreToolUse?.[0]?.hooks?.[0]?.command;
  if (typeof command !== 'string') return null;
  const text = command.trim();
  const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(text);
  let token = quoted ? quoted[1] : text.split(/\s+/)[0];
  if (quoted) {
    try {
      token = JSON.parse(`"${quoted[1]}"`);
    } catch {
      // keep the raw contents
    }
  }
  return token && path.isAbsolute(token) ? token : null;
}

/**
 * The autoagy home the registered program lives in, or null.
 *
 * `installTripwire` writes the program to `<autoagyHome>/bin/tripwire.mjs`, so
 * the registration carries the pinned home with it — which is what
 * `scripts/install.mjs` needs when it runs with the plugin directory already
 * gone and therefore no `hooks.json` to read the pin from.
 */
export function registeredAutoagyHome(home = os.homedir()) {
  const script = registeredTripwirePath(home);
  if (!script) return null;
  const bin = path.dirname(script);
  return path.basename(bin) === 'bin' ? path.dirname(bin) : null;
}

/** True when both halves are in place, at the path the registration names. */
export function tripwireInstalled({ autoagyHome, home = os.homedir() }) {
  const registered = registeredTripwirePath(home);
  return tripwireRegistered({ home }) && fs.existsSync(registered ?? tripwirePath(autoagyHome));
}

/**
 * Writes the program with its interpreter and the two paths it checks pinned,
 * then registers it.
 * @returns {{ script: string, hooks: string }}
 */
/**
 * The only directory agy loads plugin hooks from (measured, design.md §2: the CLI
 * ignores workspace-level `.agents/plugins`).
 *
 * The tripwire has to watch *this* path and not the directory `autoagy setup`
 * happened to run in, and the difference is not theoretical: `setup` writes the
 * grants wherever it is run, so running it from a checkout used to bake the
 * checkout's path into the tripwire — which exists, so the tripwire concluded all
 * was well while agy loaded nothing at all. The grants were live and the one
 * mechanism whose whole job is to catch that was watching the wrong place.
 */
export function installedPluginDir(home = os.homedir()) {
  return path.join(home, '.gemini', 'config', 'plugins', 'autoagy');
}

/**
 * Reads the user hooks file for a read-modify-write, and says whether it may be
 * rewritten: the rule `readForRewrite` (setup.mjs) applies to the CLI settings,
 * for the same reason. The file is the user's, not autoagy's, and may hold hooks
 * that have nothing to do with autoagy. Registration used to read it with
 * `readJson(file) ?? {}`, so one syntax error — or a read that failed for any
 * other reason — made it write back `{}` plus the tripwire, silently taking
 * every other hook with it, and exit 0. `removeTripwire` already refused to
 * touch such a file; the two now agree. Absent is fine: there is nothing to lose.
 */
function readHooksForRewrite(file) {
  if (!fs.existsSync(file)) return { value: {}, readable: true };
  const value = readJson(file);
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return { value: null, readable: false };
  return { value, readable: true };
}

/**
 * Whether `installTripwire` can register without destroying anything. Asked by
 * `autoagy setup` before it writes a single grant: grants whose tripwire could
 * not be registered are the fail-open the tripwire exists to catch.
 * @returns {{ ok: boolean, file: string }}
 */
export function tripwireInstallable({ home = os.homedir() } = {}) {
  const file = userHooksPath(home);
  return { ok: readHooksForRewrite(file).readable, file };
}

export function installTripwire({ autoagyHome, home = os.homedir(), nodePath = process.execPath }) {
  const file = userHooksPath(home);
  const { value: hooks, readable } = readHooksForRewrite(file);
  if (!readable) {
    throw new Error(`${file} is not valid JSON, so the tripwire was not registered and the file was left as it is. Fix it first (a trailing comma is the usual cause).`);
  }
  const script = tripwirePath(autoagyHome);
  const source = fs
    .readFileSync(SOURCE, 'utf8')
    .replace(/^#![^\n]*\n/, `#!${nodePath}\n`)
    // Derived here rather than taken from the caller: a caller that passes the
    // wrong directory turns this program into one that always says "fine".
    .replace('__PLUGIN_DIR__', installedPluginDir(home))
    .replace('__CONFIG_JSON__', path.join(home, '.gemini', 'config', 'config.json'))
    // Where it is registered, so a refusal can name the one way out that needs
    // no command to run.
    .replace('__HOOKS_JSON__', userHooksPath(home));
  fs.mkdirSync(path.dirname(script), { recursive: true, mode: 0o700 });
  const tmp = `${script}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, source, { mode: 0o700 });
  fs.renameSync(tmp, script);

  hooks[TRIPWIRE_KEY] = {
    PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: quote(script), timeout: 20 }] }],
  };
  writeJson(file, hooks);
  return { script, hooks: file };
}

/** Takes both halves away, leaving any other hooks in that file alone. */
export function removeTripwire({ autoagyHome, home = os.homedir() }) {
  const removed = { script: false, registration: false, path: null };
  // Both candidates: the home this command resolved, and the one the
  // registration names. They differ whenever the install was pinned to another
  // home, and taking away only the first leaves a registered program that every
  // tool call keeps running.
  for (const script of new Set([tripwirePath(autoagyHome), registeredTripwirePath(home)].filter(Boolean))) {
    if (!fs.existsSync(script)) continue;
    fs.rmSync(script, { force: true });
    removed.script = true;
    removed.path = script;
  }
  const file = userHooksPath(home);
  const hooks = readJson(file);
  if (hooks && TRIPWIRE_KEY in hooks) {
    delete hooks[TRIPWIRE_KEY];
    // A file that held nothing but the tripwire is autoagy's to clean up; one
    // that still holds someone else's hooks is not.
    if (Object.keys(hooks).length === 0) fs.rmSync(file, { force: true });
    else writeJson(file, hooks);
    removed.registration = true;
  }
  return removed;
}

const quote = (s) => (/[\s"'\\]/.test(s) ? JSON.stringify(s) : s);
