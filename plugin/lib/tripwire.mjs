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

/** True when both halves are in place. */
export function tripwireInstalled({ autoagyHome, home = os.homedir() }) {
  if (!fs.existsSync(tripwirePath(autoagyHome))) return false;
  return Boolean(readJson(userHooksPath(home))?.[TRIPWIRE_KEY]);
}

/**
 * Writes the program with its interpreter and the two paths it checks pinned,
 * then registers it.
 * @returns {{ script: string, hooks: string }}
 */
export function installTripwire({ autoagyHome, home = os.homedir(), pluginDir, nodePath = process.execPath }) {
  const script = tripwirePath(autoagyHome);
  const source = fs
    .readFileSync(SOURCE, 'utf8')
    .replace(/^#![^\n]*\n/, `#!${nodePath}\n`)
    .replace('__PLUGIN_DIR__', pluginDir)
    .replace('__CONFIG_JSON__', path.join(home, '.gemini', 'config', 'config.json'))
    // Where it is registered, so a refusal can name the one way out that needs
    // no command to run.
    .replace('__HOOKS_JSON__', userHooksPath(home));
  fs.mkdirSync(path.dirname(script), { recursive: true, mode: 0o700 });
  const tmp = `${script}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, source, { mode: 0o700 });
  fs.renameSync(tmp, script);

  const file = userHooksPath(home);
  const hooks = readJson(file) ?? {};
  hooks[TRIPWIRE_KEY] = {
    PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: quote(script), timeout: 20 }] }],
  };
  writeJson(file, hooks);
  return { script, hooks: file };
}

/** Takes both halves away, leaving any other hooks in that file alone. */
export function removeTripwire({ autoagyHome, home = os.homedir() }) {
  const removed = { script: false, registration: false };
  const script = tripwirePath(autoagyHome);
  if (fs.existsSync(script)) {
    fs.rmSync(script, { force: true });
    removed.script = true;
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
