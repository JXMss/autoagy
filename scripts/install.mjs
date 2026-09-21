#!/usr/bin/env node
// Installs autoagy as a global Antigravity plugin and configures Antigravity.
//
//   node scripts/install.mjs                 install (or update) + setup
//   node scripts/install.mjs --no-settings   install without touching Antigravity settings
//   node scripts/install.mjs --dry-run       show what would happen
//   node scripts/install.mjs --uninstall     revert settings and remove the plugin
//                             [--purge]      also delete ~/.gemini/autoagy (config, state, logs)

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { removeTripwire, tripwireInstalled, tripwireRegistered, tripwirePath, userHooksPath, registeredTripwirePath, registeredAutoagyHome } from '../plugin/lib/tripwire.mjs';
import { applyTeardown, hookPins, cliSettingsPath } from '../plugin/lib/setup.mjs';
import { autoagyHome as resolveAutoagyHome } from '../plugin/lib/config.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = path.join(REPO, 'plugin');
const INSTALLED = path.join(os.homedir(), '.gemini', 'config', 'plugins', 'autoagy');
const BIN = path.join(INSTALLED, 'bin', 'autoagy.mjs');
const args = new Set(process.argv.slice(2));
const dryRun = args.has('--dry-run');

function run(command, commandArgs, { allowFailure = false } = {}) {
  const res = spawnSync(command, commandArgs, { stdio: 'inherit', shell: process.platform === 'win32' });
  if (res.status !== 0 && !allowFailure) throw new Error(`${command} ${commandArgs.join(' ')} failed (exit ${res.status ?? res.error?.message})`);
  return res.status === 0;
}

function agyAvailable() {
  const res = spawnSync('agy', ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' });
  return res.status === 0;
}

function install() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 20) throw new Error(`Node.js 20 or newer is required (found ${process.versions.node}).`);
  console.log(`Installing ${SOURCE}\n       -> ${INSTALLED}`);
  if (dryRun) {
    console.log('(dry run) would install the plugin, then run `autoagy setup --dry-run`:');
    run(process.execPath, [path.join(SOURCE, 'bin', 'autoagy.mjs'), 'setup', '--dry-run']);
    return;
  }
  if (agyAvailable()) {
    run('agy', ['plugin', 'install', SOURCE]);
  } else {
    console.log('`agy` not found on PATH; copying the plugin directory instead.');
    fs.rmSync(INSTALLED, { recursive: true, force: true });
    fs.mkdirSync(path.dirname(INSTALLED), { recursive: true });
    fs.cpSync(SOURCE, INSTALLED, { recursive: true });
  }
  const setupArgs = [BIN, 'setup'];
  if (args.has('--no-settings')) setupArgs.push('--no-settings');
  run(process.execPath, setupArgs);
  console.log(`
Done. autoagy is active for new Antigravity sessions.

  Check it:      node ${BIN} status
  Watch it:      node ${BIN} log
  Switch mode:   node ${BIN} mode auto|ask|off

Tip: alias autoagy="node ${BIN}"`);
}

function uninstall() {
  // `$HOME`, the same home this script installs into (INSTALLED is built from
  // it) and the one `os.homedir()` reports. The plugin itself prefers the
  // account database's home for anything the policy reads, so an install made
  // with the two disagreeing is reconciled by the two answers below rather than
  // by picking one here.
  const userHome = os.homedir();
  // Where the state is. The pin written at install time is the first answer;
  // when the plugin directory is the thing that went missing, the tripwire's
  // own registration carries it instead (the registered program is
  // `<autoagyHome>/bin/tripwire.mjs`), and only then does the environment get a
  // say.
  const installedPin = hookPins(INSTALLED);
  const env = { ...process.env };
  const pinnedHome = installedPin.configHome ?? registeredAutoagyHome(userHome);
  if (pinnedHome) env.AUTOAGY_HOME = pinnedHome;
  const autoagyHome = resolveAutoagyHome(env, userHome);

  // The grants come out first, and nothing else is taken away unless they did.
  // They have to come out even when the installed copy is gone — this script
  // runs from the clone, whose lib is always here — because the record `setup`
  // wrote is what makes `command(*)`, `mcp(*)` and `execute_url(*)` revertable
  // at all. And when they could not come out, everything that stands behind
  // them stays: the tripwire, the plugin, and the record itself. This used to
  // carry on regardless, so a failed revert still removed the tripwire and the
  // plugin, and `--purge` then deleted the record — leaving grants that no
  // command could revert any more, and a second run that printed
  // "autoagy uninstalled." with exit 0.
  let reverted;
  if (fs.existsSync(BIN)) {
    // The exit status is the only word on whether the grants came back out, and
    // the installed command refuses (status 1) exactly when it could not. It
    // also removes the tripwire when it succeeds; the call below covers the
    // homes it cannot see.
    reverted = run(process.execPath, [BIN, 'teardown', ...(dryRun ? ['--dry-run'] : [])], { allowFailure: true });
  } else {
    const report = applyTeardown({ dryRun, env, home: userHome });
    reverted = !report.unreadable;
    if (reverted) console.log(report.found ? `${dryRun ? 'Would revert' : 'Reverted'} ${report.settingsFile}` : `No setup record found in ${autoagyHome}; nothing else to revert.`);
  }
  if (!reverted) {
    console.error(`autoagy: the permission grants could not be taken out of ${cliSettingsPath(userHome)} (is it valid JSON?), so nothing else was removed either:`);
    console.error('  the plugin, its tripwire and the setup record are all still in place, because each of them is what stands');
    console.error('  behind those grants — and the record is what lets them be reverted at all. Repair the file and run this again.');
    process.exitCode = 1;
    return;
  }

  // Deliberately not gated on the installed copy existing: a tripwire left
  // behind refuses every tool call, and it is registered in a file `agy plugin`
  // does not manage — so the install that most needs this is the one where the
  // plugin directory is already gone. Both halves are asked about separately,
  // because `tripwireInstalled` is both at once while the state that matters
  // most here is the one where they disagree — a registration whose program is
  // gone, still refusing every call.
  const tripwire = dryRun
    ? { script: fs.existsSync(registeredTripwirePath(userHome) ?? tripwirePath(autoagyHome)), registration: tripwireRegistered({ home: userHome }) }
    : removeTripwire({ autoagyHome, home: userHome });
  if (tripwire.script || tripwire.registration) {
    console.log(`${dryRun ? 'Would remove' : 'Removed'} the tripwire${tripwire.script ? ` (${tripwire.path ?? registeredTripwirePath(userHome) ?? tripwirePath(autoagyHome)})` : ''}${tripwire.registration ? ` from ${userHooksPath(userHome)}` : ''}`);
  }
  if (dryRun) return console.log(`(dry run) would remove ${INSTALLED}`);
  if (!(agyAvailable() && run('agy', ['plugin', 'uninstall', 'autoagy'], { allowFailure: true }))) {
    fs.rmSync(INSTALLED, { recursive: true, force: true });
  }
  if (args.has('--purge')) {
    fs.rmSync(autoagyHome, { recursive: true, force: true });
    console.log(`Removed ${autoagyHome} (config, state and logs).`);
  }
  // Anything that is still in place gets said out loud, and "uninstalled" is not
  // printed over it: a tripwire still registered keeps refusing every tool call.
  if (tripwireInstalled({ autoagyHome, home: userHome })) {
    console.error(`autoagy: the tripwire is still registered in ${userHooksPath(userHome)} — delete its \`autoagy-tripwire\` key there, or every tool call stays refused.`);
    process.exitCode = 1;
    return;
  }
  console.log('autoagy uninstalled.');
}

try {
  if (args.has('--uninstall')) uninstall();
  else install();
} catch (err) {
  console.error(`install: ${err.message}`);
  process.exit(1);
}
