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
  if (fs.existsSync(BIN)) run(process.execPath, [BIN, 'teardown', ...(dryRun ? ['--dry-run'] : [])], { allowFailure: true });
  if (dryRun) return console.log(`(dry run) would remove ${INSTALLED}`);
  if (!(agyAvailable() && run('agy', ['plugin', 'uninstall', 'autoagy'], { allowFailure: true }))) {
    fs.rmSync(INSTALLED, { recursive: true, force: true });
  }
  if (args.has('--purge')) {
    fs.rmSync(path.join(os.homedir(), '.gemini', 'autoagy'), { recursive: true, force: true });
    console.log('Removed ~/.gemini/autoagy (config, state and logs).');
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
