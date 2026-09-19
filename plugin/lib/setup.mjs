// `autoagy setup` / `autoagy teardown`: make Antigravity's own permission
// system hand approval decisions to autoagy, and undo exactly that.
//
// Measured on agy 1.2.x: a PreToolUse "allow" cannot override Antigravity's
// permission prompts, so actions autoagy should be able to auto-approve need an
// Antigravity grant. These grants do not widen the terminal sandbox:
//   command(*)      agent-requested sandbox bypass no longer prompts natively
//   mcp(*)          MCP tool calls no longer prompt natively
//   execute_url(*)  browser interactions no longer prompt natively
// read_url(...) is deliberately NOT granted: read_url rules also become the
// terminal sandbox's network allowlist, which would let unreviewed sandboxed
// commands reach the network.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { autoagyHome as resolveAutoagyHome, defaultConfigFileText, configPath } from './config.mjs';

export const RECOMMENDED_GRANTS = ['command(*)', 'mcp(*)', 'execute_url(*)'];
export const RECOMMENDED_SETTINGS = { enableTerminalSandbox: true, toolPermission: 'proceed-in-sandbox', allowNonWorkspaceAccess: true };

export function cliSettingsPath(home = os.homedir()) {
  return path.join(home, '.gemini', 'antigravity-cli', 'settings.json');
}

function setupRecordPath(autoagyHome) {
  return path.join(autoagyHome, 'setup.json');
}

function readJsonFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  return text.trim() ? JSON.parse(text) : {};
}

function writeJsonFile(file, value) {
  const tmp = `${file}.autoagy-tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

/** Computes the settings changes setup would make. */
export function planSetup(settings, { grants = RECOMMENDED_GRANTS, settingsChanges = true } = {}) {
  const allow = Array.isArray(settings.permissions?.allow) ? settings.permissions.allow : [];
  const deny = Array.isArray(settings.permissions?.deny) ? settings.permissions.deny : [];
  const addGrants = grants.filter((g) => !allow.includes(g));
  const conflicting = grants.filter((g) => deny.includes(g));
  const changes = [];
  if (settingsChanges) {
    for (const [key, value] of Object.entries(RECOMMENDED_SETTINGS)) {
      if (settings[key] !== value) changes.push({ key, from: settings[key], to: value });
    }
  }
  return { addGrants, changes, conflicting };
}

/**
 * Applies setup to the Antigravity CLI settings file.
 * @returns {{ settingsFile: string, addGrants: string[], changes: object[], backup: string | null, dryRun: boolean }}
 */
export function applySetup({ home = os.homedir(), env = process.env, dryRun = false, grants = RECOMMENDED_GRANTS, settingsChanges = true } = {}) {
  const autoagyHome = resolveAutoagyHome(env, home);
  const settingsFile = cliSettingsPath(home);
  let settings = {};
  if (fs.existsSync(settingsFile)) settings = readJsonFile(settingsFile);
  const plan = planSetup(settings, { grants, settingsChanges });
  const report = { settingsFile, ...plan, backup: null, dryRun };
  if (dryRun || (plan.addGrants.length === 0 && plan.changes.length === 0)) return report;

  fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
  if (fs.existsSync(settingsFile)) {
    report.backup = `${settingsFile}.autoagy-backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(settingsFile, report.backup);
  }
  const previous = readSetupRecord(autoagyHome);
  const next = JSON.parse(JSON.stringify(settings));
  next.permissions = { ...(next.permissions ?? {}) };
  next.permissions.allow = [...(Array.isArray(next.permissions.allow) ? next.permissions.allow : []), ...plan.addGrants];
  const priorValues = { ...(previous?.priorValues ?? {}) };
  for (const change of plan.changes) {
    if (!(change.key in priorValues)) priorValues[change.key] = change.key in settings ? { present: true, value: settings[change.key] } : { present: false };
    next[change.key] = change.to;
  }
  writeJsonFile(settingsFile, next);
  fs.mkdirSync(autoagyHome, { recursive: true });
  writeJsonFile(setupRecordPath(autoagyHome), {
    time: new Date().toISOString(),
    settingsFile,
    backup: report.backup,
    addedGrants: [...new Set([...(previous?.addedGrants ?? []), ...plan.addGrants])],
    priorValues,
  });
  return report;
}

export function readSetupRecord(autoagyHome) {
  try {
    return readJsonFile(setupRecordPath(autoagyHome));
  } catch {
    return null;
  }
}

/** Reverts the grants and settings that setup changed. */
export function applyTeardown({ home = os.homedir(), env = process.env, dryRun = false } = {}) {
  const autoagyHome = resolveAutoagyHome(env, home);
  const record = readSetupRecord(autoagyHome);
  if (!record) return { found: false, removedGrants: [], restored: [], dryRun };
  const settingsFile = record.settingsFile ?? cliSettingsPath(home);
  let settings = {};
  try {
    settings = readJsonFile(settingsFile);
  } catch {
    settings = {};
  }
  const allow = Array.isArray(settings.permissions?.allow) ? settings.permissions.allow : [];
  const removedGrants = allow.filter((g) => record.addedGrants?.includes(g));
  const restored = Object.entries(record.priorValues ?? {}).map(([key, prior]) => ({ key, to: prior.present ? prior.value : undefined }));
  if (!dryRun) {
    if (settings.permissions) settings.permissions.allow = allow.filter((g) => !record.addedGrants?.includes(g));
    for (const { key, to } of restored) {
      if (to === undefined) delete settings[key];
      else settings[key] = to;
    }
    writeJsonFile(settingsFile, settings);
    fs.rmSync(setupRecordPath(autoagyHome), { force: true });
  }
  return { found: true, settingsFile, removedGrants, restored, dryRun };
}

/** Writes the default config file if none exists. */
export function ensureConfigFile({ home = os.homedir(), env = process.env, dryRun = false } = {}) {
  const file = configPath(env, home);
  if (fs.existsSync(file)) return { file, created: false };
  if (!dryRun) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, defaultConfigFileText());
  }
  return { file, created: true };
}

/**
 * Replaces the bare `node` in hooks.json commands with an absolute interpreter
 * path, so hooks work even when Antigravity is started without the user's PATH.
 */
export function pinNodeInHooks(pluginDir, nodePath = process.execPath, { dryRun = false } = {}) {
  const file = path.join(pluginDir, 'hooks.json');
  const hooks = readJsonFile(file);
  let changed = 0;
  const quoted = /[\s"'\\]/.test(nodePath) ? JSON.stringify(nodePath) : nodePath;
  const visit = (value) => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (value && typeof value === 'object') {
      if (typeof value.command === 'string' && /^node\s/.test(value.command)) {
        value.command = value.command.replace(/^node(?=\s)/, quoted);
        changed++;
      }
      Object.values(value).forEach(visit);
    }
  };
  visit(hooks);
  if (changed > 0 && !dryRun) writeJsonFile(file, hooks);
  return { file, changed };
}
