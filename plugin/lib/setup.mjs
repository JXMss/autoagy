// `autoagy setup` / `autoagy teardown`: make Antigravity's own permission
// system hand approval decisions to autoagy, and undo exactly that.
//
// Measured on agy 1.2.x: a PreToolUse "allow" cannot override Antigravity's
// permission prompts, so actions autoagy should be able to auto-approve need an
// Antigravity grant. These grants do not widen the terminal sandbox:
//   command(*)      agent-requested sandbox bypass no longer prompts natively
//   mcp(*)          MCP tool calls no longer prompt natively
//   execute_url(*)  browser interactions no longer prompt natively
// read_url(*) is never granted by anything here: a read_url rule is also an entry
// in the terminal sandbox's network allowlist (measured), so the wildcard would
// let unreviewed sandboxed commands reach any host. Per-domain grants derived
// from `trustedDomains` are opt-in — see `trustedDomainGrants` and
// `networkGrants` in config.mjs.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { autoagyHome as resolveAutoagyHome, defaultConfigFileText, configPath, resolveConfigPath } from './config.mjs';
import { expandHome } from './paths.mjs';
import { executorPath } from './tokens.mjs';

export const RECOMMENDED_GRANTS = ['command(*)', 'mcp(*)', 'execute_url(*)'];
// `allowNonWorkspaceAccess: false` is the one check that happens at the moment
// of the write rather than before it, and it follows symlinks to decide
// (measured): a path swapped between autoagy's check and agy's write cannot
// land outside the workspace. autoagy already reviews every edit that names a
// place outside the workspace, so what setting this to true bought was only
// "an approved one runs without a second prompt" — and what it sold was the
// only cap problem 2 has. The directories `writableRoots` names get their own
// narrow grants instead; see `writableRootGrants`.
export const RECOMMENDED_SETTINGS = { enableTerminalSandbox: true, toolPermission: 'proceed-in-sandbox', allowNonWorkspaceAccess: false };

/**
 * A `write_file(...)` grant for each directory `writableRoots` names.
 *
 * With `allowNonWorkspaceAccess: false` agy refuses a write whose resolved
 * target is outside the workspace, and `writableRoots` exists precisely to let
 * a few outside directories be edited without review — so without these the
 * option would be a dead letter. Measured: the grant covers the whole subtree,
 * does not reach a sibling directory, and resolves symlinks, so a link planted
 * inside a granted directory cannot write out of it.
 *
 * agy's own scratch directory and the temp directories need nothing here: it
 * does not count those as outside the workspace (measured).
 */
export function writableRootGrants(config, home = os.homedir()) {
  // `resolveConfigPath`, not `path.resolve`: `loadConfig` already resolved these
  // and dropped the ones it could not, so the grant names the same directory the
  // policy treats as writable. Resolving against the cwd here was the other half
  // of that disagreement — `setup` run from two directories wrote two grants for
  // one entry, and neither matched what the hook honoured.
  return (config?.writableRoots ?? [])
    .map((p) => resolveConfigPath(p, { home }))
    .filter(Boolean)
    .map((p) => `write_file(${p})`);
}

/**
 * A `read_url(<domain>)` grant for each `trustedDomains` entry, when
 * `networkGrants` asks for them.
 *
 * The prompt this removes is the one autoagy cannot answer: a hook `allow` does
 * not override agy's own permission for a fetch (measured), so the first fetch of
 * any domain reaches the user however the reviewer judged it. `trustedDomains`
 * already says which domains need no review, and this hands that same list to
 * agy.
 *
 * It is opt-in because a `read_url` rule is also an entry in the *terminal
 * sandbox's* network allowlist. What that costs depends on which sandbox is
 * running: inside autoagy's own one, nothing at all — there is no network there
 * (`--unshare-net`, plus a seccomp filter that allows only AF_UNIX sockets), and
 * the rewrite takes the command out of agy's sandbox, which is the one the
 * allowlist governs. Without it (macOS, Windows, no bubblewrap, `ownSandbox:
 * "off"`) an unreviewed command can reach those hosts, which is the shape of
 * Codex's own network allowlist.
 *
 * `*` is the line that is not crossed. A leading `*.` is stripped, because
 * `isTrustedHost` treats `*.example.com` and `example.com` as the same rule, but
 * an entry that still holds a wildcard after that is skipped and reported rather
 * than turned into something wider than it looks — `read_url(*)` must not be
 * reachable from a configuration file. Anything that is not hostname-shaped is
 * skipped for the same reason: it would be a rule nobody can predict the meaning
 * of.
 *
 * @returns {{ grants: string[], skipped: string[] }} `skipped` is for reporting;
 *   an entry silently dropped here is a domain that keeps prompting with no
 *   explanation.
 */
export function trustedDomainGrants(config) {
  if (config?.networkGrants !== 'trusted-domains') return { grants: [], skipped: [] };
  const grants = new Set();
  const skipped = [];
  for (const raw of config.trustedDomains ?? []) {
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    const domain = raw.trim().toLowerCase().replace(/^\*\./, '');
    // Hostnames, IPv4, and the bracketed IPv6 form `trustedDomains` already uses.
    if (/[*?]/.test(domain) || !/^[a-z0-9._:[\]-]+$/.test(domain)) {
      skipped.push(raw);
      continue;
    }
    grants.add(`read_url(${domain})`);
  }
  return { grants: [...grants], skipped };
}

/**
 * Every grant a configuration needs, in the order `autoagy setup` writes them.
 * @param {object} config
 * @param {{ autoagyHome: string, home?: string }} where
 */
export function grantsFor(config, { autoagyHome, home = os.homedir() }) {
  const command = config?.commandGrant === 'executor' ? `command(${executorPath(autoagyHome)})` : 'command(*)';
  return [command, 'mcp(*)', 'execute_url(*)', ...writableRootGrants(config, home), ...trustedDomainGrants(config).grants];
}

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
  const { value: settings, readable } = readForRewrite(settingsFile);
  // Refused for the same reason `applyTeardown` refuses, one step earlier: this
  // command rewrites the file, and a file it cannot read is a file it would
  // overwrite from an empty object. The raw parse error it used to throw said
  // nothing about that.
  if (!readable) throw new Error(`${settingsFile} is not valid JSON, so autoagy setup left it alone. Fix it first (a trailing comma is the usual cause).`);
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

/**
 * The paths `autoagy setup` pinned into hooks.json, if it ran.
 *
 * The hooks always use these. Management commands are run from the user's shell,
 * which may have a different HOME or AUTOAGY_HOME than setup wrote (a launcher,
 * `sudo`, or an exported variable), and without reading the same pin they would
 * report on — and repair — a different configuration than the one in force.
 *
 * It lives here, next to the writer, because a second reader needs it too:
 * `scripts/install.mjs` runs with the plugin directory possibly already gone,
 * and it must find the same state the install wrote rather than whatever the
 * ambient environment points at.
 */
export function hookPins(pluginDir) {
  let hooks = null;
  try {
    hooks = readJsonFile(path.join(pluginDir, 'hooks.json'));
  } catch {
    return { pinned: false, command: null, configHome: null, home: null };
  }
  let command = null;
  const visit = (value) => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (value && typeof value === 'object') {
      if (command === null && typeof value.command === 'string') command = value.command;
      Object.values(value).forEach(visit);
    }
  };
  visit(hooks);
  const read = (flag) => {
    if (!command) return null;
    const match = new RegExp(`${flag}\\s+(?:"([^"]+)"|(\\S+))`).exec(command);
    return match ? match[1] ?? match[2] : null;
  };
  const configHome = read('--autoagy-home');
  const home = read('--home');
  return { pinned: Boolean(command && configHome && home), command, configHome, home };
}

export function readSetupRecord(autoagyHome) {
  try {
    return readJsonFile(setupRecordPath(autoagyHome));
  } catch {
    return null;
  }
}

/**
 * Reads a file this command is about to rewrite, and says whether it may.
 *
 * A read-modify-write that cannot read the file must stop, not proceed from an
 * empty object: `{}` is written back over everything the user had. Measured on
 * `~/.gemini/antigravity-cli/settings.json` with one syntax error in it —
 * teardown replaced the whole file with the keys it was restoring, taking
 * `model`, `theme`, `mcpServers` and the existing `permissions.deny` with it,
 * and then deleted the setup record, so the grants it was supposed to remove
 * were left in a file that could no longer be reverted at all.
 */
function readForRewrite(file) {
  if (!fs.existsSync(file)) return { value: {}, readable: true };
  try {
    return { value: readJsonFile(file), readable: true };
  } catch {
    return { value: null, readable: false };
  }
}

/** Reverts the grants and settings that setup changed. */
export function applyTeardown({ home = os.homedir(), env = process.env, dryRun = false } = {}) {
  const autoagyHome = resolveAutoagyHome(env, home);
  const record = readSetupRecord(autoagyHome);
  if (!record) return { found: false, removedGrants: [], restored: [], dryRun };
  const settingsFile = record.settingsFile ?? cliSettingsPath(home);
  const { value: settings, readable } = readForRewrite(settingsFile);
  // Nothing is written and the record is kept, so the grants are still
  // revertable once the file is fixed.
  if (!readable) return { found: true, settingsFile, unreadable: true, removedGrants: [], restored: [], dryRun };
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

/**
 * Keeps autoagy's own directory to its owner.
 *
 * Everything under it is the record of what an agent did and was allowed to do:
 * the decision log holds command lines, and with `log.reviews` it holds whole
 * transcripts. A directory created before these modes were set keeps the mode
 * it was created with, so this is called from `setup` as well — tightening the
 * top of the tree is enough, since nothing below it can be reached without it.
 */
export function restrictHomePermissions({ home = os.homedir(), env = process.env } = {}) {
  const dir = resolveAutoagyHome(env, home);
  try {
    fs.chmodSync(dir, 0o700);
    return dir;
  } catch {
    return null;
  }
}

/** Writes the default config file if none exists. */
export function ensureConfigFile({ home = os.homedir(), env = process.env, dryRun = false } = {}) {
  const file = configPath(env, home);
  if (fs.existsSync(file)) return { file, created: false };
  if (!dryRun) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, defaultConfigFileText());
  }
  return { file, created: true };
}

const quoteArg = (s) => (/[\s"'\\]/.test(s) ? JSON.stringify(s) : s);

/**
 * Pins the hook commands in hooks.json to absolute paths.
 *
 * `node` is replaced by the interpreter that ran setup, so hooks work even when
 * Antigravity is started without the user's PATH.
 *
 * `--autoagy-home` and `--home` are appended so the hook's configuration
 * directory and `~` are the ones setup wrote, rather than whatever the
 * environment says when a tool call runs. Both are otherwise taken from the
 * environment (`AUTOAGY_HOME`, then `HOME`), and a command the agent runs can
 * set either for an agy it starts — which would move the policy, the credential
 * list and the paths the agent may not edit. hooks.json lives inside the plugin
 * directory, which is in the policy's `selfPaths`, so an agent cannot rewrite
 * the pin itself.
 */
export function pinHookCommands(pluginDir, { nodePath = process.execPath, configHome = null, home = null, dryRun = false } = {}) {
  const file = path.join(pluginDir, 'hooks.json');
  const hooks = readJsonFile(file);
  let changed = 0;
  const visit = (value) => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (value && typeof value === 'object') {
      if (typeof value.command === 'string') {
        let command = value.command;
        if (/^node\s/.test(command)) command = command.replace(/^node(?=\s)/, quoteArg(nodePath));
        for (const [flag, target] of [['--autoagy-home', configHome], ['--home', home]]) {
          if (!target || command.includes(`${flag} `)) continue;
          command = `${command} ${flag} ${quoteArg(target)}`;
        }
        if (command !== value.command) {
          value.command = command;
          changed++;
        }
      }
      Object.values(value).forEach(visit);
    }
  };
  visit(hooks);
  if (changed > 0 && !dryRun) writeJsonFile(file, hooks);
  return { file, changed };
}
