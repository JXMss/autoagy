// `autoagy setup` / `autoagy teardown`: make Antigravity's own permission
// system hand approval decisions to autoagy, and undo exactly that.
//
// Measured on agy 1.2.x: a PreToolUse "allow" cannot override Antigravity's
// permission prompts, so actions autoagy should be able to auto-approve need an
// Antigravity grant. These grants do not widen the terminal sandbox:
//   command(*)      agent-requested sandbox bypass no longer prompts natively
//   mcp(*)          MCP tool calls no longer prompt natively
//   execute_url(*)  browser interactions no longer prompt natively
//   read_file(/)    reads outside the workspace no longer prompt (readGrant)
// A read_url rule is also an entry in the terminal sandbox's network allowlist
// (measured), so `read_url(*)` is written only where autoagy's own sandbox runs
// the commands (networkGrants "all", or "auto" on such a machine), and once it
// is granted agy's sandbox is not counted as one — see `trustedDomainGrants`,
// `networkGrants` in config.mjs and `detectSandbox`.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { autoagyHome as resolveAutoagyHome, defaultConfigFileText, configPath, resolveConfigPath } from './config.mjs';
import { expandHome } from './paths.mjs';
import { executorPath } from './tokens.mjs';
import { installedPluginDir } from './tripwire.mjs';

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

// What agy applies when a key is missing from its settings file. agy saves that
// file without false booleans (the field is tagged `omitempty` in the binary),
// so the `allowNonWorkspaceAccess: false` setup writes is gone the next time agy
// saves anything — trusting a new folder is enough. Measured on agy 1.2.7: right
// after such a save removed the key, a headless write outside the workspace was
// still refused ("a tool required the "write_file" permission that headless mode
// cannot prompt for"), after autoagy's own review had approved it. So a missing
// key is false. Read as "not false", it made `status` warn about a cap that was
// in force, and made the policy spend a review on an edit agy then refused.
export const AGY_SETTING_DEFAULTS = Object.freeze({ allowNonWorkspaceAccess: false });

/**
 * A setting as agy applies it: the file's value, or agy's own default when the
 * key is missing. Undefined when the settings could not be read at all, which
 * says nothing about what agy will do.
 */
export function effectiveSetting(settings, key) {
  if (!settings || typeof settings !== 'object') return undefined;
  return settings[key] ?? AGY_SETTING_DEFAULTS[key];
}

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
 * A `trustedDomains` entry never widens into `*`. A leading `*.` is stripped,
 * because `isTrustedHost` treats `*.example.com` and `example.com` as the same
 * rule, but an entry that still holds a wildcard after that is skipped and
 * reported rather than turned into something wider than it looks. The
 * network-wide grant exists only as its own explicit value, `networkGrants:
 * "all"`, never as a side effect of a list entry. Anything that is not
 * hostname-shaped is skipped for the same reason: it would be a rule nobody can
 * predict the meaning of.
 *
 * @returns {{ grants: string[], skipped: string[] }} `skipped` is for reporting;
 *   an entry silently dropped here is a domain that keeps prompting with no
 *   explanation.
 */
export function trustedDomainGrants(config, { ownSandboxPossible = false } = {}) {
  // "all" is the explicit switch for `read_url(*)`; see `networkGrants` in
  // config.mjs for why it is safe only while autoagy's own sandbox runs, and
  // `detectSandbox` for what happens to agy's sandbox once it is granted.
  const mode = networkGrantsFor(config, { ownSandboxPossible });
  if (mode === 'all') return { grants: ['read_url(*)'], skipped: [] };
  if (mode !== 'trusted-domains') return { grants: [], skipped: [] };
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
 * What `networkGrants` means on this machine: "auto" is "all" where autoagy's
 * own sandbox can run — commands then never run in the sandbox `read_url(*)`
 * opens — and "none" elsewhere.
 * @param {{ ownSandboxPossible?: boolean }} where from `ownSandboxPossible` in confine.mjs
 */
export function networkGrantsFor(config, { ownSandboxPossible = false } = {}) {
  const mode = config?.networkGrants ?? 'none';
  if (mode !== 'auto') return mode;
  return ownSandboxPossible ? 'all' : 'none';
}

/**
 * Every grant a configuration needs, in the order `autoagy setup` writes them.
 * @param {object} config
 * @param {{ autoagyHome: string, home?: string }} where
 */
export function grantsFor(config, { autoagyHome, home = os.homedir(), ownSandboxPossible = false }) {
  const command = config?.commandGrant === 'executor' ? `command(${executorPath(autoagyHome)})` : 'command(*)';
  return [command, 'mcp(*)', 'execute_url(*)', ...readGrants(config), ...writableRootGrants(config, home), ...trustedDomainGrants(config, { ownSandboxPossible }).grants];
}

/**
 * The read grant `readGrant` asks for: `read_file(/)` unless it is "none".
 *
 * `allowNonWorkspaceAccess: false` caps reads as well as writes, so without it
 * every read outside the workspace prompts (measured on agy 1.2.7). A read is
 * something Codex allows anywhere, and autoagy has already reviewed a
 * credential read before agy is asked, so only the write cap is worth keeping.
 */
export function readGrants(config) {
  return config?.readGrant === 'none' ? [] : ['read_file(/)'];
}

/**
 * The setup record, when `autoagy setup` has written grants and there is no
 * plugin where agy loads plugins from — or null.
 *
 * That combination is the fail-open in full: standing grants, nothing loaded,
 * nothing watching. It is reached by running `setup` and skipping `agy plugin
 * install`, which is following half the README. The question is asked of the
 * install location and never of where the asking code runs: a `status` run from a
 * checkout beside a real install would otherwise report a plugin that is there as
 * missing, which is the false positive the first version of this check had.
 */
/**
 * Grants an earlier `setup` added that are still in the settings file although
 * the configuration no longer asks for them. `setup` takes these out; `status`
 * names them, so a file that was narrowed on paper only is visible.
 * @param {string[]} allow the file's `permissions.allow`
 */
export function staleGrants(config, allow, { autoagyHome, home = os.homedir(), ownSandboxPossible = false }) {
  const wanted = grantsFor(config, { autoagyHome, home, ownSandboxPossible });
  return (readSetupRecord(autoagyHome)?.addedGrants ?? []).filter((g) => allow.includes(g) && !wanted.includes(g));
}

export function halfInstalledRecord({ autoagyHome, home = os.homedir() }) {
  const record = readSetupRecord(autoagyHome);
  if (!record?.addedGrants?.length) return null;
  return fs.existsSync(path.join(installedPluginDir(home), 'hooks.json')) ? null : record;
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

/**
 * Computes the settings changes setup would make.
 *
 * `recorded` is what earlier runs added (the setup record). A grant in it that is
 * still in the file and that the configuration no longer asks for is taken out:
 * setup used to only ever add, so turning `networkGrants` back to "none",
 * dropping a `writableRoots` entry or switching `commandGrant` to "executor" left
 * the old `read_url(…)`, `write_file(…)` or `command(*)` in place — while setup
 * printed "read_url(...) is not granted" and `status` "network grants none",
 * both worked out from the configuration. A `read_url` rule is also the terminal
 * sandbox's network allowlist, so the narrowing the user asked for did not
 * happen and they were told it had. Only autoagy's own grants are touched: one
 * the user wrote is not in the record.
 */
export function planSetup(settings, { grants = RECOMMENDED_GRANTS, settingsChanges = true, recorded = [] } = {}) {
  const allow = Array.isArray(settings.permissions?.allow) ? settings.permissions.allow : [];
  const deny = Array.isArray(settings.permissions?.deny) ? settings.permissions.deny : [];
  const addGrants = grants.filter((g) => !allow.includes(g));
  const removeGrants = [...new Set(recorded)].filter((g) => allow.includes(g) && !grants.includes(g));
  const conflicting = grants.filter((g) => deny.includes(g));
  const changes = [];
  if (settingsChanges) {
    // Compared as agy applies them: writing a key agy already defaults to the
    // same value is a change that agy undoes at its next save, and it made every
    // later `setup` report a change and take a backup for nothing.
    for (const [key, value] of Object.entries(RECOMMENDED_SETTINGS)) {
      if (effectiveSetting(settings, key) !== value) changes.push({ key, from: settings[key], to: value });
    }
  }
  return { addGrants, removeGrants, changes, conflicting };
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
  const previous = readSetupRecord(autoagyHome);
  const plan = planSetup(settings, { grants, settingsChanges, recorded: previous?.addedGrants ?? [] });
  const report = { settingsFile, ...plan, backup: null, dryRun };
  if (dryRun || (plan.addGrants.length === 0 && plan.removeGrants.length === 0 && plan.changes.length === 0)) return report;

  fs.mkdirSync(path.dirname(settingsFile), { recursive: true });
  if (fs.existsSync(settingsFile)) {
    report.backup = `${settingsFile}.autoagy-backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(settingsFile, report.backup);
  }
  const next = JSON.parse(JSON.stringify(settings));
  next.permissions = { ...(next.permissions ?? {}) };
  const kept = (Array.isArray(next.permissions.allow) ? next.permissions.allow : []).filter((g) => !plan.removeGrants.includes(g));
  next.permissions.allow = [...kept, ...plan.addGrants];
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
    // What teardown will take back: everything added so far, minus what this run
    // already took back.
    addedGrants: [...new Set([...(previous?.addedGrants ?? []), ...plan.addGrants])].filter((g) => !plan.removeGrants.includes(g)),
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
