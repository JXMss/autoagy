#!/usr/bin/env node
// autoagy — Codex-style auto mode ("Approve for me") for Google Antigravity.
//
//   autoagy hook pre-tool-use|post-tool-use|post-invocation   (called by hooks.json)
//   autoagy status | log [-n N] | denials | approve <id> | trust [<id>] | mode <auto|ask|off>
//   autoagy review --tool NAME --args JSON [--transcript FILE] [--workspace DIR] [--classify-only]
//   autoagy setup [--dry-run] [--no-settings] | teardown [--dry-run]

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadConfig, autoagyHome as resolveAutoagyHome, configPath } from '../lib/config.mjs';
import { HookContext, PLUGIN_DIR, detectSandbox } from '../lib/context.mjs';
import { findExecutable } from '../lib/paths.mjs';
import { detectOwnSandbox, readSandboxCheck, envBinaryPath, removeControlPlaceholders, lockQuiescent, flockPath } from '../lib/confine.mjs';
import { classify, failOpenOutput } from '../lib/policy.mjs';
import { hookBudgetSec } from '../lib/timeout.mjs';
import { handlePreToolUse, handlePostToolUse, handlePostInvocation, failClosedOutput } from '../lib/hook.mjs';
import { gatherEvidence, buildReviewPrompt, runReview, decisionFor, TIMEOUT_INSTRUCTIONS } from '../lib/guardian.mjs';
import { createReviewer } from '../lib/reviewers.mjs';
import { appendDecision, readDecisions, decisionLogPath } from '../lib/log.mjs';
import { listStates, updateState, readState, isUntrusted, readHeartbeat } from '../lib/state.mjs';
import { applySetup, applyTeardown, ensureConfigFile, pinHookCommands, cliSettingsPath, grantsFor, writableRootGrants, readSetupRecord } from '../lib/setup.mjs';
import { installExecutor, executorPath, executorInstalled } from '../lib/tokens.mjs';
import { installTripwire, removeTripwire, tripwireInstalled, tripwirePath, userHooksPath } from '../lib/tripwire.mjs';

/**
 * The home directory the account database reports. `HOME` can be set for a
 * single command, which would move `~` for the policy (`~/.ssh/**` and friends)
 * and for the paths the agent must never edit; this cannot be.
 */
export function accountHome() {
  try {
    return os.userInfo().homedir || os.homedir();
  } catch {
    return os.homedir();
  }
}

/**
 * The paths `autoagy setup` pinned into hooks.json, if it ran.
 *
 * The hooks always use these. Management commands are run from the user's shell,
 * which may have a different HOME or AUTOAGY_HOME than setup wrote (a launcher,
 * sudo, or an exported variable), and without reading the same pin they would
 * report on — and repair — a different configuration than the one in force.
 */
export function hookPins(pluginDir = PLUGIN_DIR) {
  const hooks = readJsonQuiet(path.join(pluginDir, 'hooks.json'));
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

/**
 * Environment, user home and configuration directory for a management command.
 * The pin wins where it exists; without one the ambient environment decides, as
 * it did before — a dev checkout and the test harness rely on that.
 */
function managementContext() {
  const pins = hookPins();
  const env = { ...process.env };
  if (pins.configHome) env.AUTOAGY_HOME = pins.configHome;
  const home = pins.home || accountHome();
  return { env, home, autoagyHome: resolveAutoagyHome(env, home), pins };
}

/** The conversation's trust flag, for the watchdog and error fallbacks. */
function stateIsUntrusted(payload, env, home) {
  try {
    return isUntrusted(readState(resolveAutoagyHome(env, home), payload?.conversationId));
  } catch {
    return false;
  }
}

/**
 * @param {string} event
 * @param {{ configHome?: string|null, home?: string|null }} [pinned] the values
 *   `autoagy setup` wrote into hooks.json, so a command cannot relocate the
 *   configuration or `~` for the hook that judges it.
 */
async function runHook(event, pinned = {}) {
  let input = '';
  try {
    input = fs.readFileSync(0, 'utf8');
  } catch {
    input = '';
  }
  let payload = {};
  try {
    payload = JSON.parse(input || '{}');
  } catch {
    payload = {};
  }
  let emitted = false;
  const emit = (output) => {
    if (emitted) return;
    emitted = true;
    const text = output === null || output === undefined ? '' : JSON.stringify(output);
    process.stdout.write(text, () => process.exit(0));
  };
  const env = { ...process.env };
  // Pinned wins over the inherited environment, so a command cannot point the
  // hook at a configuration directory it can write.
  if (pinned.configHome) env.AUTOAGY_HOME = pinned.configHome;
  const home = pinned.home || accountHome();
  // Answer before Antigravity kills the hook, which would fail the tool call with an opaque error.
  const budgetSec = hookBudgetSec(event, { pluginDir: PLUGIN_DIR });
  // The failure paths ask the policy one question that needs the configuration:
  // whether a search is supposed to be reviewed. Both refuse to answer anything
  // else about it, so a config that cannot be read leaves the previous
  // behaviour in place rather than turning a failure into an allow.
  const safeConfig = () => {
    try {
      return loadConfig({ env, home }).config;
    } catch {
      return null;
    }
  };
  const watchdog = setTimeout(() => {
    if (event !== 'pre-tool-use') return emit({});
    // Best effort: a conversation whose paths were already swapped loses its
    // content reads here too. A read failure is treated as trusted, which is
    // safe because everything that changes anything is already refused below.
    emit(failOpenOutput(payload, { untrusted: stateIsUntrusted(payload, env, home), reason: TIMEOUT_INSTRUCTIONS, config: safeConfig() }));
  }, budgetSec * 1000);
  watchdog.unref();
  try {
    if (event === 'pre-tool-use') {
      const { config } = loadConfig({ env, home });
      // Keep the review deadline (plus process teardown) inside the hook budget.
      const maxReview = Math.max(3, budgetSec - 3);
      if (config.reviewer.timeoutSec > maxReview) env.AUTOAGY_REVIEW_TIMEOUT_CAP = String(maxReview);
      emit(await handlePreToolUse(payload, { env, home }));
    } else if (event === 'post-tool-use') {
      emit(handlePostToolUse(payload, { env, home }));
    } else if (event === 'post-invocation') {
      emit(handlePostInvocation(payload, { env, home }));
    } else {
      emit({});
    }
  } catch (err) {
    appendDecision(resolveAutoagyHome(env, home), {
      conversation: payload?.conversationId,
      tool: payload?.toolCall?.name,
      verdict: 'error',
      error: String(err?.stack ?? err).slice(0, 2000),
    });
    emit(event === 'pre-tool-use' ? failClosedOutput(payload, err, { untrusted: stateIsUntrusted(payload, env, home), config: safeConfig() }) : {});
  }
}

// ---------------------------------------------------------------------------
// Management commands

function parseFlags(args) {
  const flags = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const [name, inline] = arg.slice(2).split(/=(.*)/s);
      if (inline !== undefined) flags[name] = inline;
      else if (args[i + 1] !== undefined && !args[i + 1].startsWith('-')) flags[name] = args[++i];
      else flags[name] = true;
    } else if (arg === '-n') {
      flags.n = args[++i];
    } else {
      flags._.push(arg);
    }
  }
  return flags;
}

/** A flag's value when it was given as `--name value`, otherwise null. */
const strFlag = (value) => (typeof value === 'string' && value !== '' ? value : null);

const fmtTime = (iso) => (iso ? iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '');

/** "3 minutes", "2 days": for a heartbeat the exact seconds do not matter. */
function ageText(ms) {
  const minutes = Math.round(ms / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? '' : 's'}`;
}

/**
 * Clears the "untrusted" flag. The flag is set when the environment did
 * something autoagy did not approve — an edit whose target resolved elsewhere,
 * or a command that wrote into a directory the sandbox hid — and it is never
 * cleared by starting a new turn, because a swapped symlink outlives the turn.
 * Clearing it is therefore a claim about the filesystem that only a person can
 * make, which is why it is a command rather than an automatic expiry.
 */
const flagDescription = (state) => {
  const parts = [];
  if (state.untrusted) parts.push(`untrusted: ${state.untrusted.reason}${state.untrusted.detail ? ` (${state.untrusted.detail})` : ''}`);
  if (state.backgroundSuspected) parts.push('a backgrounded command may still be running, so read-only mount points are retained');
  const planted = state.plantedHooks ?? [];
  if (planted.length > 0) {
    const named = planted.slice(0, 3).map((p) => p.path).join(', ');
    parts.push(`${planted.length} planted git hook${planted.length === 1 ? '' : 's'} (${named}${planted.length > 3 ? ', …' : ''})`);
  }
  return parts.join('; ');
};

/**
 * A conversation something has to look at by hand. `trust` is the looking: it
 * releases the mount points, the untrusted mark and the planted-hook records in
 * one gesture, because all three are claims about the same thing — what is on the
 * filesystem right now.
 */
const flagged = (state) => isUntrusted(state) || state.backgroundSuspected === true || (state.plantedHooks ?? []).length > 0;

function trust(prefix, all, force) {
  const { autoagyHome: home } = managementContext();
  const states = listStates(home).filter(({ state }) => flagged(state));
  if (states.length === 0) return console.log('No conversation is flagged.');
  // A bare `autoagy trust` lists rather than clearing: releasing every
  // conversation at once is a decision about the filesystem that the user
  // should make deliberately, not the default reading of an omitted argument.
  if (!all && !prefix) {
    console.log('These conversations are flagged. Pass a conversation id prefix, or --all, to release them:');
    for (const { state } of states) console.log(`  ${state.conversationId}  ${flagDescription(state)}`);
    return;
  }
  const chosen = all ? states : states.filter(({ state }) => String(state.conversationId).startsWith(prefix));
  if (chosen.length === 0) {
    console.log(`No flagged conversation matches "${prefix}". Flagged:`);
    for (const { state } of states) console.log(`  ${state.conversationId}  ${flagDescription(state)}`);
    return;
  }
  // Mount points are workspace-level artifacts but the record of them is
  // per-conversation, so another conversation may be holding a command that
  // needs the very directory this one is about to release. Removing it would
  // pull the mount out from under that command, so refuse rather than guess.
  const others = new Map();
  for (const { state } of listStates(home)) {
    if (chosen.some((c) => c.state.conversationId === state.conversationId)) continue;
    for (const p of Object.values(state.pendingPlaceholders ?? {}).flatMap((list) => list ?? [])) {
      if (!others.has(p)) others.set(p, state.conversationId);
    }
  }
  const chosenPaths = new Set(chosen.flatMap(({ state }) => Object.values(state.pendingPlaceholders ?? {}).flatMap((list) => list ?? [])));
  const shared = [...chosenPaths].filter((p) => others.has(p));

  for (const { state } of chosen) {
    // "Nothing is running" is this command's whole premise, and it is now a
    // question the lock can answer — so ask it rather than take the word for it.
    const held = state.pendingLock ? lockQuiescent(null, { lockFile: state.pendingLock }) : null;
    if (held === false && !force) {
      console.log(`Kept: ${state.conversationId}`);
      console.log(`  ! a sandboxed command is still running against ${state.pendingLock};`);
      console.log('    releasing the mount points now would take them out from under it. Re-run with --force if you know better.');
      continue;
    }
    console.log(`Trusted again: ${state.conversationId}`);
    console.log(`  was flagged for ${flagDescription(state)}`);
    // The mount points are released here rather than at the conversation's next
    // turn: this command IS the assertion that nothing is still running, and a
    // conversation that never gets another turn would otherwise leave empty
    // `.agents`-style directories in the workspace with nothing recording them.
    const paths = Object.values(state.pendingPlaceholders ?? {}).flatMap((list) => list ?? []).filter((p) => !others.has(p));
    updateState(home, state.conversationId, (s) => {
      s.untrusted = null;
      s.backgroundSuspected = false;
      s.pendingPlaceholders = {};
      // Dropped without being inspected: this command has no hook payload, so it
      // has no workspace to walk. That is the same premise as the mount points —
      // the user is asserting they have looked at what changed on disk.
      s.pendingNestedGit = {};
      s.plantedHooks = [];
    });
    const { removed, dirty } = removeControlPlaceholders(paths);
    if (removed.length) console.log(`  released ${removed.length} read-only mount point(s)`);
    for (const p of dirty) console.log(`  ! kept ${p}: it has contents, so something wrote into it`);
  }
  for (const p of shared) {
    console.log(`  ! kept ${p}: conversation ${others.get(p)} also has a mount point there`);
  }
  if (shared.length > 0) {
    console.log('Some mount points are shared with another conversation, which may still have a command running against');
    console.log('them, so they were kept. Release that conversation too once you know it is idle.');
  }
  console.log('Only do this once you have checked what changed on disk AND know that no backgrounded command is still running.');
}

function readJsonQuiet(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function status() {
  // `userHome` (not `home`) so a later call cannot silently take the user's
  // home directory where the configuration directory is meant.
  const { env, home: userHome, autoagyHome, pins } = managementContext();
  const { config, warnings, path: cfgPath, exists } = loadConfig({ env, home: userHome });
  const lines = [];
  lines.push(`autoagy — Codex-style auto mode for Antigravity`);
  lines.push(`  plugin dir      ${PLUGIN_DIR}`);
  lines.push(`  config          ${cfgPath}${exists ? '' : ' (not found — using defaults)'}`);
  // The hooks read a pin written at setup time, not the ambient environment. If
  // the two disagree, this report describes a different configuration than the
  // one that is actually judging tool calls.
  const installed = PLUGIN_DIR.includes(path.join('.gemini', 'config', 'plugins'));
  if (pins.pinned) {
    lines.push(`  home            ${pins.home}   (pinned by autoagy setup)`);
    const ambientHome = resolveAutoagyHome();
    if (ambientHome !== pins.configHome) {
      lines.push(`  ! this shell would use ${ambientHome}; the hooks use the pinned ${pins.configHome}`);
    }
  } else if (installed) {
    // The pin is written by `autoagy setup`, and `agy plugin install` replaces
    // hooks.json with the unpinned copy from the source tree — so an installed
    // plugin without a pin went in without setup, or was updated around it.
    lines.push('  home            not pinned');
    lines.push('  ! the installed hooks.json has no pinned configuration directory, so the hooks take the');
    lines.push('    config directory and home from the environment agy inherits. Run `autoagy setup`.');
  }
  lines.push(`  mode            ${config.mode}${config.mode === 'auto' ? ' (Approve for me: risky actions go to the reviewer model)' : config.mode === 'ask' ? ' (risky actions prompt you)' : ' (no review; sandbox escapes, MCP and browser actions prompt you)'}`);
  const model = config.reviewer.backend === 'agy' ? config.reviewer.agy.model ?? '(your default agy model)' : config.reviewer.openai.model;
  lines.push(`  reviewer        ${config.reviewer.backend}${config.reviewer.backend === 'none' ? '' : `, model ${model}, ${config.reviewer.timeoutSec}s deadline`}`);
  if (config.reviewer.backend === 'openai') {
    lines.push(`  api key         ${config.reviewer.openai.apiKeyEnv} ${process.env[config.reviewer.openai.apiKeyEnv] ? 'is set' : 'is NOT set'}`);
  }
  if (config.reviewer.backend === 'agy') {
    // Inside a session, reviews run the agy CLI of that session unless reviewer.agy.command is an absolute path.
    const command = config.reviewer.agy.command;
    const exe = path.isAbsolute(command) ? command : findExecutable(command, process.env.PATH);
    const probe = exe ? spawnSync(exe, ['--version'], { encoding: 'utf8', timeout: 10000, shell: process.platform === 'win32' && !/\.exe$/i.test(exe) }) : null;
    lines.push(`  agy             ${probe?.status === 0 ? `found at ${exe} (${probe.stdout.trim()})` : `NOT runnable as "${command}"`}`);
  }
  const own = detectOwnSandbox({ config, host: null, appDataDir: path.dirname(cliSettingsPath()), autoagyHome: autoagyHome });
  lines.push(`  own sandbox     ${own.active ? 'active' : own.required ? 'REQUIRED BUT UNAVAILABLE (commands are reviewed)' : 'inactive'} — ${own.detail}`);
  // What the command grant is worth when the hook is not running is the whole
  // reason the executor exists, so say which of the two shapes is in force.
  if (config.commandGrant === 'executor') {
    lines.push(`  command grant   one program (${executorPath(autoagyHome)})${executorInstalled(autoagyHome) ? '' : ' — NOT INSTALLED, run `autoagy setup`'}`);
    const settingsNow = readJsonQuiet(cliSettingsPath());
    if (settingsNow && settingsNow.allowNonWorkspaceAccess !== false) {
      lines.push('  ! that grant only stays narrow while the executor cannot be overwritten. A file-editing');
      lines.push('    tool can still write outside the workspace here (allowNonWorkspaceAccess is not false),');
      lines.push('    and a hook that is not running refuses nothing. Set it to false to close that.');
    }
  } else {
    lines.push('  command grant   command(*) — a standing licence to run anything, which keeps working if the hook stops (see commandGrant: "executor")');
  }
  // The degraded mode is worth saying out loud rather than falling back in
  // silence: without a usable `flock`, autoagy cannot tell whether a sandboxed
  // command is still running, so it has to guess — and the guess can be wrong in
  // the direction that takes a mount point out from under a command.
  if (own.active && !flockPath()) {
    lines.push('  ! liveness      no root-owned `flock` (usually util-linux), so autoagy cannot tell whether a');
    lines.push('                  sandboxed command is still running. Read-only mount points for protected');
    lines.push('                  directories are retained until `autoagy trust`.');
  }
  const check = readSandboxCheck(autoagyHome);
  if (check?.status === 'broken') {
    lines.push(`  ! self-check    FAILED ${fmtTime(check.time)}: ${check.detail}. The own sandbox is off for that agy build; it is checked again after agy updates.`);
  } else if (check?.status === 'verified') {
    lines.push(`  self-check      agy ran ${check.verified} rewritten command(s) as expected (last ${fmtTime(check.time)})`);
  } else if (own.active) {
    lines.push('  self-check      no command has run in the own sandbox yet');
  }
  // The env-scrub rewrite has its own check: it is the rewrite that runs where
  // there is no sandbox, and it fails independently of the sandbox one.
  if (config.commandEnv?.mode === 'scrub' && !own.active) {
    const scrub = readSandboxCheck(autoagyHome, 'envScrub');
    if (!envBinaryPath()) {
      // Saying "no command has run yet" here would claim a rewrite that this
      // platform cannot perform: there is no `env` to run commands under.
      lines.push(`  ! command env   "scrub" is set, but ${process.platform} has no root-owned \`env\` to rewrite commands with, so they keep the environment agy was started with`);
    } else if (scrub?.status === 'broken') {
      lines.push(`  ! command env   SELF-CHECK FAILED ${fmtTime(scrub.time)}: ${scrub.detail}. Commands keep the environment agy was started with, for that agy build.`);
    } else if (scrub?.status === 'verified') {
      lines.push(`  command env     scrubbed: agy ran ${scrub.verified} rewritten command(s) as expected (last ${fmtTime(scrub.time)})`);
    } else {
      lines.push('  command env     to be scrubbed by rewriting each command under `env -i`; no command has run yet');
    }
  }
  for (const w of warnings) lines.push(`  ! config: ${w}`);

  const settingsFile = cliSettingsPath();
  const settings = readJsonQuiet(settingsFile);
  lines.push('');
  lines.push(`Antigravity CLI settings (${settingsFile}):`);
  if (!settings) {
    lines.push('  (not found)');
  } else {
    const allow = settings.permissions?.allow ?? [];
    lines.push(`  enableTerminalSandbox   ${settings.enableTerminalSandbox}`);
    lines.push(`  toolPermission          ${settings.toolPermission}`);
    lines.push(`  allowNonWorkspaceAccess ${settings.allowNonWorkspaceAccess}`);
    lines.push(`  permissions.allow       ${JSON.stringify(allow)}`);
    const wanted = grantsFor(config, { autoagyHome, home: userHome });
    const missing = wanted.filter((g) => !allow.includes(g));
    if (missing.length) lines.push(`  ! missing grants ${missing.join(', ')} — approved actions may still prompt; run \`autoagy setup\``);
    // The grants are read once when agy starts (measured), so a writableRoots
    // entry added after the last setup has no grant and simply will not work.
    const rootsMissing = writableRootGrants(config, userHome).filter((g) => !allow.includes(g));
    if (rootsMissing.length) {
      lines.push(`  ! writableRoots changed since the last \`autoagy setup\`: ${rootsMissing.length} of them have no write_file grant,`);
      lines.push('    so edits there are refused however autoagy classifies them. Re-run `autoagy setup`.');
    }
    if (config.commandGrant === 'executor' && allow.includes('command(*)')) {
      lines.push('  ! command(*) is still granted, which makes the narrow executor grant pointless — remove it');
    }
    if (allow.some((g) => /^read_url\(\*\)$/.test(g))) lines.push('  ! read_url(*) is granted: sandboxed commands can reach any host without review');
    // Report what the policy will actually conclude, not what the file says: on
    // a platform where the process arguments cannot be read, detectSandbox
    // refuses to trust this file, and the difference is worth showing.
    const sandbox = detectSandbox({ config, host: null, appDataDir: path.dirname(settingsFile), own });
    lines.push(`  terminal sandbox        ${sandbox.active ? 'in force' : 'not in force'} (${sandbox.source}) — ${sandbox.detail}`);
    if (!sandbox.active && config.sandbox !== 'on' && !own.active) lines.push('  ! every command that is not known read-only will be reviewed');
  }
  // The one thing that still runs when the plugin does not, so whether it is
  // there is the difference between "fails closed" and "fails silently".
  const tw = tripwireInstalled({ autoagyHome, home: userHome });
  lines.push(`  tripwire        ${tw ? `installed (${userHooksPath(userHome)}) — tool calls are refused if the plugin stops loading` : 'NOT installed — if the plugin stops loading, nothing notices and the grants above still apply'}`);
  const record = readSetupRecord(autoagyHome);
  lines.push(`  setup record            ${record ? `${fmtTime(record.time)} (grants added: ${record.addedGrants?.join(', ') || 'none'})` : 'none'}`);

  const hooks = readJsonQuiet(path.join(PLUGIN_DIR, 'hooks.json'));
  const command = hooks?.autoagy?.PreToolUse?.[0]?.hooks?.[0]?.command;
  lines.push('');
  lines.push(`Hook command: ${command ?? '(hooks.json not found)'}`);
  // A plugin that is not loading cannot say so: the three ways it goes missing —
  // `agy plugin disable`, an `agy plugin install` that replaced the pinned
  // hooks.json, or the pinned interpreter breaking — all look like silence from
  // inside. The hook leaves a mark instead, and this is how stale it is.
  const heartbeat = readHeartbeat(autoagyHome);
  if (heartbeat) {
    const ageMs = Date.now() - Date.parse(heartbeat.at);
    lines.push(`  hooks last ran  ${fmtTime(heartbeat.at)} (${ageText(ageMs)} ago)`);
    if (installed && ageMs > 24 * 3600 * 1000) {
      lines.push('  ! if you have used agy since then, its hooks are not loading: check that the plugin is');
      lines.push('    enabled, that the hook command above is intact, and that the interpreter it names runs');
      lines.push('    (`agy plugin list`, `agy plugin enable autoagy`). Until then no tool call is being');
      lines.push('    reviewed, while the permission grants from `autoagy setup` still apply.');
    }
  } else if (installed) {
    lines.push('  ! hooks         plugin installed but no hook has ever run: nothing is being reviewed');
  }

  const recent = readDecisions(autoagyHome, 500).filter((r) => r.review);
  const counts = {};
  for (const r of recent) counts[r.review.status] = (counts[r.review.status] ?? 0) + 1;
  lines.push(`Recent reviews: ${recent.length ? Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') : 'none'}  (log: ${decisionLogPath(autoagyHome)})`);
  // A flagged conversation keeps its sandbox protection turned up and, while a
  // command may still be running, retains its read-only mount points. Nothing
  // clears that by itself, so it has to be visible somewhere.
  const flaggedStates = listStates(autoagyHome).filter(({ state }) => flagged(state));
  if (flaggedStates.length > 0) {
    lines.push('');
    lines.push(`Flagged conversations (\`autoagy trust <id>\` to release):`);
    for (const { state } of flaggedStates) lines.push(`  ${state.conversationId}  ${flagDescription(state)}`);
  }
  console.log(lines.join('\n'));
}

function printLog(flags) {
  const limit = Number(flags.n ?? 20);
  const records = readDecisions(managementContext().autoagyHome, limit);
  if (records.length === 0) return console.log('No decisions logged yet.');
  for (const r of records) {
    const review = r.review ? ` [${r.review.backend} ${r.review.status}${r.review.risk ? `, risk ${r.review.risk}` : ''}${r.review.latencyMs ? `, ${(r.review.latencyMs / 1000).toFixed(1)}s` : ''}]` : '';
    console.log(`${fmtTime(r.time)}  ${String(r.verdict).padEnd(9)} ${r.tool ?? ''}${review}${r.denialId ? ` id=${r.denialId}` : ''}`);
    if (r.summary) console.log(`    ${r.summary}`);
    const why = r.review?.rationale ?? r.review?.error ?? r.reason ?? r.error;
    if (why) console.log(`    → ${why}`);
  }
}

function listDenials() {
  const { autoagyHome: home } = managementContext();
  const rows = [];
  for (const { state } of listStates(home)) {
    for (const d of state.denials ?? []) rows.push({ ...d, conversation: state.conversationId });
  }
  rows.sort((a, b) => (a.time < b.time ? 1 : -1));
  if (rows.length === 0) return console.log('No recent auto-review denials.');
  console.log('Auto-review denials (newest first). Approve one retry with: autoagy approve <id>\n');
  for (const d of rows.slice(0, 30)) {
    console.log(`${d.id}  ${fmtTime(d.time)}  risk ${d.risk ?? '?'}  conversation ${String(d.conversation).slice(0, 8)}`);
    console.log(`    ${d.summary}`);
    console.log(`    → ${d.rationale ?? 'no rationale'}`);
  }
}

function approve(id) {
  if (!id) throw new Error('usage: autoagy approve <denial-id>');
  const { autoagyHome: home } = managementContext();
  for (const { state } of listStates(home)) {
    const denial = (state.denials ?? []).find((d) => d.id === id);
    if (!denial) continue;
    updateState(home, state.conversationId, (s) => {
      s.approvals.push({ id, actionKey: denial.actionKey, time: new Date().toISOString(), rationale: denial.rationale });
    });
    console.log('Approval recorded for one retry of the selected auto-review denial.');
    console.log('The reviewer will see your approval; the retry still goes through auto-review, and critical-risk actions stay denied.');
    console.log(`Action: ${denial.summary}`);
    return;
  }
  throw new Error(`no recent denial with id ${id} (see \`autoagy denials\`)`);
}

function setMode(mode) {
  const { env, home } = managementContext();
  if (!['auto', 'ask', 'off'].includes(mode)) throw new Error('usage: autoagy mode <auto|ask|off>');
  ensureConfigFile({ env, home });
  const file = configPath(env, home);
  const config = readJsonQuiet(file) ?? {};
  config.mode = mode;
  fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`);
  console.log(`autoagy mode set to "${mode}" (${file}). It applies to the next tool call; no restart needed.`);
}

async function dryRunReview(flags) {
  if (!flags.tool) throw new Error('usage: autoagy review --tool NAME --args JSON [--transcript FILE] [--workspace DIR] [--classify-only]');
  const args = flags.args ? JSON.parse(flags.args) : {};
  const { config } = loadConfig();
  const workspace = path.resolve(flags.workspace ?? process.cwd());
  const payload = {
    conversationId: flags.conversation ?? 'autoagy-dry-run',
    stepIdx: 0,
    toolCall: { name: flags.tool, args },
    transcriptPath: flags.transcript ? path.resolve(flags.transcript) : undefined,
    // Lets sandbox detection find the Antigravity CLI settings.
    artifactDirectoryPath: path.join(os.homedir(), '.gemini', 'antigravity-cli', 'brain', 'autoagy-dry-run'),
    workspacePaths: [workspace],
  };
  const ctx = new HookContext(payload, { config, host: null });
  const classification = classify(ctx);
  console.log(`Layer 1: ${classification.verdict} (${classification.category})${classification.reason ? `\n  ${classification.reason}` : ''}`);
  console.log(`  sandbox: ${ctx.sandbox.active ? 'active' : 'not active'} — ${ctx.sandbox.detail}`);
  if (flags.tool === 'run_command' && args.BypassSandbox !== true && ctx.ownSandbox.active) console.log("  if allowed, the command runs inside autoagy's own sandbox");
  if (classification.verdict !== 'review' || flags['classify-only']) return;
  const reviewer = createReviewer(config, { autoagyHome: ctx.autoagyHome, executable: ctx.reviewerExecutable });
  if (!reviewer) return console.log('No reviewer model configured (mode ask / backend none): the user would be asked.');
  const evidence = gatherEvidence(ctx, { rootConversationId: null });
  const prompt = buildReviewPrompt(ctx, classification, evidence);
  if (flags['show-prompt']) console.log(`\n----- system -----\n${prompt.system}\n----- user -----\n${prompt.user}`);
  console.log(`\nLayer 2: asking the ${reviewer.name} reviewer...`);
  const result = await runReview(prompt, reviewer, config.reviewer);
  console.log(`  status:  ${result.status} after ${(result.latencyMs / 1000).toFixed(1)}s (${result.attempts} attempt(s))`);
  if (result.assessment) console.log(`  risk:    ${result.assessment.risk_level}, authorization: ${result.assessment.user_authorization}\n  reason:  ${result.assessment.rationale}`);
  if (result.error) console.log(`  error:   ${result.error}`);
  const decision = decisionFor(result, config);
  console.log(`  hook decision: ${decision.decision}`);
}

function setup(flags) {
  const dryRun = Boolean(flags['dry-run']);
  const cfg = ensureConfigFile({ dryRun });
  console.log(`${cfg.created ? (dryRun ? 'Would create' : 'Created') : 'Keeping'} config ${cfg.file}`);
  const installedRoot = path.join(os.homedir(), '.gemini', 'config', 'plugins');
  if (PLUGIN_DIR.startsWith(installedRoot) || flags['pin-node']) {
    const pin = pinHookCommands(PLUGIN_DIR, { configHome: resolveAutoagyHome(process.env, accountHome()), home: accountHome(), dryRun });
    console.log(pin.changed ? `${dryRun ? 'Would pin' : 'Pinned'} hook interpreter to ${process.execPath}` : 'Hook interpreter already pinned');
  }
  const { config } = loadConfig();
  const home = resolveAutoagyHome(process.env, accountHome());
  if (config.commandGrant === 'executor') {
    if (!dryRun) installExecutor(home);
    console.log(`${dryRun ? 'Would install' : 'Installed'} the token executor at ${executorPath(home)}`);
    console.log('  the command grant names that program instead of `command(*)`, so a hook that stops running leaves nothing usable behind');
  }
  if (flags['no-settings']) {
    console.log('Skipping Antigravity settings (--no-settings). Approved actions may still show Antigravity prompts.');
    return;
  }
  const report = applySetup({ dryRun, grants: grantsFor(config, { autoagyHome: home, home: accountHome() }) });
  // The tripwire exists because those grants do: it is installed where the
  // grants are, and `--no-settings` (which writes none) gets none.
  if (!dryRun && PLUGIN_DIR.startsWith(installedRoot)) {
    const tw = installTripwire({ autoagyHome: home, home: accountHome(), pluginDir: PLUGIN_DIR });
    console.log(`\nTripwire: ${tw.script}`);
    console.log(`  registered in ${tw.hooks}, which \`agy plugin\` does not manage — so it keeps running when`);
    console.log('  the plugin is disabled or its hooks.json is replaced, and refuses tool calls rather than let');
    console.log('  the grants above apply with nobody reviewing. `autoagy teardown` removes it.');
  }
  console.log(`\nAntigravity CLI settings: ${report.settingsFile}`);
  if (report.addGrants.length === 0 && report.changes.length === 0) console.log('  already configured');
  for (const g of report.addGrants) console.log(`  ${dryRun ? 'would add' : 'added'} permissions.allow ${g}`);
  for (const c of report.changes) console.log(`  ${dryRun ? 'would set' : 'set'} ${c.key}: ${JSON.stringify(c.from)} -> ${JSON.stringify(c.to)}`);
  for (const g of report.conflicting) console.log(`  ! ${g} is also in permissions.deny; deny wins, so those actions stay blocked`);
  if (report.backup) console.log(`  backup: ${report.backup}`);
  console.log('\nread_url(...) is intentionally not granted: it would also open the terminal sandbox to the network.');
  console.log('Antigravity IDE / Antigravity 2.0: add the same grants under Settings → Permission Grants and keep the terminal sandbox on.');
}

function teardown(flags) {
  const dryRun = Boolean(flags['dry-run']);
  // Before the grants, and whether or not a setup record exists: a tripwire
  // left behind refuses every tool call, which is the right failure while
  // autoagy is installed and the wrong one once it is not.
  if (!dryRun) {
    const { autoagyHome: home } = managementContext();
    const removed = removeTripwire({ autoagyHome: home, home: accountHome() });
    if (removed.script || removed.registration) console.log(`Removed the tripwire (${tripwirePath(home)}, ${userHooksPath(accountHome())})`);
  } else {
    console.log('Would remove the tripwire');
  }
  const report = applyTeardown({ dryRun });
  if (!report.found) return console.log('No setup record found; nothing else to revert.');
  const verb = (done, planned) => (report.dryRun ? planned : done);
  console.log(`${verb('Reverted', 'Would revert')} ${report.settingsFile}`);
  for (const g of report.removedGrants) console.log(`  ${verb('removed', 'would remove')} permissions.allow ${g}`);
  for (const r of report.restored) console.log(`  ${verb('restored', 'would restore')} ${r.key} -> ${r.to === undefined ? '(unset)' : JSON.stringify(r.to)}`);
}

const USAGE = `autoagy — Codex-style auto mode for Google Antigravity

Usage:
  autoagy status                     show configuration and environment checks
  autoagy log [-n 20]                recent decisions
  autoagy denials                    recent auto-review denials
  autoagy approve <id>               approve one retry of a denied action
  autoagy trust [<conversation>] [--all] [--force]
                                     trust a conversation's paths again
  autoagy mode <auto|ask|off>        switch mode
  autoagy review --tool NAME --args JSON [--transcript FILE] [--workspace DIR] [--classify-only] [--show-prompt]
  autoagy setup [--dry-run] [--no-settings]
  autoagy teardown [--dry-run]
  autoagy hook <pre-tool-use|post-tool-use|post-invocation>   (used by hooks.json)`;

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const flags = parseFlags(rest);
  switch (command) {
    case 'hook':
      return runHook(rest[0], { configHome: strFlag(flags['autoagy-home']), home: strFlag(flags.home) });
    case 'status':
      return status();
    case 'log':
      return printLog(flags);
    case 'denials':
      return listDenials();
    case 'approve':
      return approve(flags._[0]);
    case 'trust':
      return trust(flags._[0], Boolean(flags.all), Boolean(flags.force));
    case 'mode':
      return setMode(flags._[0]);
    case 'review':
      return dryRunReview(flags);
    case 'setup':
      return setup(flags);
    case 'teardown':
      return teardown(flags);
    default:
      console.log(USAGE);
      process.exitCode = command && command !== 'help' && command !== '--help' ? 1 : 0;
  }
}

main().catch((err) => {
  console.error(`autoagy: ${err.message}`);
  process.exit(1);
});
