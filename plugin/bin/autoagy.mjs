#!/usr/bin/env node
// autoagy — Codex-style auto mode ("Approve for me") for Google Antigravity.
//
//   autoagy hook pre-tool-use|post-tool-use|post-invocation   (called by hooks.json)
//   autoagy status | log [-n N] | denials | approve <id> | mode <auto|ask|off>
//   autoagy review --tool NAME --args JSON [--transcript FILE] [--workspace DIR] [--classify-only]
//   autoagy setup [--dry-run] [--no-settings] | teardown [--dry-run]

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadConfig, autoagyHome as resolveAutoagyHome, configPath } from '../lib/config.mjs';
import { HookContext, PLUGIN_DIR } from '../lib/context.mjs';
import { findExecutable } from '../lib/paths.mjs';
import { detectOwnSandbox, readSandboxCheck } from '../lib/confine.mjs';
import { classify, READ_ONLY_TOOLS, AGENT_TOOLS } from '../lib/policy.mjs';
import { handlePreToolUse, handlePostToolUse, handlePostInvocation, failClosedOutput } from '../lib/hook.mjs';
import { gatherEvidence, buildReviewPrompt, runReview, decisionFor, TIMEOUT_INSTRUCTIONS } from '../lib/guardian.mjs';
import { createReviewer } from '../lib/reviewers.mjs';
import { appendDecision, readDecisions, decisionLogPath } from '../lib/log.mjs';
import { listStates, updateState } from '../lib/state.mjs';
import { applySetup, applyTeardown, ensureConfigFile, pinNodeInHooks, cliSettingsPath, RECOMMENDED_GRANTS, readSetupRecord } from '../lib/setup.mjs';

const HOOK_TIMEOUT_FALLBACK_SEC = 150;

function hookTimeoutSec(event) {
  const override = Number(process.env.AUTOAGY_HOOK_TIMEOUT_SEC);
  if (Number.isFinite(override) && override > 0) return override;
  try {
    const hooks = JSON.parse(fs.readFileSync(path.join(PLUGIN_DIR, 'hooks.json'), 'utf8'));
    const key = { 'pre-tool-use': 'PreToolUse', 'post-tool-use': 'PostToolUse', 'post-invocation': 'PostInvocation' }[event];
    for (const spec of Object.values(hooks)) {
      for (const entry of spec?.[key] ?? []) {
        for (const handler of entry.hooks ?? [entry]) {
          if (typeof handler.command === 'string' && handler.command.includes(event)) return handler.timeout ?? 30;
        }
      }
    }
  } catch {
    // fall through
  }
  return HOOK_TIMEOUT_FALLBACK_SEC;
}

async function runHook(event) {
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
  // Answer before Antigravity kills the hook, which would fail the tool call with an opaque error.
  const budgetSec = Math.max(5, hookTimeoutSec(event) - 5);
  const watchdog = setTimeout(() => {
    if (event !== 'pre-tool-use') return emit({});
    const name = payload?.toolCall?.name;
    emit(READ_ONLY_TOOLS.has(name) || AGENT_TOOLS.has(name) ? { decision: 'allow' } : { decision: 'deny', reason: TIMEOUT_INSTRUCTIONS });
  }, budgetSec * 1000);
  watchdog.unref();
  try {
    if (event === 'pre-tool-use') {
      const env = { ...process.env };
      const { config } = loadConfig({ env });
      // Keep the review deadline (plus process teardown) inside the hook budget.
      const maxReview = Math.max(3, budgetSec - 3);
      if (config.reviewer.timeoutSec > maxReview) env.AUTOAGY_REVIEW_TIMEOUT_CAP = String(maxReview);
      emit(await handlePreToolUse(payload, { env }));
    } else if (event === 'post-tool-use') {
      emit(handlePostToolUse(payload));
    } else if (event === 'post-invocation') {
      emit(handlePostInvocation(payload));
    } else {
      emit({});
    }
  } catch (err) {
    appendDecision(resolveAutoagyHome(), {
      conversation: payload?.conversationId,
      tool: payload?.toolCall?.name,
      verdict: 'error',
      error: String(err?.stack ?? err).slice(0, 2000),
    });
    emit(event === 'pre-tool-use' ? failClosedOutput(payload, err) : {});
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

const fmtTime = (iso) => (iso ? iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z') : '');

function readJsonQuiet(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function status() {
  const { config, warnings, path: cfgPath, exists } = loadConfig();
  const home = resolveAutoagyHome();
  const lines = [];
  lines.push(`autoagy — Codex-style auto mode for Antigravity`);
  lines.push(`  plugin dir      ${PLUGIN_DIR}`);
  lines.push(`  config          ${cfgPath}${exists ? '' : ' (not found — using defaults)'}`);
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
  const own = detectOwnSandbox({ config, host: null, appDataDir: path.dirname(cliSettingsPath()), autoagyHome: resolveAutoagyHome() });
  lines.push(`  own sandbox     ${own.active ? 'active' : own.required ? 'REQUIRED BUT UNAVAILABLE (commands are reviewed)' : 'inactive'} — ${own.detail}`);
  const check = readSandboxCheck(home);
  if (check?.status === 'broken') {
    lines.push(`  ! self-check    FAILED ${fmtTime(check.time)}: ${check.detail}. The own sandbox is off for that agy build; it is checked again after agy updates.`);
  } else if (check?.status === 'verified') {
    lines.push(`  self-check      agy ran ${check.verified} rewritten command(s) as expected (last ${fmtTime(check.time)})`);
  } else if (own.active) {
    lines.push('  self-check      no command has run in the own sandbox yet');
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
    const missing = RECOMMENDED_GRANTS.filter((g) => !allow.includes(g));
    if (missing.length) lines.push(`  ! missing grants ${missing.join(', ')} — approved actions may still prompt; run \`autoagy setup\``);
    if (allow.some((g) => /^read_url\(\*\)$/.test(g))) lines.push('  ! read_url(*) is granted: sandboxed commands can reach any host without review');
    const sandbox = settings.enableTerminalSandbox === true && (settings.toolPermission ?? 'proceed-in-sandbox') === 'proceed-in-sandbox';
    if (!sandbox && config.sandbox !== 'on') lines.push('  ! the terminal sandbox is off: every non-read-only command will be reviewed');
  }
  const record = readSetupRecord(home);
  lines.push(`  setup record            ${record ? `${fmtTime(record.time)} (grants added: ${record.addedGrants?.join(', ') || 'none'})` : 'none'}`);

  const hooks = readJsonQuiet(path.join(PLUGIN_DIR, 'hooks.json'));
  const command = hooks?.autoagy?.PreToolUse?.[0]?.hooks?.[0]?.command;
  lines.push('');
  lines.push(`Hook command: ${command ?? '(hooks.json not found)'}`);

  const recent = readDecisions(home, 500).filter((r) => r.review);
  const counts = {};
  for (const r of recent) counts[r.review.status] = (counts[r.review.status] ?? 0) + 1;
  lines.push(`Recent reviews: ${recent.length ? Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') : 'none'}  (log: ${decisionLogPath(home)})`);
  console.log(lines.join('\n'));
}

function printLog(flags) {
  const limit = Number(flags.n ?? 20);
  const records = readDecisions(resolveAutoagyHome(), limit);
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
  const home = resolveAutoagyHome();
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
  const home = resolveAutoagyHome();
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
  if (!['auto', 'ask', 'off'].includes(mode)) throw new Error('usage: autoagy mode <auto|ask|off>');
  ensureConfigFile();
  const file = configPath();
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
    const pin = pinNodeInHooks(PLUGIN_DIR, process.execPath, { dryRun });
    console.log(pin.changed ? `${dryRun ? 'Would pin' : 'Pinned'} hook interpreter to ${process.execPath}` : 'Hook interpreter already pinned');
  }
  if (flags['no-settings']) {
    console.log('Skipping Antigravity settings (--no-settings). Approved actions may still show Antigravity prompts.');
    return;
  }
  const report = applySetup({ dryRun });
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
  const report = applyTeardown({ dryRun: Boolean(flags['dry-run']) });
  if (!report.found) return console.log('No setup record found; nothing to revert.');
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
      return runHook(rest[0]);
    case 'status':
      return status();
    case 'log':
      return printLog(flags);
    case 'denials':
      return listDenials();
    case 'approve':
      return approve(flags._[0]);
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
