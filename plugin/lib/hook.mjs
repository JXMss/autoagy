// Hook handlers: PreToolUse (the approval decision) and PostInvocation (ends a
// turn after the rejection circuit breaker trips).
//
// Antigravity PreToolUse contract (measured on agy 1.2.x):
//   empty stdout   -> no opinion; Antigravity's own permission flow applies
//   {"decision":"allow"}      -> no objection (Antigravity permissions still apply)
//   {"decision":"deny","reason":...} -> blocked; the agent sees the reason
//   {"decision":"force_ask"}  -> always prompts the user
//   {} / invalid JSON / non-zero exit / timeout -> the tool call fails

import { loadConfig, autoagyHome as resolveAutoagyHome } from './config.mjs';
import { HookContext, HOST_INSPECTABLE_PLATFORMS, newNestedGitPlantings } from './context.mjs';
import { classify, failOpenOutput, BROWSER_ACTION_TOOLS, CONTENT_READ_TOOLS, FILE_EDIT_TOOLS, editTargets, readTargets, canonicalPathArgs, classifyWriteTarget, isCredentialPath } from './policy.mjs';
import { isKnownSafeCommandLine } from './command-safety.mjs';
import { confinedCommandLine, scrubbedCommandLine, commandHash, recordSandboxCheck, takeSandboxNotice, removeControlPlaceholders, lockQuiescent, workspaceLockFile } from './confine.mjs';
import { gatherEvidence, buildReviewPrompt, runReview, decisionFor } from './guardian.mjs';
import { createReviewer } from './reviewers.mjs';
import { readState, updateState, recordReviewOutcome, recordDenial, takeApprovals, actionKey, newId, isUntrusted, markUntrusted, touchHeartbeat, takeConfigWarnings } from './state.mjs';
import { appendDecision, writeReviewRecord } from './log.mjs';
import { readTranscriptRows } from './transcript.mjs';
import { mintToken, sweepTokens, executorInstalled } from './tokens.mjs';
import { toAbsolute } from './paths.mjs';

const SUMMARY_MAX = 300;

export function summarizeAction(toolName, args = {}) {
  let text;
  if (toolName === 'run_command') text = `${args.BypassSandbox === true ? '[bypass] ' : ''}${args.CommandLine ?? ''}`;
  else if (typeof args.TargetFile === 'string') text = `${toolName} ${args.TargetFile}`;
  else if (typeof args.Url === 'string') text = `${toolName} ${args.Url}`;
  else {
    const { toolAction, toolSummary, ...rest } = args;
    text = `${toolName} ${JSON.stringify(rest)}`;
  }
  return text.length > SUMMARY_MAX ? `${text.slice(0, SUMMARY_MAX)}…` : text;
}

function countUserMessages(transcriptPath) {
  if (!transcriptPath) return 0;
  return readTranscriptRows(transcriptPath).filter((r) => r.type === 'USER_INPUT').length;
}

/**
 * Under `agy --dangerously-skip-permissions` Antigravity auto-approves every
 * prompt, so asking the user would silently allow the action. Refuse instead.
 */
export function withoutUnanswerablePrompt(output, ctx) {
  if (output?.decision !== 'force_ask') return output;
  const skip = ctx.host?.flags?.skipPermissions === true;
  // Where a process's arguments cannot be read at all — Windows has no /proc and
  // no ps — the flag can never be ruled out, so a prompt could be approved
  // silently. Treat that as "cannot ask" rather than emitting it. On the
  // platforms where the arguments are readable the hook runs as agy's child and
  // the walk finds it, so an unidentified host there is not evidence of the flag.
  const flagUnknowable = !ctx.host && !HOST_INSPECTABLE_PLATFORMS.includes(process.platform);
  if (!skip && !flagUnknowable) return output;
  const why = skip
    ? 'agy runs with --dangerously-skip-permissions, which would auto-approve the prompt'
    : `autoagy cannot read the agy process arguments on ${process.platform}, so it cannot rule out --dangerously-skip-permissions`;
  return {
    decision: 'deny',
    reason: `${output.reason}\nautoagy cannot ask the user here: ${why}. Ask the user in chat instead.`,
  };
}

/**
 * Mode "off": no review, but the grants `autoagy setup` added (command(*),
 * mcp(*), execute_url(*)) must not let the actions they cover run unchecked.
 * Those actions go back to the user, as they would without autoagy.
 */
export function offModeOutput(ctx, state = {}) {
  const name = ctx.toolName;
  let what = null;
  if (name === 'run_command') {
    if (ctx.args.BypassSandbox === true) what = 'a command outside the terminal sandbox';
    else if (!ctx.sandbox.active && !isKnownSafeCommandLine(String(ctx.args.CommandLine ?? ''))) what = 'a command the terminal sandbox does not confine';
  } else if (name === 'call_mcp_tool' || name.startsWith('mcp_')) {
    what = 'an MCP tool call';
  } else if (BROWSER_ACTION_TOOLS.has(name) || name === 'open_browser_url' || name === 'browser_subagent') {
    // Navigating and the browser subagent belong here for the same reason the
    // clicks do: `execute_url(*)` is one of the grants setup added, and a
    // subagent driving the browser does its own navigating and clicking, none of
    // which passes through this hook again.
    what = 'a browser action';
  } else if (state.untrusted && (FILE_EDIT_TOOLS.has(name) || CONTENT_READ_TOOLS.has(name))) {
    // Mode "off" normally has no opinion here, which would leave the setup
    // grants to wave it through. In an untrusted conversation that is worse
    // than a review, so it goes back to the user instead.
    what = 'a file edit or read in a conversation whose paths are no longer trusted';
  }
  if (!what) return null;
  return {
    decision: 'force_ask',
    reason: `autoagy is off: ${what} needs your confirmation, because the permission grants added by autoagy setup would otherwise let it run without review.`,
  };
}

/**
 * With autoagy's own sandbox active, a command the agent did not ask to
 * escalate runs inside it: the call is rewritten to leave Antigravity's
 * sandbox and enter autoagy's.
 */
export function withOwnSandbox(output, ctx) {
  if (output?.decision !== 'allow' && output?.decision !== 'force_ask') return output;
  if (ctx.toolName !== 'run_command' || typeof ctx.args.CommandLine !== 'string') return output;
  // An escalation is not confined — that is what it means — but under the narrow
  // command grant it still has to be rewritten, or agy refuses it. See below.
  if (ctx.args.BypassSandbox === true) return withEscalationToken(output, ctx);
  if (!ctx.ownSandbox.active) return withScrubbedEnv(output, ctx);
  const placeholders = [];
  const confined = confinedCommandLine(ctx, ctx.args.CommandLine, { placeholders });
  // What agy is actually told to run. In executor mode that is not the bwrap
  // line but a one-shot token that redeems it, so the standing grant can name
  // one program instead of every command — see tokens.mjs. Everything below
  // works on the line that runs, because that is what PostToolUse will see.
  const commandLine = ctx.config.commandGrant === 'executor' ? issueToken(ctx, confined) : confined;
  // Remembered for the PostToolUse self-check and for cleaning the mount points up.
  if (ctx.stepIdx !== null) {
    updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
      // Mount points belonging to other steps are deliberately left alone. agy
      // can leave a command running and return from the tool call early, so
      // "another step" is no longer evidence that its command has finished —
      // and `--tmpfs` on a directory that has since been removed makes bwrap
      // fail outright, which would break a command that was already approved.
      // Whatever is left over is swept when the turn ends.
      s.pendingConfined[ctx.stepIdx] = commandHash(commandLine);
      // What the mount list above could not cover. `--ro-bind-try` silently
      // skips a `.git` that does not exist yet, and the placeholders only ever
      // cover the top-level protected directories, so a nested repository THIS
      // command creates is writable inside the sandbox and lands on the host.
      // Recorded for PostToolUse to compare against; the getter is memoized and
      // readOnlyPaths walked it a moment ago, so this costs nothing.
      // The whole set, never a truncated one — a missing entry would make a
      // repository that was already there look newly created, and the record
      // names that path on stderr.
      //
      // There was a count cap here and it was the wrong shape: going over it
      // recorded nothing, so the check went silent, and going over it cost one
      // unreviewed command. An empty `.git` holds nothing runnable and is never
      // a finding, so `mkdir -p d1/.git … d101/.git` was a legal move that
      // turned the check off for the rest of the conversation. The array needs
      // no cap of its own: `findNestedGitPaths` visits a bounded number of
      // directories and each one yields at most one `.git`, so its own budget
      // is the bound.
      s.pendingNestedGit[ctx.stepIdx] = ctx.nestedGitPaths;
      // What that walk cost and whether it finished. `nestedGitScan` has carried
      // both since the time bound was added, and nothing read them — so on a
      // filesystem where the walk truncates (measured: ~300 of 1269 directories
      // in 0.5s on a 9p mount) the protection was partial with no way to find
      // out. Written here because the scan already happened for the mount list;
      // `status` reports it, so a reader does not have to run a command to learn
      // that nested repositories below the cut are not mounted read-only.
      s.nestedScan = { ...ctx.nestedGitScan, paths: undefined, at: new Date().toISOString() };
      if (placeholders.length) {
        s.pendingPlaceholders[ctx.stepIdx] = placeholders;
        // Recorded rather than recomputed: if the workspace roots this hook
        // sees differ between building the command and reclaiming it, the
        // reclaim would probe a different lock file, find it free, and take a
        // mount point out from under a command — the one direction that must
        // not be wrong.
        s.pendingLock = workspaceLockFile(ctx);
      }
      // The two are written together and deleted together: the reader relies on
      // "no pendingConfined" meaning "no before-set to compare either".
      const steps = Object.keys(s.pendingConfined);
      for (const step of steps.slice(0, Math.max(0, steps.length - MAX_PENDING_CONFINED))) {
        delete s.pendingConfined[step];
        delete s.pendingNestedGit[step];
      }
    });
  } else {
    // Nothing to key the cleanup on: do not leave the mount points behind.
    removeControlPlaceholders(placeholders);
  }
  return { ...output, overwrite: { BypassSandbox: true, CommandLine: commandLine } };
}

/**
 * An approved escalation, behind the same one-shot token, so the narrow command
 * grant covers it.
 *
 * Measured on agy 1.2.7, which is what makes this necessary: a `command(...)`
 * grant is matched against the *content* of the command. With
 * `permissions.allow: ["command(echo)"]`, `echo probe-granted` with
 * `BypassSandbox: true` ran, and `whoami` with `BypassSandbox: true` was refused
 * — "a tool required the \"command\" permission that headless mode cannot prompt
 * for, so it was auto-denied".
 *
 * So under `commandGrant: "executor"`, where the standing grant names one program
 * instead of `command(*)`, an escalation the agent asks for itself could never
 * match it: its content is `git push`, not the executor's path. Interactively that
 * is a prompt on every escalation; in print mode it is an outright denial, so the
 * agent cannot escalate at all. The mode that closes autoagy's fail-open was the
 * mode that broke escalation.
 *
 * Rewriting it to redeem a token fixes that and widens nothing. The executor runs
 * `sh -c <the token's command line>` — it never assumed bwrap — and the token is
 * one-shot, expires, and is written to a directory only the hook can write. Which
 * means the grant still says exactly what it said: "the only program that may run
 * is the one that redeems a line autoagy wrote down". The line, this time, is the
 * command the reviewer approved, unconfined, which is what approving an escalation
 * already meant.
 *
 * Only on `allow`: a `force_ask` or a denial has approved nothing, and a token is
 * a decision already made.
 *
 * No self-check for this one, deliberately. If agy ignored the rewrite the
 * original `git push` would run — which is what was approved — and then fail its
 * own permission check, because the grant does not name it. The failure is visible
 * to the agent and nothing ran that was not approved, so there is no silent
 * weakening for a check to catch; the unredeemed token expires and is swept.
 */
function withEscalationToken(output, ctx) {
  if (output.decision !== 'allow') return output;
  // `command(*)` already covers any content, so there is nothing to work around.
  if (ctx.config.commandGrant !== 'executor') return output;
  // Without the program there is nothing to redeem the token; leaving the call
  // alone means agy refuses it, which is the fail-closed direction, and `status`
  // already says the executor is missing.
  if (!executorInstalled(ctx.autoagyHome)) return output;
  return { ...output, overwrite: { CommandLine: issueToken(ctx, ctx.args.CommandLine) } };
}

/**
 * Puts the confined command line behind a one-shot token and returns the call
 * that redeems it.
 *
 * The working directory is recorded rather than left to be inherited: the
 * executor is started by agy with the `Cwd` the agent chose, and the command was
 * judged against the one the hook saw. Sweeping here as well as at the end of
 * the turn means a hook that dies between minting and running does not leave a
 * usable retry behind.
 */
function issueToken(ctx, commandLine) {
  sweepTokens(ctx.autoagyHome);
  const cwd = typeof ctx.args.Cwd === 'string' && ctx.args.Cwd ? toAbsolute(ctx.args.Cwd, ctx.baseDir, ctx.home) : ctx.baseDir;
  return mintToken(ctx.autoagyHome, {
    commandLine,
    cwd,
    conversation: ctx.conversationId,
    step: ctx.stepIdx,
  }).commandLine;
}

/**
 * Hands agy the target with its parent directories already resolved.
 *
 * agy performs edits and reads itself, outside every sandbox, so the only
 * protection available is to narrow what can still change between the check and
 * the call. Resolving the path first removes one way it changes — a symlink
 * already in the path being re-pointed — and leaves the other, a real directory
 * turned into a symlink, which nothing here can reach.
 *
 * Applied only when something actually resolves elsewhere, so the ordinary call
 * carries no `overwrite` and the agent sees no note about one.
 */
function withCanonicalTarget(output, ctx) {
  if (output?.decision !== 'allow' && output?.decision !== 'force_ask') return output;
  if (!targetCheckKind(ctx.toolName)) return output;
  const overwrite = canonicalPathArgs(ctx);
  if (!overwrite) return output;
  return { ...output, overwrite: { ...(output.overwrite ?? {}), ...overwrite } };
}

/**
 * Where autoagy has no sandbox of its own (macOS, Windows, no bubblewrap, IDE
 * without `ownSandbox: "on"`), `commandEnv.mode: "scrub"` takes away the one
 * thing it still can: the environment. The command is rewritten to run under
 * `env -i` with the same allowlist the sandbox uses, so an unreviewed command
 * cannot print the API keys agy was started with — and neither can a reviewed
 * one whose output lands in the transcript.
 *
 * agy applies an `overwrite` that leaves `BypassSandbox` unset (measured), so
 * the command still runs inside Antigravity's sandbox and needs no `command`
 * grant. Escalated commands are left alone: they were reviewed as full-privilege
 * actions, and the environment is part of what that means.
 */
function withScrubbedEnv(output, ctx) {
  // The same question the policy asked before allowing the command: it decided
  // not to review a read of the environment because this rewrite was going to
  // take that environment away, so the two must not be able to disagree.
  if (!ctx.envScrubbed) return output;
  const commandLine = scrubbedCommandLine(ctx, ctx.args.CommandLine);
  if (!commandLine) return output;
  if (ctx.stepIdx !== null) {
    updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
      s.pendingEnvScrub[ctx.stepIdx] = commandHash(commandLine);
      const steps = Object.keys(s.pendingEnvScrub);
      for (const step of steps.slice(0, Math.max(0, steps.length - MAX_PENDING_CONFINED))) delete s.pendingEnvScrub[step];
    });
  }
  return { ...output, overwrite: { CommandLine: commandLine } };
}

/**
 * The env-scrub counterpart of the sandbox self-check: PostToolUse sees the
 * arguments that actually ran, so a mismatch means the rewrite was ignored and
 * the command saw the inherited environment after all. The response is to stop
 * claiming the environment is scrubbed for this agy build — not to mark the
 * conversation, which is about the filesystem — and to say so once.
 */
function checkScrubbedEnv(ctx, state) {
  // Nothing was rewritten for this step, so there is nothing to compare: no
  // lock is taken. Every run_command would otherwise pay one, and the path
  // below is not free — the lock is shared with every other hook.
  if (!state.pendingEnvScrub?.[ctx.stepIdx]) return;
  const recorded = updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
    const hash = s.pendingEnvScrub?.[ctx.stepIdx] ?? null;
    if (s.pendingEnvScrub) delete s.pendingEnvScrub[ctx.stepIdx];
    return hash;
  });
  if (!recorded) return;
  const problem = commandHash(ctx.args.CommandLine) === recorded ? null : 'agy ran the original command instead of the one autoagy rewrote to run under env -i';
  recordSandboxCheck(ctx.autoagyHome, ctx.hostBuild, problem, 'envScrub');
  if (problem) {
    appendDecision(ctx.autoagyHome, { conversation: ctx.conversationId, step: ctx.stepIdx, tool: ctx.toolName, verdict: 'env-scrub-self-check-failed', error: problem });
    process.stderr.write(`autoagy: this agy version did not run the scrubbed command line; commands will keep the inherited environment. Run \`autoagy status\`.\n`);
  }
}

/**
 * Removes mount points and treats a still-populated one as what it is: a
 * command reached the real directory the mount was supposed to hide. bwrap
 * mounts inside the child's own namespace, so the host directory stays empty
 * for the whole command — entries there mean the rewrite did not cover it.
 */
function removePlaceholders(home, conversationId, paths, { attribute = false } = {}) {
  const { dirty } = removeControlPlaceholders(paths);
  if (dirty.length === 0) return;
  const detail = dirty.join(', ');
  appendDecision(home, {
    conversation: conversationId,
    verdict: 'placeholder-dirty',
    error: `a command wrote into ${detail}, which was supposed to be read-only in the sandbox`,
  });
  // The decision log is the protocol's stdout; warnings go to stderr.
  process.stderr.write(`autoagy: a command wrote into ${detail}; that path was meant to be read-only inside the sandbox.\n`);
  // Only a caller that knows a sandboxed command just ran can attribute this.
  // At a sweep the directory may simply have been filled by agy's own edit
  // tool, which writes outside every sandbox — marking the conversation
  // untrusted for that would be a false alarm about a reviewed edit.
  if (!attribute) return;
  updateState(home, conversationId, (s) => markUntrusted(s, { reason: 'protected-path-written', detail }));
}

/**
 * Records the `.git` directories a sandboxed command created that hold something
 * git will run, so later commands touching that repository are reviewed. Deduped
 * by path: the same repository is one fact, however many commands touch it.
 */
function recordPlantedHooks(state, findings, step) {
  for (const finding of findings) {
    if ((state.plantedHooks ?? []).some((p) => p.path === finding.path)) continue;
    state.plantedHooks = [...(state.plantedHooks ?? []), step === null ? finding : { ...finding, step }].slice(-MAX_PLANTED_HOOKS);
  }
}

/**
 * Says so, on the two channels PostToolUse has: the decision log and stderr.
 *
 * "Appeared while a sandboxed command ran", not "a sandboxed command created":
 * a backgrounded command plus a concurrently approved edit can be confused for
 * one moment, and placeholder-dirty already taught that attribution is the
 * fragile part. The record is about a fact on disk, and the consequence does not
 * depend on which writer made it.
 */
function reportPlantedHooks(home, ctx, findings) {
  const first = findings[0];
  const names = first.hooks.map((h) => h.name).slice(0, 3).join(', ') || first.config.join(', ');
  const more = findings.length > 1 ? ` (and ${findings.length - 1} more)` : '';
  appendDecision(home, {
    conversation: ctx.conversationId,
    step: ctx.stepIdx,
    tool: ctx.toolName,
    verdict: 'planted-git-hook',
    path: first.path,
    hooks: first.hooks.map((h) => h.name),
    config: first.config,
    error: `${first.path} appeared while a sandboxed command ran and holds content git will execute (${names}); commands touching ${first.dir} are reviewed until \`autoagy trust\``,
  });
  process.stderr.write(
    `autoagy: ${first.path} appeared while a sandboxed command ran and holds content git will execute (${names})${more}. ` +
      `A command touching ${first.dir} runs it outside every sandbox, so those are now reviewed; check it and run \`autoagy trust\`.\n`,
  );
}

const MAX_PENDING_CONFINED = 50;
const MAX_PLANTED_HOOKS = 20;

/**
 * PostToolUse: the two checks that only the arguments which actually ran can
 * answer — whether agy kept autoagy's sandbox rewrite, and whether the target
 * of a file edit still resolved where it did when the edit was approved.
 */
export function handlePostToolUse(payload, options = {}) {
  const env = options.env ?? process.env;
  const { config } = loadConfig({ env, home: options.home });
  const ctx = new HookContext(payload, { config, env, home: options.home, host: options.host });
  if (ctx.stepIdx === null) return {};
  // These checks run even in mode "off": they clean up mount points a command
  // left behind and verify what actually ran, and a conversation whose mode was
  // switched mid-flight would otherwise strand them.
  if (ctx.toolName === 'run_command') {
    // One state read shared by both checks; each writes only when it has
    // something to record, so an ordinary command takes the lock once, in
    // checkConfinedRun, as it did before the env scrub existed.
    const state = readState(ctx.autoagyHome, ctx.conversationId);
    checkScrubbedEnv(ctx, state);
    return checkConfinedRun(ctx, state);
  }
  const kind = targetCheckKind(ctx.toolName);
  if (kind) return checkTargets(ctx, kind);
  return {};
}

/**
 * Checks that agy ran the command exactly as autoagy rewrote it (the payload
 * carries the arguments that actually executed). A mismatch means this agy
 * build no longer honors the rewrite, so the own sandbox is switched off for
 * it; see detectOwnSandbox. The mount points of protected directories that did
 * not exist are taken away again here, once the command has run.
 */
/**
 * Whether the mount points can be reclaimed now.
 *
 * Reclaiming one while a command is still running does not fail the command, it
 * takes its protection away: the mount lives in that process's mount namespace,
 * and removing the directory makes the path stop resolving there, so the command
 * recreates it through the writable workspace bind — on the host. So reclamation
 * happens only on positive evidence that nothing is running: the workspace lock,
 * which every rewritten command line holds for as long as bwrap lives. Where the
 * lock is unavailable, fall back to the weaker signal that one may be around.
 */
function reclaimAllowed(state, quiet) {
  return quiet === null ? !state.backgroundSuspected : quiet;
}

function checkConfinedRun(ctx, state = {}) {
  const home = ctx.autoagyHome;
  // Only ask the lock when there is something to reclaim: it costs a process.
  const reclaiming = (state.pendingPlaceholders?.[ctx.stepIdx]?.length ?? 0) > 0;
  const quiet = reclaiming ? lockQuiescent(ctx, { lockFile: state.pendingLock ?? null }) : null;
  const keepPlaceholders = reclaiming && !reclaimAllowed(state, quiet);
  // A before-set exists only for a command autoagy actually rewrote into its own
  // sandbox — the same gate as `pendingConfined`, and the only case where a
  // `.git` could have been created behind a mount. The walk and the file reads
  // happen outside the lock: they are the slow part, and the lock guards a small
  // file.
  const before = state.pendingConfined?.[ctx.stepIdx] ? state.pendingNestedGit?.[ctx.stepIdx] : undefined;
  const findings = before === undefined ? [] : newNestedGitPlantings(ctx, before);
  // A command that may still be running is the one case where the workspace is
  // not yet settled: the walk above can have caught a half-made `.git`, or
  // missed one the command has not reached yet. Keep the before-set then and let
  // the turn-end sweep look again. Same rule and same answer as the mount points
  // follow, so this asks no lock of its own.
  const keepTracked = before !== undefined && !reclaimAllowed(state, quiet);
  const recorded = updateState(home, ctx.conversationId, (s) => {
    const entry = s.pendingConfined[ctx.stepIdx] ? { hash: s.pendingConfined[ctx.stepIdx], placeholders: s.pendingPlaceholders[ctx.stepIdx] ?? [] } : null;
    delete s.pendingConfined[ctx.stepIdx];
    if (!keepTracked) delete s.pendingNestedGit[ctx.stepIdx];
    if (!keepPlaceholders) delete s.pendingPlaceholders[ctx.stepIdx];
    if (findings.length > 0) recordPlantedHooks(s, findings, ctx.stepIdx);
    return entry;
  });
  if (reclaiming && !keepPlaceholders) {
    // The mount points are gone, so the weaker signal that produced them is
    // stale — leaving it set would have status report a conversation as
    // holding mount points it no longer has.
    updateState(home, ctx.conversationId, (s) => {
      s.backgroundSuspected = false;
      s.pendingLock = null;
    });
  }
  if (!keepPlaceholders && recorded) removePlaceholders(home, ctx.conversationId, recorded.placeholders, { attribute: true });
  if (!recorded) return {};
  if (findings.length > 0) reportPlantedHooks(home, ctx, findings);
  let problem = null;
  if (commandHash(ctx.args.CommandLine) !== recorded.hash) problem = 'agy ran the original command instead of the one autoagy rewrote';
  else if (ctx.args.BypassSandbox !== true) problem = "agy ran the rewritten command without BypassSandbox, inside its own sandbox";
  recordSandboxCheck(home, ctx.hostBuild, problem);
  if (problem) {
    appendDecision(home, { conversation: ctx.conversationId, step: ctx.stepIdx, tool: ctx.toolName, verdict: 'self-check-failed', error: problem });
    // agy ran the command where autoagy did not intend it to run — inside a
    // sandbox that leaves .git and the conversation log writable — so what the
    // workspace looks like now is no longer something autoagy can vouch for.
    updateState(home, ctx.conversationId, (s) => markUntrusted(s, { reason: 'rewrite-ignored', detail: problem, step: ctx.stepIdx }));
  }
  return {};
}

/**
 * The two kinds of tool call whose path arguments are resolved once before the
 * call and once after: agy performs both itself, outside every sandbox, so a
 * path swapped in between lands the call somewhere other than the place that was
 * approved. Everything about the check is the same for both; only the state key,
 * the log verdict and what the user has to do about it differ.
 */
const TARGET_CHECKS = {
  edit: {
    pending: 'pendingEdits',
    verdict: 'edit-target-changed',
    targets: editTargets,
    message: (tool, abs, real, after) =>
      `autoagy: ${abs} resolved to ${real} when the ${tool} was approved, but to ${after} when it ran. ` +
      'Something replaced part of that path in between, so the write may have landed outside the approved location. ' +
      'Check what changed there before continuing.',
    // `pathDrift: "graded"`, and the write landed on an ordinary workspace file.
    // The turn still stops — something moved under the call and the user should
    // hear it — but the wording does not ask for `autoagy trust`, because the mark
    // that command clears was not set.
    containedMessage: (tool, abs, real, after) =>
      `autoagy: ${abs} resolved to ${real} when the ${tool} was approved, but to ${after} when it ran. ` +
      'Something replaced part of that path in between. The write landed on an ordinary file inside the workspace, ' +
      'which this conversation could have named directly, so only this turn stops. Say what happened and check that file.',
  },
  read: {
    pending: 'pendingReads',
    verdict: 'read-target-changed',
    targets: readTargets,
    // The consequence points the other way from an edit's. A write that landed
    // somewhere else can be cleaned up; a read that landed somewhere else has
    // already put that file into the model's context, and nothing takes that
    // back. So the message says the one thing the user can still act on.
    message: (tool, abs, real, after) =>
      `autoagy: ${abs} resolved to ${real} when the ${tool} was approved, but to ${after} when it ran. ` +
      `Something replaced part of that path in between, so ${after} is what may have been read into this conversation. ` +
      'That cannot be taken back: treat anything secret in that file as disclosed, and rotate it.',
    // The read counterpart. A read that landed elsewhere is the less reversible
    // of the two, and what makes this case harmless is not that it was a read —
    // it is that the file was already readable without review.
    containedMessage: (tool, abs, real, after) =>
      `autoagy: ${abs} resolved to ${real} when the ${tool} was approved, but to ${after} when it ran. ` +
      `Something replaced part of that path in between, so ${after} is what was read. It is an ordinary file inside the workspace, ` +
      'readable without review anyway, so only this turn stops. Say what happened, and do not rely on having read the path you asked for.',
  },
};

/** Which check a tool call belongs to, or null. */
function targetCheckKind(toolName) {
  if (FILE_EDIT_TOOLS.has(toolName)) return 'edit';
  if (CONTENT_READ_TOOLS.has(toolName)) return 'read';
  return null;
}

/**
 * Records where a tool's targets resolved when it was approved, for checkTargets.
 *
 * `args` is the call as it will actually run, which is not `ctx.args` when
 * `withCanonicalTarget` rewrote a path: PostToolUse sees the rewritten
 * arguments, so recording the original ones would leave the two halves of the
 * comparison keyed differently and the check would quietly compare nothing.
 */
function rememberTargets(ctx, args = ctx.args) {
  const kind = ctx.stepIdx === null ? null : targetCheckKind(ctx.toolName);
  if (!kind) return;
  const check = TARGET_CHECKS[kind];
  const targets = check.targets(ctx, args);
  if (targets.length === 0) return;
  updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
    const pending = s[check.pending] ?? (s[check.pending] = {});
    pending[ctx.stepIdx] = targets;
    const steps = Object.keys(pending);
    for (const step of steps.slice(0, Math.max(0, steps.length - MAX_PENDING_EDITS))) delete pending[step];
    // Only the edits go on from here. `recentEdits` is handed to the reviewer as
    // the files this conversation edited, and a read is not one of those.
    if (kind !== 'edit') return;
    // Kept for the reviewer: the transcript is budget-trimmed, so an edit made
    // long before a command is approved can be gone from it by then.
    s.recentEdits = [...(s.recentEdits ?? []), ...targets.map((t) => ({ path: t.abs, real: t.real, step: ctx.stepIdx, kind: ctx.toolName }))].slice(-MAX_RECENT_EDITS);
  });
}

const MAX_PENDING_EDITS = 50;
const MAX_RECENT_EDITS = 20;

/**
 * agy writes edited files itself, outside every sandbox, so autoagy can only
 * judge the target before the write. Resolving it again here catches a path
 * that was swapped for a symlink in between (a command running in the
 * background could do that): the write may have landed somewhere other than
 * the location that was approved, which is worth interrupting the turn over.
 */
function checkTargets(ctx, kind) {
  const check = TARGET_CHECKS[kind];
  const home = ctx.autoagyHome;
  const recorded = updateState(home, ctx.conversationId, (s) => {
    const pending = s[check.pending] ?? {};
    const targets = pending[ctx.stepIdx] ?? null;
    delete pending[ctx.stepIdx];
    return targets;
  });
  if (!recorded) return {};
  let rootId;
  const now = new Map(check.targets(ctx).map((t) => [t.abs, t.real]));
  for (const { abs, real } of recorded) {
    const after = now.get(abs);
    if (!after || after === real) continue;
    const contained = driftIsContained(ctx, after);
    const message = contained ? check.containedMessage(ctx.toolName, abs, real, after) : check.message(ctx.toolName, abs, real, after);
    appendDecision(home, {
      conversation: ctx.conversationId,
      step: ctx.stepIdx,
      tool: ctx.toolName,
      verdict: check.verdict,
      path: abs,
      before: real,
      after,
      contained: contained || undefined,
    });
    updateState(home, ctx.conversationId, (s) => {
      s.interrupt = { turnKey: countUserMessages(ctx.transcriptPath), pending: true, message };
      // This is a fact about the filesystem, not about the agent's behaviour, so
      // it outlives the turn: leaving the symlink in place does not undo it.
      // Unless the drift stayed inside the workspace under `pathDrift: "graded"`
      // — then the turn still stops and the log still names it, but the rest of
      // the conversation is not reviewed. See driftIsContained.
      if (!contained) markUntrusted(s, { reason: check.verdict, detail: `${abs} resolved to ${after}`, step: ctx.stepIdx });
      rootId = s.rootConversationId;
    });
    // A subagent's conversation keeps its own state file, but it just changed
    // the parent's workspace too, so the parent stops trusting its paths as well.
    if (!contained && rootId && rootId !== ctx.conversationId) {
      updateState(home, rootId, (s) => markUntrusted(s, { reason: check.verdict, detail: `${abs} changed while a subagent ran`, step: ctx.stepIdx }));
    }
    return {};
  }
  return {};
}

/**
 * Whether a drifted target landed somewhere the agent could have named outright.
 *
 * Only asked under `pathDrift: "graded"`. The default answers "nowhere" and every
 * drift marks the conversation, which is what every version before this did.
 *
 * `classifyWriteTarget` is the same judgement the edit rules use, so the two
 * cannot disagree about what a control surface is: `self`, `evidence` and
 * `protected` (which covers `protectedPaths`, `.git` anywhere in the path, agent
 * metadata and `~/.gemini`) all fall through to "not contained", as does a
 * credential store and anything outside the writable roots. What is left —
 * `workspace` and the agy-managed scratch, artifact and temp directories — is a
 * place the agent writes and reads without review anyway, so a call that landed
 * there reached nothing it was not already allowed to reach.
 *
 * The same test serves reads and edits, and it is worth saying why, because a
 * read that lands elsewhere is the less reversible of the two: what makes it
 * harmless here is not that it was a read, it is that the file was already
 * readable. The question "could this call have named that path itself" has one
 * answer for both.
 *
 * A real `~/.ssh` drift fails this twice over — it is outside every writable root
 * *and* a credential path — and that redundancy is worth keeping rather than
 * trimming to whichever check looks sufficient. `/tmp` is the case that surprises:
 * it is a writable root, so a drift landing there *is* contained, deliberately, on
 * the same grounds as the workspace. Exported for the test, because the
 * interesting part of this change is the predicate rather than the plumbing.
 */
export function driftIsContained(ctx, after) {
  if (ctx.config.pathDrift !== 'graded') return false;
  const where = classifyWriteTarget(ctx, after);
  if (where !== 'workspace' && where !== 'managed') return false;
  return !isCredentialPath(ctx, after);
}

/** The decision used when autoagy itself fails: never block reads, never allow the rest. */
export function failClosedOutput(payload, error, { untrusted = false, config = null } = {}) {
  return failOpenOutput(payload, {
    untrusted,
    config,
    reason: `autoagy internal error (${error?.message ?? error}); the action was blocked to fail closed. See ~/.gemini/autoagy/logs/decisions.jsonl.`,
  });
}

/** The tools that inspect or feed a terminal that may already be running a command. */
const TERMINAL_TOOLS = new Set(['send_command_input', 'read_terminal', 'command_status']);

/**
 * Whether this call may leave a command running in a terminal autoagy cannot
 * observe. agy starts the process, so autoagy holds no pid and cannot check
 * liveness directly — these are the signals agy's own run_command schema offers:
 *
 * - `IsDaemon: true` marks a command expected to run indefinitely. agy's tool
 *   description says NOT to combine it with `WaitMsBeforeAsync`, so a dev server
 *   arrives with that value absent or zero — watching only the wait value would
 *   miss exactly the case that matters.
 * - `Blocking: false` means the tool call returns without waiting.
 * - a positive `WaitMsBeforeAsync` is a bounded async window. Zero is not a
 *   signal: agy's own examples send `WaitMsBeforeAsync: 0` with a plain test run.
 * - any use of the tools that feed or inspect a terminal means a persistent one
 *   exists.
 */
function toolMayLeaveTerminalRunning(ctx) {
  if (TERMINAL_TOOLS.has(ctx.toolName)) return true;
  if (ctx.toolName !== 'run_command') return false;
  const args = ctx.args ?? {};
  if (args.IsDaemon === true || args.IsDaemon === 'true') return true;
  if (args.Blocking === false || args.Blocking === 'false') return true;
  const wait = args.WaitMsBeforeAsync;
  if (wait === undefined || wait === null) return false;
  const ms = Number(wait);
  return Number.isFinite(ms) && ms > 0;
}

/** Records that a command may outlive its tool call; see state.backgroundSuspected. */
function noteTerminalUse(ctx, state) {
  if (ctx.stepIdx === null || state.backgroundSuspected) return;
  if (!toolMayLeaveTerminalRunning(ctx)) return;
  updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
    s.backgroundSuspected = true;
  });
  state.backgroundSuspected = true;
}

/**
 * @param {object} payload
 * @param {{ env?: NodeJS.ProcessEnv, home?: string, host?: object | null, tempRoots?: string[], bwrapProbe?: Function }} [options]
 * @returns {Promise<object | null>} hook output, or null for "no opinion"
 */
export async function handlePreToolUse(payload, options = {}) {
  const env = options.env ?? process.env;
  const { config, warnings } = loadConfig({ env, home: options.home });
  const ctx = new HookContext(payload, { config, env, home: options.home, host: options.host, tempRoots: options.tempRoots, bwrapProbe: options.bwrapProbe });
  const home = ctx.autoagyHome;
  const state = readState(home, ctx.conversationId);
  // Mode "off" still has to route the actions the setup grants cover back to
  // the user, and it must not ask when the flag makes asking impossible.
  if (config.mode === 'off') return withoutUnanswerablePrompt(offModeOutput(ctx, state), ctx);

  if (ctx.role === 'guardian') {
    const verdict = classify(ctx);
    return verdict.verdict === 'allow' ? { decision: 'allow' } : { decision: 'deny', reason: verdict.reason };
  }

  // Once per agy build: the self-check found that agy no longer honors the sandbox rewrite.
  const notice = ctx.toolName === 'run_command' && ctx.ownSandbox.broken ? takeSandboxNotice(home, ctx.hostBuild) : null;
  if (notice) {
    appendDecision(home, { conversation: ctx.conversationId, step: ctx.stepIdx, tool: ctx.toolName, verdict: 'deny', reason: 'own sandbox self-check notice' });
    return {
      decision: 'deny',
      reason:
        `autoagy's self-check found that this agy version does not run commands the way autoagy's own sandbox rewrites them (${notice.detail}). ` +
        `autoagy stopped using its own sandbox for this agy version, so ${ctx.config.ownSandbox === 'on' ? 'every command that is not read-only is now reviewed' : "commands run in Antigravity's terminal sandbox, which leaves .git and the conversation logs writable"}. ` +
        'Tell the user about this and suggest running `autoagy status`, then retry the command.',
    };
  }

  // Once per agy build: the self-check found that this agy version does not run
  // the command line autoagy rewrites to scrub the environment where it has no
  // sandbox of its own.
  const scrubNotice =
    ctx.toolName === 'run_command' && ctx.config.commandEnv?.mode === 'scrub' && !ctx.ownSandbox.active ? takeSandboxNotice(home, ctx.hostBuild, 'envScrub') : null;
  if (scrubNotice) {
    appendDecision(home, { conversation: ctx.conversationId, step: ctx.stepIdx, tool: ctx.toolName, verdict: 'deny', reason: 'env scrub self-check notice' });
    return {
      decision: 'deny',
      reason:
        `autoagy's self-check found that this agy version does not run the command line autoagy rewrites to scrub the environment (${scrubNotice.detail}). ` +
        'autoagy stopped rewriting commands for this agy version, so they run with the environment agy itself was started with. ' +
        'Tell the user about this and suggest running `autoagy status`, then retry the command.',
    };
  }

  noteTerminalUse(ctx, state);
  const classification = classify(ctx, {
    escalatedCommandApproved: state.escalatedCommandApproved,
    untrusted: isUntrusted(state),
    // The .git directories a sandboxed command created with something runnable
    // in them; a command that touches one is reviewed rather than judged alone.
    plantedHooks: state.plantedHooks,
  });
  const summary = summarizeAction(ctx.toolName, ctx.args);
  const base = {
    conversation: ctx.conversationId,
    step: ctx.stepIdx,
    tool: ctx.toolName,
    summary,
    category: classification.category,
  };
  if (warnings.length > 0) {
    base.configWarnings = warnings;
    // The decision log is not a channel anyone watches during a session, and a
    // setting that was silently dropped is exactly what the user needs told.
    for (const warning of takeConfigWarnings(home, warnings)) process.stderr.write(`autoagy: ${warning}\n`);
  }

  // After the circuit breaker trips, only harmless tools may run for the rest of the turn.
  if (state.interrupt && classification.category !== 'read' && classification.category !== 'agent-coordination') {
    const turnKey = countUserMessages(ctx.transcriptPath);
    if (turnKey === state.interrupt.turnKey) {
      appendDecision(home, { ...base, verdict: 'deny', reason: 'circuit breaker' });
      return { decision: 'deny', reason: `${state.interrupt.message} Stop and ask the user how to proceed.` };
    }
    // The user spoke again: a new turn starts with a fresh circuit breaker.
    updateState(home, ctx.conversationId, (s) => {
      if (s.interrupt && s.interrupt.turnKey !== turnKey) {
        s.interrupt = null;
        s.turnKey = turnKey;
        s.consecutiveDenials = 0;
        s.recent = [];
      }
    });
  }

  if (classification.verdict === 'allow') {
    if (config.log.allowed) appendDecision(home, { ...base, verdict: 'allow', reason: classification.reason });
    const allowed = withCanonicalTarget({ decision: 'allow' }, ctx);
    rememberTargets(ctx, { ...ctx.args, ...(allowed.overwrite ?? {}) });
    return withOwnSandbox(allowed, ctx);
  }
  if (classification.verdict === 'deny') {
    appendDecision(home, { ...base, verdict: 'deny', reason: classification.reason });
    return { decision: 'deny', reason: classification.reason };
  }

  // Needs review.
  const reviewer = config.mode === 'auto' ? createReviewer(config, { env, autoagyHome: home, executable: ctx.reviewerExecutable }) : null;
  if (!reviewer) {
    const output = withoutUnanswerablePrompt({ decision: 'force_ask', reason: `autoagy: ${classification.reason}` }, ctx);
    appendDecision(home, { ...base, verdict: output.decision === 'force_ask' ? 'ask' : 'deny', reason: classification.reason });
    // The same two steps the reviewed path takes below, and for the same reason:
    // a person answering the prompt instead of the reviewer does not change the
    // fact that agy performs the edit itself, outside every sandbox. Resolving
    // the target before the call and comparing it after is the only protection
    // against a path swapped in between — and `withCanonicalTarget`'s own
    // `force_ask` guard says it was meant to cover this path. In `mode: ask`
    // (and with `reviewer.backend: "none"`) every reviewed action went without
    // either of them.
    const asked = withCanonicalTarget(output, ctx);
    if (asked.decision !== 'deny') rememberTargets(ctx, { ...ctx.args, ...(asked.overwrite ?? {}) });
    return withOwnSandbox(asked, ctx);
  }

  const key = actionKey(ctx.toolName, ctx.args);
  const approvals = state.approvals.filter((a) => a.actionKey === key);
  let result;
  let evidence = { rootId: null, userMessageCount: 0 };
  let prompt = null;
  try {
    evidence = gatherEvidence(ctx, { rootConversationId: state.rootConversationId });
    prompt = buildReviewPrompt(ctx, classification, evidence, {
      approvals,
      untrusted: state.untrusted,
      recentEdits: state.recentEdits,
      plantedHooks: state.plantedHooks,
    });
  } catch (err) {
    result = { status: 'failed', error: `could not build the review request: ${err.message}`, attempts: 0, latencyMs: 0 };
  }
  if (!result) result = await runReview(prompt, reviewer, config.reviewer);
  const output = withoutUnanswerablePrompt(decisionFor(result, config), ctx);
  const denialId = result.status === 'denied' ? newId() : null;

  const interrupt = updateState(home, ctx.conversationId, (s) => {
    // Cache the lookup (null = root conversation) so later reviews skip the scan.
    if (prompt) s.rootConversationId = evidence.rootId ?? null;
    if (approvals.length > 0) takeApprovals(s, key);
    if (result.status === 'approved' && ctx.toolName === 'run_command' && ctx.args.BypassSandbox === true) {
      s.escalatedCommandApproved = true;
    }
    if (denialId) {
      recordDenial(s, {
        id: denialId,
        time: new Date().toISOString(),
        tool: ctx.toolName,
        actionKey: key,
        summary,
        risk: result.assessment?.risk_level,
        rationale: result.assessment?.rationale,
      });
    }
    return recordReviewOutcome(s, {
      denied: result.status === 'denied',
      // An answer that never came is not a judgement, and the rejection breaker
      // below counts only judgements — so a reviewer that is down (quota, auth,
      // network) denied every risky action for the rest of the session while the
      // agent retried into the same wall, with nothing ever stopping the turn.
      backendError: result.status === 'failed' || result.status === 'timed_out' ? `${result.status}: ${result.error ?? 'no reason given'}` : null,
      turnKey: evidence.userMessageCount,
      circuitBreaker: config.circuitBreaker,
    });
  });
  if (denialId && output.decision === 'deny') output.reason = `${output.reason}\n(autoagy denial id: ${denialId})`;
  if (interrupt) output.reason = `${output.reason}\n${interrupt.message}`;

  appendDecision(home, {
    ...base,
    verdict: output.decision,
    reason: classification.reason,
    review: {
      backend: reviewer.name,
      status: result.status,
      risk: result.assessment?.risk_level,
      authorization: result.assessment?.user_authorization,
      rationale: result.assessment?.rationale,
      error: result.error,
      attempts: result.attempts,
      latencyMs: result.latencyMs,
      approvedByUser: approvals.length > 0 || undefined,
      subagentOf: evidence.rootId || undefined,
    },
    denialId: denialId ?? undefined,
    circuitBreaker: interrupt ? interrupt.message : undefined,
  });
  if (config.log.reviews && prompt) {
    writeReviewRecord(home, `${Date.now()}-${ctx.conversationId.slice(0, 8)}`, { prompt, result });
  }
  const reviewed = withCanonicalTarget(output, ctx);
  if (reviewed.decision !== 'deny') rememberTargets(ctx, { ...ctx.args, ...(reviewed.overwrite ?? {}) });
  return withOwnSandbox(reviewed, ctx);
}

/**
 * Removes any mount point still recorded for this conversation. Called when the
 * turn ends, which is the first moment nothing can still be running against it.
 */
function sweepPlaceholders(home, conversationId, state, ctx) {
  // See reclaimAllowed: only positive evidence that nothing is running. The
  // lock is released by the command itself when bwrap exits — including a
  // backgrounded one — so this is the first moment it is safe.
  if (!reclaimAllowed(state, ctx ? lockQuiescent(ctx, { lockFile: state.pendingLock ?? null }) : null)) return;
  const pending = Object.values(state.pendingPlaceholders ?? {});
  const tracked = Object.entries(state.pendingNestedGit ?? {});
  if (pending.length === 0 && tracked.length === 0) return;
  // The before-sets checkConfinedRun kept because a command might still have
  // been running. The union is enough for the question asked here — which nested
  // `.git` are there now that were not there when those commands started — and
  // it is one walk instead of one per step.
  const findings = tracked.length > 0 && ctx ? newNestedGitPlantings(ctx, tracked.flatMap(([, before]) => before ?? [])) : [];
  const paths = pending.flatMap((list) => list ?? []);
  updateState(home, conversationId, (s) => {
    s.pendingPlaceholders = {};
    s.pendingNestedGit = {};
    // `pendingConfined` is deliberately left alone, and the asymmetry with the
    // line above is the point. `checkConfinedRun` deletes a step's entry
    // unconditionally, so whatever is still here belongs to a step whose
    // PostToolUse never ran — and its before-set was just included in the walk
    // above, so the planting question is already answered for it. What the entry
    // still buys is the hash self-check, if that PostToolUse arrives late;
    // clearing it would throw that away and buy nothing. A stale entry cannot be
    // mistaken for another step's: `stepIdx` does not repeat within a
    // conversation (measured on a real transcript: 0..413, monotonic across
    // turns), and the write side trims the map to the newest 50.
    s.pendingLock = null;
    // The mount points are gone, so the fallback signal that produced them is
    // stale; leaving it set would keep status reporting a conversation as
    // holding mount points it no longer has.
    s.backgroundSuspected = false;
    if (findings.length > 0) recordPlantedHooks(s, findings, null);
  });
  if (findings.length > 0) reportPlantedHooks(home, ctx, findings);
  removePlaceholders(home, conversationId, paths);
}

/** Ends the agent loop once after the circuit breaker tripped. */
export function handlePostInvocation(payload, options = {}) {
  const env = options.env ?? process.env;
  const { config } = loadConfig({ env, home: options.home });
  const home = resolveAutoagyHome(env, options.home);
  const conversationId = payload?.conversationId || env.ANTIGRAVITY_CONVERSATION_ID;
  // A hook that runs at all is news: `status` uses this to tell a plugin that is
  // not loading — disabled, its pin replaced, or its interpreter broken — from
  // one that is merely quiet. Written before the early returns below, so mode
  // "off" and a payload without a conversation id both leave a mark.
  touchHeartbeat(home, 'post-invocation');
  // A token nobody redeemed is a retry nobody granted, and the end of a turn is
  // the point at which none of THIS conversation's calls can still be on their
  // way. Scoped to the conversation on purpose: the token directory is shared,
  // and another conversation's call can be between its mint and its execution
  // right now — this hook runs after every model call, not at the end of a turn.
  sweepTokens(home, { all: true, conversation: conversationId });
  if (!conversationId) return {};
  const state = readState(home, conversationId);
  // Sweep the mount points PostToolUse did not see (a backgrounded command, or
  // a mode switch), but only once the workspace lock says nothing is running.
  // Read-only first, so an idle conversation does not get a state file written.
  sweepPlaceholders(home, conversationId, state, new HookContext(payload, { config, env, home: options.home, host: options.host }));
  if (config.mode === 'off') return {};
  if (!state.interrupt?.pending) return {};
  updateState(home, conversationId, (s) => {
    if (s.interrupt) s.interrupt.pending = false;
  });
  return { terminationBehavior: 'terminate' };
}
