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
import { HookContext } from './context.mjs';
import { classify, READ_ONLY_TOOLS, AGENT_TOOLS, BROWSER_ACTION_TOOLS, FILE_EDIT_TOOLS, editTargets } from './policy.mjs';
import { isKnownSafeCommandLine } from './command-safety.mjs';
import { confinedCommandLine, commandHash, recordSandboxCheck, takeSandboxNotice, removeControlPlaceholders } from './confine.mjs';
import { gatherEvidence, buildReviewPrompt, runReview, decisionFor } from './guardian.mjs';
import { createReviewer } from './reviewers.mjs';
import { readState, updateState, recordReviewOutcome, recordDenial, takeApprovals, actionKey, newId } from './state.mjs';
import { appendDecision, writeReviewRecord } from './log.mjs';
import { readTranscriptRows } from './transcript.mjs';

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
  if (output?.decision !== 'force_ask' || !ctx.host?.flags?.skipPermissions) return output;
  return {
    decision: 'deny',
    reason: `${output.reason}\nautoagy cannot ask the user here: agy runs with --dangerously-skip-permissions, which would auto-approve the prompt. Ask the user in chat instead.`,
  };
}

/**
 * Mode "off": no review, but the grants `autoagy setup` added (command(*),
 * mcp(*), execute_url(*)) must not let the actions they cover run unchecked.
 * Those actions go back to the user, as they would without autoagy.
 */
export function offModeOutput(ctx) {
  const name = ctx.toolName;
  let what = null;
  if (name === 'run_command') {
    if (ctx.args.BypassSandbox === true) what = 'a command outside the terminal sandbox';
    else if (!ctx.sandbox.active && !isKnownSafeCommandLine(String(ctx.args.CommandLine ?? ''))) what = 'a command the terminal sandbox does not confine';
  } else if (name === 'call_mcp_tool' || name.startsWith('mcp_')) {
    what = 'an MCP tool call';
  } else if (BROWSER_ACTION_TOOLS.has(name)) {
    what = 'a browser action';
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
  if (ctx.toolName !== 'run_command' || ctx.args.BypassSandbox === true || typeof ctx.args.CommandLine !== 'string') return output;
  if (!ctx.ownSandbox.active) return output;
  const placeholders = [];
  const commandLine = confinedCommandLine(ctx, ctx.args.CommandLine, { placeholders });
  // Remembered for the PostToolUse self-check and for cleaning the mount points up.
  if (ctx.stepIdx !== null) {
    updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
      // Commands run one at a time, so a mount point recorded for another step
      // belongs to a command that already finished: PostToolUse removes them,
      // this catches the ones it did not see.
      for (const [step, paths] of Object.entries(s.pendingPlaceholders)) {
        if (Number(step) === ctx.stepIdx) continue;
        removeControlPlaceholders(paths);
        delete s.pendingPlaceholders[step];
      }
      s.pendingConfined[ctx.stepIdx] = commandHash(commandLine);
      if (placeholders.length) s.pendingPlaceholders[ctx.stepIdx] = placeholders;
      const steps = Object.keys(s.pendingConfined);
      for (const step of steps.slice(0, Math.max(0, steps.length - MAX_PENDING_CONFINED))) delete s.pendingConfined[step];
    });
  } else {
    // Nothing to key the cleanup on: do not leave the mount points behind.
    removeControlPlaceholders(placeholders);
  }
  return { ...output, overwrite: { BypassSandbox: true, CommandLine: commandLine } };
}

const MAX_PENDING_CONFINED = 50;

/**
 * PostToolUse: the two checks that only the arguments which actually ran can
 * answer — whether agy kept autoagy's sandbox rewrite, and whether the target
 * of a file edit still resolved where it did when the edit was approved.
 */
export function handlePostToolUse(payload, options = {}) {
  const env = options.env ?? process.env;
  const { config } = loadConfig({ env, home: options.home });
  if (config.mode === 'off') return {};
  const ctx = new HookContext(payload, { config, env, home: options.home, host: options.host });
  if (ctx.stepIdx === null) return {};
  if (ctx.toolName === 'run_command') return checkConfinedRun(ctx);
  if (FILE_EDIT_TOOLS.has(ctx.toolName)) return checkEditTargets(ctx);
  return {};
}

/**
 * Checks that agy ran the command exactly as autoagy rewrote it (the payload
 * carries the arguments that actually executed). A mismatch means this agy
 * build no longer honors the rewrite, so the own sandbox is switched off for
 * it; see detectOwnSandbox. The mount points of protected directories that did
 * not exist are taken away again here, once the command has run.
 */
function checkConfinedRun(ctx) {
  const home = ctx.autoagyHome;
  const recorded = updateState(home, ctx.conversationId, (s) => {
    const entry = s.pendingConfined[ctx.stepIdx] ? { hash: s.pendingConfined[ctx.stepIdx], placeholders: s.pendingPlaceholders[ctx.stepIdx] ?? [] } : null;
    delete s.pendingConfined[ctx.stepIdx];
    delete s.pendingPlaceholders[ctx.stepIdx];
    return entry;
  });
  removeControlPlaceholders(recorded?.placeholders);
  if (!recorded) return {};
  let problem = null;
  if (commandHash(ctx.args.CommandLine) !== recorded.hash) problem = 'agy ran the original command instead of the one autoagy rewrote';
  else if (ctx.args.BypassSandbox !== true) problem = "agy ran the rewritten command without BypassSandbox, inside its own sandbox";
  recordSandboxCheck(home, ctx.hostBuild, problem);
  if (problem) appendDecision(home, { conversation: ctx.conversationId, step: ctx.stepIdx, tool: ctx.toolName, verdict: 'self-check-failed', error: problem });
  return {};
}

/** Records where an edit tool's targets resolved, for checkEditTargets. */
function rememberEditTargets(ctx) {
  if (ctx.stepIdx === null || !FILE_EDIT_TOOLS.has(ctx.toolName)) return;
  const targets = editTargets(ctx);
  if (targets.length === 0) return;
  updateState(ctx.autoagyHome, ctx.conversationId, (s) => {
    s.pendingEdits[ctx.stepIdx] = targets;
    const steps = Object.keys(s.pendingEdits);
    for (const step of steps.slice(0, Math.max(0, steps.length - MAX_PENDING_EDITS))) delete s.pendingEdits[step];
  });
}

const MAX_PENDING_EDITS = 50;

/**
 * agy writes edited files itself, outside every sandbox, so autoagy can only
 * judge the target before the write. Resolving it again here catches a path
 * that was swapped for a symlink in between (a command running in the
 * background could do that): the write may have landed somewhere other than
 * the location that was approved, which is worth interrupting the turn over.
 */
function checkEditTargets(ctx) {
  const home = ctx.autoagyHome;
  const recorded = updateState(home, ctx.conversationId, (s) => {
    const targets = s.pendingEdits[ctx.stepIdx] ?? null;
    delete s.pendingEdits[ctx.stepIdx];
    return targets;
  });
  if (!recorded) return {};
  const now = new Map(editTargets(ctx).map((t) => [t.abs, t.real]));
  for (const { abs, real } of recorded) {
    const after = now.get(abs);
    if (!after || after === real) continue;
    const message =
      `autoagy: ${abs} resolved to ${real} when the ${ctx.toolName} was approved, but to ${after} when it ran. ` +
      'Something replaced part of that path in between, so the write may have landed outside the approved location. ' +
      'Check what changed there before continuing.';
    appendDecision(home, {
      conversation: ctx.conversationId,
      step: ctx.stepIdx,
      tool: ctx.toolName,
      verdict: 'edit-target-changed',
      path: abs,
      before: real,
      after,
    });
    updateState(home, ctx.conversationId, (s) => {
      s.interrupt = { turnKey: countUserMessages(ctx.transcriptPath), pending: true, message };
    });
    return {};
  }
  return {};
}

/** The decision used when autoagy itself fails: never block reads, never allow the rest. */
export function failClosedOutput(payload, error) {
  const name = payload?.toolCall?.name;
  if (READ_ONLY_TOOLS.has(name) || AGENT_TOOLS.has(name)) return { decision: 'allow' };
  return {
    decision: 'deny',
    reason: `autoagy internal error (${error?.message ?? error}); the action was blocked to fail closed. See ~/.gemini/autoagy/logs/decisions.jsonl.`,
  };
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
  if (config.mode === 'off') return offModeOutput(ctx);
  const home = ctx.autoagyHome;

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

  const state = readState(home, ctx.conversationId);
  const classification = classify(ctx, { escalatedCommandApproved: state.escalatedCommandApproved });
  const summary = summarizeAction(ctx.toolName, ctx.args);
  const base = {
    conversation: ctx.conversationId,
    step: ctx.stepIdx,
    tool: ctx.toolName,
    summary,
    category: classification.category,
  };
  if (warnings.length > 0) base.configWarnings = warnings;

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
    rememberEditTargets(ctx);
    return withOwnSandbox({ decision: 'allow' }, ctx);
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
    return withOwnSandbox(output, ctx);
  }

  const key = actionKey(ctx.toolName, ctx.args);
  const approvals = state.approvals.filter((a) => a.actionKey === key);
  let result;
  let evidence = { rootId: null, userMessageCount: 0 };
  let prompt = null;
  try {
    evidence = gatherEvidence(ctx, { rootConversationId: state.rootConversationId });
    prompt = buildReviewPrompt(ctx, classification, evidence, { approvals });
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
  if (output.decision !== 'deny') rememberEditTargets(ctx);
  return withOwnSandbox(output, ctx);
}

/** Ends the agent loop once after the circuit breaker tripped. */
export function handlePostInvocation(payload, options = {}) {
  const env = options.env ?? process.env;
  const { config } = loadConfig({ env, home: options.home });
  if (config.mode === 'off') return {};
  const home = resolveAutoagyHome(env, options.home);
  const conversationId = payload?.conversationId || env.ANTIGRAVITY_CONVERSATION_ID;
  if (!conversationId) return {};
  const state = readState(home, conversationId);
  if (!state.interrupt?.pending) return {};
  updateState(home, conversationId, (s) => {
    if (s.interrupt) s.interrupt.pending = false;
  });
  return { terminationBehavior: 'terminate' };
}
