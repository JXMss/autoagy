// How long a hook may spend before it must answer.
//
// The budget is the `timeout` the plugin's hooks.json declares, minus a margin,
// so autoagy always answers before Antigravity kills the hook — a killed hook
// fails the tool call with an opaque error.
//
// AUTOAGY_HOOK_TIMEOUT_SEC may adjust the pre-tool-use budget for experiments.
// It deliberately cannot touch the post events: those hooks run the self-checks
// that verify agy really did run the rewritten command and that an edit's target
// still resolved where it was approved. A short budget there does not merely cut
// the check short — the watchdog answers and calls process.exit before the check
// runs at all, so the check silently disappears. The environment reaches the
// hook from agy, which a command can set for an agy it starts, so it must not be
// able to switch the self-checks off.

import fs from 'node:fs';
import path from 'node:path';

export const HOOK_TIMEOUT_FALLBACK_SEC = 150;
/** Bounds for the pre-tool-use override. A low budget is friction, not a hole:
 *  the watchdog fails closed for everything that changes anything. */
export const HOOK_TIMEOUT_ENV_MIN_SEC = 10;
export const HOOK_TIMEOUT_ENV_MAX_SEC = 600;

/** The only event whose budget the environment may override. */
export const OVERRIDABLE_EVENTS = new Set(['pre-tool-use']);

const HOOK_KEY = { 'pre-tool-use': 'PreToolUse', 'post-tool-use': 'PostToolUse', 'post-invocation': 'PostInvocation' };

/**
 * The `timeout` declared for `event` in the plugin's hooks.json, or the fallback.
 * @param {string} event
 * @param {{ pluginDir: string }} options
 */
export function declaredHookTimeoutSec(event, { pluginDir }) {
  try {
    const hooks = JSON.parse(fs.readFileSync(path.join(pluginDir, 'hooks.json'), 'utf8'));
    const key = HOOK_KEY[event];
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

/**
 * The effective hook timeout for `event`.
 * @param {string} event
 * @param {{ env?: NodeJS.ProcessEnv, pluginDir: string }} options
 */
export function hookTimeoutSec(event, { env = process.env, pluginDir } = {}) {
  const declared = declaredHookTimeoutSec(event, { pluginDir });
  if (!OVERRIDABLE_EVENTS.has(event)) return declared;
  const raw = Number(env.AUTOAGY_HOOK_TIMEOUT_SEC);
  if (!Number.isFinite(raw) || raw <= 0) return declared;
  return Math.min(HOOK_TIMEOUT_ENV_MAX_SEC, Math.max(HOOK_TIMEOUT_ENV_MIN_SEC, raw));
}

/**
 * The watchdog deadline: a few seconds inside the hook timeout, so writing the
 * decision is never what runs out of time.
 */
export function hookBudgetSec(event, options) {
  return Math.max(5, hookTimeoutSec(event, options) - 5);
}
