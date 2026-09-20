#!/usr/bin/env node
// The hook that notices autoagy is not running.
//
// A plugin cannot report that it stopped being loaded: code nobody calls says
// nothing. That is the shape of the risk the README opens with — the grants
// `autoagy setup` added keep working after the hook stops, and the failure is
// silent. The three ways it happens are `agy plugin disable`, an `agy plugin
// install` that replaces the pinned hooks.json, and a pinned interpreter that
// no longer runs.
//
// So this runs from somewhere `agy plugin` does not manage. Measured on agy
// 1.2.7: `~/.gemini/config/hooks.json` is loaded and fires, survives
// `plugin disable` and `plugin install`, and a name that differs from the
// plugin's does not collide (same name in two files runs both — that is why
// this is a separate name and not a second copy of autoagy's own hooks).
//
// It answers one question and costs nothing when the answer is good: is the
// plugin there and enabled? If not, every tool call is refused, because the
// grants are still in place and nothing else is looking at them.
//
// The third failure mode needs no check. A hook that cannot run at all makes
// the tool call fail (measured), so a broken interpreter fails closed by
// itself — provided this file's own interpreter is the one `autoagy setup`
// pinned, which it is.
//
// Self-contained, and installed under $AUTOAGY_HOME rather than in the plugin:
// it has to keep working when the plugin directory is the thing that went away.

import fs from 'node:fs';

const PLUGIN_DIR = '__PLUGIN_DIR__';
const CONFIG_JSON = '__CONFIG_JSON__';
const PLUGIN_NAME = 'autoagy';

const readJson = (file) => {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
};

/** Why autoagy's own hooks are not running, or null when they are. */
function whatIsWrong() {
  // `agy plugin disable <name>` records `plugins.<name>.enabled = false` here
  // and the plugin's hooks.json stops being loaded entirely (measured).
  const enabled = readJson(CONFIG_JSON)?.plugins?.[PLUGIN_NAME]?.enabled;
  if (enabled === false) return `the ${PLUGIN_NAME} plugin is disabled (\`agy plugin enable ${PLUGIN_NAME}\`)`;

  const hooks = readJson(`${PLUGIN_DIR}/hooks.json`);
  if (!hooks) return `${PLUGIN_DIR}/hooks.json is missing or unreadable`;
  // `agy plugin install` writes the source tree's copy over the installed one,
  // which drops the absolute paths `autoagy setup` pinned into it. The hooks
  // would still load, but against an interpreter and a configuration directory
  // taken from whatever environment agy inherited.
  const commands = JSON.stringify(hooks);
  if (!commands.includes('hook pre-tool-use')) return `${PLUGIN_DIR}/hooks.json no longer registers autoagy's PreToolUse hook`;
  if (!commands.includes('--autoagy-home')) return `${PLUGIN_DIR}/hooks.json is not pinned (run \`autoagy setup\`)`;
  return null;
}

const wrong = whatIsWrong();
if (!wrong) {
  // No opinion: Antigravity's own permission flow and autoagy's real hook decide.
  process.stdout.write('');
  process.exit(0);
}
process.stdout.write(
  JSON.stringify({
    decision: 'deny',
    reason:
      `autoagy is not reviewing anything: ${wrong}. The permission grants \`autoagy setup\` added are still in place, ` +
      'so tool calls are refused rather than run unreviewed. Tell the user, and suggest `autoagy status`. ' +
      'To stop reviewing on purpose use `autoagy mode off`, and to remove autoagy entirely use `autoagy teardown`.',
  }),
);
