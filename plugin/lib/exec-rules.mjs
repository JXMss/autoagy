// Codex execpolicy-style prefix rules (a subset of `prefix_rule(...)`).
//
//   { "pattern": ["git", ["push", "fetch"]], "decision": "prompt", "justification": "..." }
//
// Each pattern token is a literal or a list of alternatives, matched against
// the leading arguments of every command segment. Decisions combine as
// forbidden > prompt > allow. As in Codex, an `allow` rule only covers a
// command line that uses no redirection, substitution, variable assignment or
// glob, so an approved prefix cannot be stretched to run something else.

import { executableName } from './command-safety.mjs';

const SEVERITY = { allow: 1, prompt: 2, forbidden: 3 };
const COMPLEX_FEATURES = [
  'substitution',
  'process-substitution',
  'redirect-write',
  'redirect-read',
  'redirect-null',
  'heredoc',
  'herestring',
  'assignment',
  'glob',
  'background',
  'function',
  'arith',
  'brace-expansion',
  'variable',
];

function tokenMatches(token, value) {
  return Array.isArray(token) ? token.includes(value) : token === value;
}

/** True when the rule's pattern is a prefix of argv (first token by executable name). */
export function ruleMatches(rule, argv) {
  if (argv.length < rule.pattern.length) return false;
  return rule.pattern.every((token, i) => tokenMatches(token, i === 0 ? executableName(argv[0]) : argv[i]) || (i === 0 && tokenMatches(token, argv[0])));
}

/**
 * @param {import('./command-safety.mjs').CommandAnalysis} analysis
 * @param {object[]} rules
 * @returns {{ decision: 'allow' | 'prompt' | 'forbidden' | null, rule: object | null, argv: string[] | null, allCovered: boolean }}
 */
export function evaluateRules(analysis, rules) {
  let best = null;
  if (!rules || rules.length === 0) return { decision: null, rule: null, argv: null, allCovered: false };
  // forbidden/prompt rules apply to every command the line would run.
  for (const segment of analysis.segments) {
    for (const rule of rules) {
      if (!ruleMatches(rule, segment.argv)) continue;
      if (!best || SEVERITY[rule.decision] > SEVERITY[best.rule.decision]) best = { rule, argv: segment.argv };
    }
  }
  const simple = !analysis.error && !analysis.tooDeep && !COMPLEX_FEATURES.some((f) => analysis.features.has(f));
  const topLevel = analysis.parsed.commands.filter((c) => !c.nested);
  const allCovered =
    simple &&
    topLevel.length > 0 &&
    topLevel.every((c) => c.argv.length > 0 && rules.some((rule) => rule.decision === 'allow' && ruleMatches(rule, c.argv))) &&
    // Nothing reached through wrappers or nested shells may escape the allow rules.
    analysis.segments.every((s) => s.depth === 0 || rules.some((rule) => rule.decision === 'allow' && ruleMatches(rule, s.argv)));
  if (!best) return { decision: null, rule: null, argv: null, allCovered: false };
  const decision = best.rule.decision === 'allow' && !allCovered ? null : best.rule.decision;
  return { decision, rule: best.rule, argv: best.argv, allCovered };
}

/** Human-readable form of a rule for messages. */
export function describeRule(rule) {
  const tokens = rule.pattern.map((t) => (Array.isArray(t) ? `[${t.join('|')}]` : t));
  return `${rule.decision} ${JSON.stringify(tokens.join(' '))}${rule.justification ? ` — ${rule.justification}` : ''}`;
}
