// Fails when the test run skipped anything.
//
// Skipping is right on a developer's machine — the own-sandbox tests need Linux
// and bubblewrap, `flock` is not everywhere — and it is exactly wrong in CI,
// which is the one place that is supposed to have all of it. A skipped
// real-sandbox test is not a smaller version of a passing one: the command
// inside autoagy's sandbox is the command that runs with no review at all, so
// "the suite is green and the sandbox never started" is the failure this repo
// has already been bitten by (docs/design.md, thirteenth round: a protection
// that was wired in, tested, and never called — every behavioural test passed).
//
// The CI workflow runs the suite with the TAP reporter and hands the output
// here. Usage:
//
//   node --test --test-reporter=tap test/*.test.mjs | tee tap.txt
//   node scripts/assert-no-skips.mjs tap.txt
//
// Exit 0 when nothing was skipped, 1 with the list when something was.

import fs from 'node:fs';

const file = process.argv[2];
if (!file) {
  console.error('autoagy: usage: node scripts/assert-no-skips.mjs <tap-output-file>');
  process.exit(2);
}

let text;
try {
  text = fs.readFileSync(file, 'utf8');
} catch (err) {
  console.error(`autoagy: cannot read ${file}: ${err.message}`);
  process.exit(2);
}

// A skipped leaf test shows up as `ok 12 - name # SKIP reason` (and `# TODO` for
// a todo). Directive lines are matched case-sensitively on purpose: a test whose
// name happens to contain "skip" is not a skipped test.
const skipped = [];
const ran = [];
for (const line of text.split('\n')) {
  const m = /^(ok|not ok) (\d+) - (.*)$/.exec(line.trim());
  if (!m) continue;
  const directive = /#\s*(SKIP|TODO)\b(.*)$/.exec(m[3]);
  if (directive) skipped.push({ name: m[3].replace(/#\s*(SKIP|TODO)\b.*$/, '').trim(), why: directive[2].trim() || directive[1] });
  else ran.push(m[3].trim());
}

if (ran.length === 0) {
  console.error('autoagy: no tests ran — the TAP file is empty or was not produced. Check the step that writes it.');
  process.exit(1);
}

if (skipped.length > 0) {
  console.error(`autoagy: ${skipped.length} test(s) skipped, ${ran.length} ran. CI is expected to run all of them:`);
  for (const s of skipped) console.error(`  - ${s.name}${s.why ? ` (${s.why})` : ''}`);
  console.error('\nInstall what the skip needs (bubblewrap, util-linux flock) or fix the reason above.');
  console.error('If a skip is genuinely correct in CI, change this guard rather than letting it pass quietly.');
  process.exit(1);
}

console.log(`autoagy: ${ran.length} test(s) ran, none skipped.`);
