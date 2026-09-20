import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { detectSandbox, HOST_INSPECTABLE_PLATFORMS, plantedGitContent, newNestedGitPlantings } from '../plugin/lib/context.mjs';
import { makeSandboxDirs, configWith, contextFor } from './helpers.mjs';

const dirs = makeSandboxDirs();
after(() => dirs.cleanup());

const cliHost = (flags = {}) => ({ kind: 'cli', cwd: dirs.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [], ...flags } });
const detect = (options) => detectSandbox({ config: configWith(), host: null, appDataDir: dirs.appData, own: { active: false, required: false }, ...options });

test('the settings file cannot report an active sandbox where the process arguments cannot be read', () => {
  // Windows has no terminal sandbox, and --dangerously-skip-permissions cannot
  // be seen there. autoagy setup writes the very values the settings file is
  // checked for, so trusting it would report a sandbox that does not exist.
  const out = detect({ platform: 'win32' });
  assert.equal(out.active, false);
  assert.equal(out.source, 'platform');
  assert.match(out.detail, /cannot read the agy process arguments/);
  assert.ok(!HOST_INSPECTABLE_PLATFORMS.includes('win32'));
});

test('the IDE case still reads the sandbox state from the settings file', () => {
  // On Linux and macOS the host is only sometimes identifiable — an IDE user
  // relies on this branch, and there the flag could have been read if present.
  for (const platform of HOST_INSPECTABLE_PLATFORMS) {
    const out = detect({ platform });
    assert.equal(out.active, true, platform);
    assert.equal(out.source, 'settings', platform);
  }
});

test('detected flags and an explicit config still decide the answer', () => {
  assert.equal(detect({ platform: 'win32', config: configWith({ sandbox: 'on' }) }).active, true, 'config.sandbox "on" is the documented escape hatch');
  assert.equal(detect({ platform: 'linux', host: cliHost({ skipPermissions: true }) }).active, false);
  assert.equal(detect({ platform: 'linux', host: cliHost({ skipPermissions: true }) }).source, 'flag');
  // Nowhere to read the arguments, no settings file, nothing declared.
  assert.equal(detect({ platform: 'win32', appDataDir: null }).source, 'platform');
});

// A `.git` is judged on what is in it, never on its existing: creating a
// repository is a routine agent action, while a record that flags one names an
// innocent path on stderr and costs the user a review on every command that
// touches it from then on.
const gitDir = path.join(dirs.root, 'planted');

function withGitDir(build) {
  fs.rmSync(gitDir, { recursive: true, force: true });
  fs.mkdirSync(gitDir, { recursive: true });
  build(gitDir);
  return plantedGitContent(gitDir);
}

test('a .git holds runnable content only when something in it actually runs', () => {
  assert.equal(withGitDir(() => {}), null, 'an empty .git is what `git init` makes');
  assert.equal(withGitDir((d) => fs.mkdirSync(path.join(d, 'hooks'))), null);
  assert.equal(
    withGitDir((d) => {
      fs.mkdirSync(path.join(d, 'hooks'));
      fs.writeFileSync(path.join(d, 'hooks', 'pre-commit.sample'), '#!/bin/sh\n');
    }),
    null,
    "git's own samples are not hooks",
  );
  assert.equal(
    withGitDir((d) => {
      fs.mkdirSync(path.join(d, 'hooks'));
      fs.mkdirSync(path.join(d, 'hooks', 'pre-commit'));
    }),
    null,
    'a directory is not a hook',
  );

  const hook = withGitDir((d) => {
    fs.mkdirSync(path.join(d, 'hooks'));
    fs.writeFileSync(path.join(d, 'hooks', 'pre-commit'), '#!/bin/sh\necho pwned\n');
  });
  assert.equal(hook.hooks.length, 1);
  assert.equal(hook.hooks[0].name, 'pre-commit');
  assert.match(hook.hooks[0].head, /pwned/);
  assert.ok(hook.hooks[0].bytes > 0);

  // A symlinked hook counts: `isFile()` is false for those, and pointing the
  // hook at a file the agent can write is the shape a plant is most likely to
  // take, since the target can live anywhere.
  const target = path.join(dirs.root, 'evil.sh');
  fs.writeFileSync(target, '#!/bin/sh\necho pwned\n');
  const linked = withGitDir((d) => {
    fs.mkdirSync(path.join(d, 'hooks'));
    fs.symlinkSync(target, path.join(d, 'hooks', 'pre-commit'));
  });
  assert.equal(linked.hooks.length, 1);
  assert.equal(linked.hooks[0].name, 'pre-commit');
});

test('config is judged by key, not by the word appearing somewhere', () => {
  const config = (text) => withGitDir((d) => fs.writeFileSync(path.join(d, 'config'), text));
  assert.equal(config('[core]\n\trepositoryformatversion = 0\n'), null);
  // A remote URL that happens to contain the word is not a trigger. Matching it
  // as a substring would accuse a repository that never set a hook path.
  assert.equal(config('[remote "origin"]\n\turl = https://host/hooksPath\n'), null);
  assert.deepEqual(config('[core]\n\thooksPath = .husky\n').config, ['hooksPath/fsmonitor']);
  assert.deepEqual(config('[core]\n\tfsmonitor = /usr/bin/fsmon\n').config, ['hooksPath/fsmonitor']);
  assert.deepEqual(config('[alias]\n\tco = checkout\n').config, ['[alias]']);
  assert.deepEqual(config('[alias "st"]\n\tst = status\n').config, ['[alias]']);
});

test('the hook list is capped and the head is read, not loaded', () => {
  const many = withGitDir((d) => {
    fs.mkdirSync(path.join(d, 'hooks'));
    for (let i = 0; i < 9; i += 1) fs.writeFileSync(path.join(d, 'hooks', `hook-${i}`), '#!/bin/sh\n');
  });
  assert.equal(many.hooks.length, 5);
  assert.equal(many.hooksMore, 4);

  // A "hook" that is enormous must not be read into memory to describe it.
  const big = withGitDir((d) => {
    fs.mkdirSync(path.join(d, 'hooks'));
    fs.writeFileSync(path.join(d, 'hooks', 'pre-commit'), 'x'.repeat(200000));
  });
  assert.equal(big.hooks[0].bytes, 200000);
  assert.equal(big.hooks[0].head.length, 400);
});

test('only a .git that was not there when the command was built counts as a planting', () => {
  const existing = path.join(dirs.workspace, 'existing', '.git');
  const created = path.join(dirs.workspace, 'created', '.git');
  for (const dir of [existing, created]) {
    fs.mkdirSync(path.join(dir, 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'hooks', 'pre-commit'), '#!/bin/sh\n');
  }
  try {
    const ctx = contextFor(dirs, 'run_command', { CommandLine: 'ls' });
    const found = newNestedGitPlantings(ctx, [existing]);
    assert.deepEqual(found.map((f) => f.path), [created]);
    assert.equal(found[0].dir, path.dirname(created), 'the repository, which is what a later git command runs in');
    // Everything that was already there is excluded, however runnable it is.
    assert.deepEqual(newNestedGitPlantings(ctx, [existing, created]), []);
  } finally {
    fs.rmSync(path.join(dirs.workspace, 'existing'), { recursive: true, force: true });
    fs.rmSync(path.join(dirs.workspace, 'created'), { recursive: true, force: true });
  }
});
