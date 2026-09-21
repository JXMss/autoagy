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
  // A declaration does not outweigh the flag that is known to defeat what it declares.
  const both = detect({ platform: 'linux', config: configWith({ sandbox: 'on' }), host: cliHost({ skipPermissions: true }) });
  assert.deepEqual([both.active, both.source], [false, 'flag']);
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
  assert.deepEqual(config('[core]\n\thooksPath = .husky\n').config, ['hooksPath']);
  assert.deepEqual(config('[core]\n\tfsmonitor = /usr/bin/fsmon\n').config, ['fsmonitor']);
  assert.deepEqual(config('[alias]\n\tco = checkout\n').config, ['[alias]']);
  assert.deepEqual(config('[alias "st"]\n\tst = status\n').config, ['[alias]']);
  // `[include]` is not a key that runs a command, it is a key that changes which
  // file is read — and that file is not inside a `.git`, so nothing inspects it.
  // Measured: git honours it (`git config --get core.pager` returns the value
  // from the included file) while this check saw nothing in either file.
  assert.deepEqual(config(`[include]\n\tpath = ${path.join(dirs.root, 'evil.cfg')}\n`).config, ['[include]']);
  assert.deepEqual(config('[includeIf "gitdir:**"]\n\tpath = x.cfg\n').config, ['[includeif]']);
  // A real .git/config, including a remote whose URL carries one of the words.
  assert.equal(
    config('[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://host/sshCommand\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n'),
    null,
  );
});

test('every config key that makes git run a command is a trigger, not only the hook ones', () => {
  const config = (text) => withGitDir((d) => fs.writeFileSync(path.join(d, 'config'), text));
  // Each of these reaches the same place `hooksPath` does, by a different door:
  // a fetch or push, authentication, a checkout, ordinary porcelain.
  const doors = {
    sshCommand: '[core]\n\tsshCommand = ./evil.sh\n',
    pager: '[core]\n\tpager = ./evil.sh\n',
    editor: '[core]\n\teditor = ./evil.sh\n',
    askPass: '[core]\n\taskPass = ./evil.sh\n',
    helper: '[credential]\n\thelper = !./evil.sh\n',
    clean: '[filter "f"]\n\tclean = ./evil.sh\n',
    textconv: '[diff "d"]\n\ttextconv = ./evil.sh\n',
    driver: '[merge "m"]\n\tdriver = ./evil.sh %O %A %B\n',
    packObjectsHook: '[uploadpack]\n\tpackObjectsHook = ./evil.sh\n',
    templateDir: '[init]\n\ttemplateDir = ../t\n',
    program: '[gpg]\n\tprogram = ./evil.sh\n',
  };
  for (const [key, text] of Object.entries(doors)) {
    assert.deepEqual(config(text)?.config, [key], key);
  }
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

test('a new repository the reading budget did not reach is recorded as unchecked, not skipped', () => {
  const plain = path.join(dirs.workspace, 'plain', '.git');
  fs.mkdirSync(plain, { recursive: true });
  try {
    const ctx = contextFor(dirs, 'run_command', { CommandLine: 'ls' });
    // Read in time: an empty `git init` holds nothing runnable and is not a finding.
    assert.deepEqual(newNestedGitPlantings(ctx, []), []);
    // Not read: not knowing is treated like it holding something.
    const late = newNestedGitPlantings(ctx, [], { budgetMs: 0 });
    assert.deepEqual(late.map((f) => [f.path, f.unchecked]), [[plain, true]]);
  } finally {
    fs.rmSync(path.join(dirs.workspace, 'plain'), { recursive: true, force: true });
  }
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

test('a relative policy.file no longer breaks every tool call', () => {
  // This is the regression test. The value reaches `selfPaths`, and the version
  // of that line which fed `toAbsolute`'s null straight into `resolveReal` made
  // every edit and command come back as a fail-closed deny reading
  // `autoagy internal error (The "path" argument must be of type string.
  // Received null)` — a sentence that explains nothing to the person seeing it.
  const relative = contextFor(dirs, 'run_command', { CommandLine: 'ls' }, { config: configWith({ policy: { file: 'policy.md' } }) });
  assert.ok(Array.isArray(relative.selfPaths));
  assert.ok(!relative.selfPaths.some((p) => typeof p !== 'string'));

  // And a value that IS usable names one file for every reader: `~` expanded
  // once, here and in the prompt that reads it.
  const file = path.join(dirs.env.AUTOAGY_HOME, 'policy.md');
  fs.mkdirSync(dirs.env.AUTOAGY_HOME, { recursive: true });
  fs.writeFileSync(file, '## Custom\n- Never allow deploys.');
  const tilde = contextFor(dirs, 'run_command', { CommandLine: 'ls' }, { config: configWith({ policy: { file: '~/.gemini/autoagy/policy.md' } }) });
  assert.ok(tilde.selfPaths.includes(fs.realpathSync(file)), 'the file selfPaths protects is the one the reviewer reads');
});
