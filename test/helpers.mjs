// Shared fixtures: an isolated home, workspace and Antigravity app-data dir.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DEFAULT_CONFIG } from '../plugin/lib/config.mjs';
import { HookContext } from '../plugin/lib/context.mjs';

export function makeSandboxDirs() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'autoagy-test-')));
  const home = path.join(root, 'home');
  const workspace = path.join(root, 'work', 'project');
  const appData = path.join(home, '.gemini', 'antigravity-cli');
  const conversationId = '11111111-2222-4333-8444-555555555555';
  const brain = path.join(appData, 'brain', conversationId);
  const logs = path.join(brain, '.system_generated', 'logs');
  const tmp = path.join(root, 'tmp');
  for (const dir of [home, workspace, logs, tmp, path.join(workspace, '.git'), path.join(home, '.ssh')]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(path.join(appData, 'settings.json'), JSON.stringify({ enableTerminalSandbox: true, toolPermission: 'proceed-in-sandbox' }));
  return {
    root,
    tmp,
    home,
    workspace,
    appData,
    brain,
    conversationId,
    transcriptPath: path.join(logs, 'transcript_full.jsonl'),
    // AUTOAGY_UNSAFE_MOCK_REVIEWER opts the mock reviewer back in; loadConfig
    // refuses it otherwise, so the tests that drive the real binary need it.
    env: { AUTOAGY_HOME: path.join(home, '.gemini', 'autoagy'), HOME: home, PATH: process.env.PATH, AUTOAGY_UNSAFE_MOCK_REVIEWER: '1' },
    cleanup: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

export function configWith(overrides = {}) {
  const config = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  return Object.assign(config, overrides);
}

export function payloadFor(dirs, name, args, extra = {}) {
  return {
    conversationId: dirs.conversationId,
    stepIdx: 3,
    toolCall: { name, args },
    transcriptPath: dirs.transcriptPath,
    artifactDirectoryPath: dirs.brain,
    modelName: 'gemini-test',
    workspacePaths: [],
    ...extra,
  };
}

export function contextFor(dirs, name, args, { config = configWith(), env = dirs.env, host, extra, bwrapProbe } = {}) {
  const fakeHost = host === undefined ? { kind: 'cli', cwd: dirs.workspace, argv: ['agy'], flags: { skipPermissions: false, sandbox: false, addDirs: [] } } : host;
  return new HookContext(payloadFor(dirs, name, args, extra), { config, env, home: dirs.home, host: fakeHost, tempRoots: [dirs.tmp], bwrapProbe });
}

/** A bubblewrap probe that reports success, so the own sandbox is "active" without running bwrap. */
export const okProbe = () => ({ ok: true, bwrap: '/usr/bin/bwrap', detail: 'test' });

/**
 * autoagy's own sandbox exists only on Linux (`detectOwnSandbox` refuses every
 * other platform), so a test that needs it active cannot pass anywhere else —
 * `okProbe` fakes bubblewrap, not the platform. Those tests are skipped there,
 * with this as the reason; the real-bubblewrap ones already skip on their own.
 */
export const ownSandboxPlatform = process.platform === 'linux';
export const linuxOnly = ownSandboxPlatform ? false : "autoagy's own sandbox exists only on Linux";
