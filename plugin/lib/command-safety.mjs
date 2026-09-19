// Static command analysis: which literal commands a command line runs, which
// of them are destructive enough to need review even inside the terminal
// sandbox, and which command lines are known to be read-only.
//
// Dangerous-command detection follows OpenAI Codex (codex-rs/shell-command,
// `is_dangerous_command.rs`): a forced `rm`, looked for through `sudo`,
// `env`, `trap` and nested shell scripts. Because Antigravity's terminal
// sandbox — unlike Codex's — does not keep `.git` read-only, history- and
// worktree-destroying git commands are flagged as well.
//
// The known-safe list follows Codex's historical `is_known_safe_command`.

import { parseShell, isFileWriteRedirect, MAX_NESTING_DEPTH } from './shell.mjs';

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'mksh', 'fish']);

/** Returns the lookup key for an executable: its basename without Windows suffixes. */
export function executableName(raw) {
  if (typeof raw !== 'string' || raw === '') return '';
  let name = raw.split(/[\\/]/).pop() ?? raw;
  name = name.replace(/^[A-Za-z]:/, '');
  const lower = name.toLowerCase();
  for (const suffix of ['.exe', '.cmd', '.bat', '.com']) {
    if (lower.endsWith(suffix)) return name.slice(0, -suffix.length);
  }
  return name;
}

/**
 * For wrappers such as `sudo X`, `env A=b X`, `nohup X`, `timeout 5 X`,
 * returns the wrapped argv; otherwise null.
 * @param {string[]} argv
 * @returns {string[] | null}
 */
export function unwrapCommand(argv) {
  const name = executableName(argv[0]);
  const rest = argv.slice(1);
  const skipOptions = (args, withValue = new Set()) => {
    let i = 0;
    while (i < args.length && args[i].startsWith('-') && args[i] !== '-') {
      if (args[i] === '--') return args.slice(i + 1);
      if (withValue.has(args[i])) i++;
      i++;
    }
    return args.slice(i);
  };
  switch (name) {
    case 'sudo':
    case 'doas':
      return nonEmpty(skipOptions(rest, new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T'])));
    case 'env': {
      let i = 0;
      while (i < rest.length) {
        const arg = rest[i];
        if (arg === '--') {
          i++;
          break;
        }
        if (arg === '-u' || arg === '--unset' || arg === '-C' || arg === '--chdir' || arg === '-S' || arg === '--split-string') {
          if (arg === '-S' || arg === '--split-string') return null; // handled by shellScriptOf
          i += 2;
          continue;
        }
        if (arg.startsWith('-')) {
          i++;
          continue;
        }
        if (/^[^=]+=/.test(arg)) {
          i++;
          continue;
        }
        break;
      }
      return nonEmpty(rest.slice(i));
    }
    case 'nohup':
    case 'setsid':
    case 'chronic':
    case 'unbuffer':
    case 'builtin':
      return nonEmpty(skipOptions(rest));
    case 'command':
      if (rest[0] === '-v' || rest[0] === '-V') return null;
      return nonEmpty(skipOptions(rest));
    case 'exec':
      return nonEmpty(skipOptions(rest, new Set(['-a'])));
    case 'time':
      return nonEmpty(skipOptions(rest, new Set(['-o', '-f', '--output', '--format'])));
    case 'nice':
      return nonEmpty(skipOptions(rest, new Set(['-n', '--adjustment'])));
    case 'ionice':
      return nonEmpty(skipOptions(rest, new Set(['-c', '-n', '-p', '-P', '-u'])));
    case 'stdbuf':
      return nonEmpty(skipOptions(rest, new Set(['-i', '-o', '-e'])));
    case 'timeout': {
      const args = skipOptions(rest, new Set(['-s', '--signal', '-k', '--kill-after']));
      return nonEmpty(args.slice(1));
    }
    case 'xargs': {
      const args = skipOptions(
        rest,
        new Set(['-a', '--arg-file', '-d', '--delimiter', '-E', '-e', '-I', '-i', '-L', '-l', '-n', '--max-args', '-P', '--max-procs', '-s', '--max-chars']),
      );
      return nonEmpty(args);
    }
    case 'flock': {
      const args = skipOptions(rest, new Set(['-w', '--wait', '--timeout', '-E', '--conflict-exit-code']));
      return nonEmpty(args.slice(1));
    }
    default:
      return null;
  }
}

function nonEmpty(argv) {
  return argv && argv.length > 0 ? argv : null;
}

/**
 * Returns shell source that `argv` would execute as a script
 * (`bash -lc "..."`, `eval ...`, `trap '...' EXIT`, `watch ...`, `env -S ...`), or null.
 * @param {string[]} argv
 * @returns {string | null}
 */
export function shellScriptOf(argv) {
  const name = executableName(argv[0]);
  if (SHELLS.has(name) || (name === 'busybox' && SHELLS.has(executableName(argv[1] ?? '')))) {
    const args = name === 'busybox' ? argv.slice(2) : argv.slice(1);
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (arg === '--') break;
      if (/^-[A-Za-z]*c[A-Za-z]*$/.test(arg) || arg === '--command') {
        return args[i + 1] ?? '';
      }
      if (!arg.startsWith('-') && !arg.startsWith('+')) break;
    }
    return null;
  }
  if (name === 'eval') return argv.slice(1).join(' ');
  if (name === 'trap') {
    let i = 1;
    if (argv[i] === '--') i++;
    const action = argv[i];
    return action && !action.startsWith('-') ? action : null;
  }
  if (name === 'watch') {
    const args = argv.slice(1);
    let i = 0;
    while (i < args.length && args[i].startsWith('-')) {
      if (['-n', '--interval', '-q', '--equexit'].includes(args[i])) i++;
      i++;
    }
    return args.length > i ? args.slice(i).join(' ') : null;
  }
  if (name === 'env') {
    const idx = argv.findIndex((a) => a === '-S' || a === '--split-string');
    if (idx >= 0) return argv.slice(idx + 1).join(' ');
  }
  if (name === 'su') {
    const idx = argv.findIndex((a) => a === '-c' || a === '--command');
    if (idx >= 0) return argv[idx + 1] ?? '';
  }
  return null;
}

/** Commands executed by `find -exec/-execdir/-ok/-okdir ... ;|+`. */
function findExecCommands(argv) {
  const out = [];
  for (let i = 1; i < argv.length; i++) {
    if (['-exec', '-execdir', '-ok', '-okdir'].includes(argv[i])) {
      const start = i + 1;
      let end = start;
      while (end < argv.length && argv[end] !== ';' && argv[end] !== '+') end++;
      if (end > start) out.push(argv.slice(start, end));
      i = end;
    }
  }
  return out;
}

/**
 * @typedef {{ argv: string[], depth: number, via: string | null, command: import('./shell.mjs').Command | null }} Segment
 * @typedef {{
 *   source: string, parsed: import('./shell.mjs').ParseResult, segments: Segment[],
 *   features: Set<string>, error: string | null, tooDeep: boolean,
 * }} CommandAnalysis
 */

/**
 * Parses a command line and collects every literal command it would run,
 * following wrappers and nested shell scripts.
 * @param {string} source
 * @returns {CommandAnalysis}
 */
export function analyzeCommandLine(source) {
  const parsed = parseShell(source);
  const features = new Set(parsed.features);
  const segments = [];
  let tooDeep = features.has('too-deep');
  let error = parsed.error;

  const visit = (argv, depth, via, command) => {
    if (depth > MAX_NESTING_DEPTH) {
      tooDeep = true;
      return;
    }
    if (argv.length === 0) return;
    segments.push({ argv, depth, via, command });
    const inner = unwrapCommand(argv);
    if (inner) visit(inner, depth + 1, executableName(argv[0]), null);
    const script = shellScriptOf(argv);
    if (script !== null) {
      const sub = parseShell(script);
      for (const f of sub.features) features.add(f);
      if (sub.error) error = error ?? sub.error;
      for (const c of sub.commands) visit(c.argv, depth + 1, executableName(argv[0]), c);
    }
    if (executableName(argv[0]) === 'find') {
      for (const execArgv of findExecCommands(argv)) visit(execArgv, depth + 1, 'find', null);
    }
    // Scripts fed to an interpreter on stdin through a heredoc.
    if (command && SHELLS.has(executableName(argv[0])) && script === null) {
      for (const doc of command.heredocs) {
        const sub = parseShell(doc.body);
        for (const f of sub.features) features.add(f);
        for (const c of sub.commands) visit(c.argv, depth + 1, executableName(argv[0]), c);
      }
      for (const redirect of command.redirects) {
        if (redirect.op === '<<<') {
          const sub = parseShell(redirect.target);
          for (const c of sub.commands) visit(c.argv, depth + 1, executableName(argv[0]), c);
        }
      }
    }
  };

  for (const command of parsed.commands) visit(command.argv, command.depth, null, command);
  if (tooDeep) features.add('too-deep');
  return { source, parsed, segments, features, error, tooDeep };
}

// ---------------------------------------------------------------------------
// Dangerous commands

/**
 * @typedef {{ kind: string, argv: string[], description: string }} DangerousMatch
 */

/**
 * Returns the first dangerous command in the command line, or null.
 * @param {CommandAnalysis | string} analysisOrSource
 * @returns {DangerousMatch | null}
 */
export function findDangerousCommand(analysisOrSource) {
  const analysis = typeof analysisOrSource === 'string' ? analyzeCommandLine(analysisOrSource) : analysisOrSource;
  if (analysis.tooDeep) {
    return { kind: 'too-deep', argv: [], description: 'deeply nested command wrappers (failing closed)' };
  }
  for (const segment of analysis.segments) {
    const match = dangerousArgv(segment.argv);
    if (match) return match;
  }
  return null;
}

/**
 * @param {string[]} argv
 * @returns {DangerousMatch | null}
 */
export function dangerousArgv(argv) {
  const name = executableName(argv[0]);
  const args = argv.slice(1);
  const hit = (kind, description) => ({ kind, argv, description });
  switch (name) {
    case 'rm':
      if (rmArgsIncludeForce(args)) return hit('forced-rm', 'forced rm (`rm -f`/`rm -rf`)');
      return null;
    case 'git':
      return gitDangerous(argv);
    case 'find':
      if (args.includes('-delete')) return hit('find-delete', '`find -delete`');
      return null;
    case 'shred':
    case 'wipefs':
    case 'mkfs':
    case 'mke2fs':
    case 'fdisk':
    case 'sfdisk':
    case 'parted':
    case 'blkdiscard':
      return hit('disk-destructive', `\`${name}\` can irreversibly destroy data`);
    case 'dd':
      if (args.some((a) => a.startsWith('of='))) return hit('dd-write', '`dd of=...` overwrites its target');
      return null;
    case 'truncate':
      if (args.some((a) => a === '-s' || a.startsWith('--size') || /^-s\S/.test(a))) return hit('truncate', '`truncate` discards file contents');
      return null;
    // Windows (PowerShell / cmd.exe) equivalents.
    case 'Remove-Item':
    case 'remove-item':
    case 'ri':
    case 'rd':
    case 'rmdir':
    case 'del':
    case 'erase':
      if (windowsRemoveIsForced(name, args)) return hit('forced-rm', `forced \`${name}\``);
      return null;
    case 'Format-Volume':
    case 'format':
      return hit('disk-destructive', `\`${name}\` formats a volume`);
    default:
      if (/^mkfs\./.test(name)) return hit('disk-destructive', `\`${name}\` formats a filesystem`);
      return null;
  }
}

function rmArgsIncludeForce(args) {
  for (const arg of args) {
    if (arg === '--') break;
    if (arg === '--force') return true;
    if (arg.startsWith('-') && !arg.startsWith('--') && arg.slice(1).includes('f')) return true;
  }
  return false;
}

function windowsRemoveIsForced(name, args) {
  const lower = args.map((a) => a.toLowerCase());
  if (name.toLowerCase() === 'remove-item' || name === 'ri') {
    return lower.some((a) => a === '-force' || a === '-fo' || a === '-recurse' || a === '-r');
  }
  if (name === 'rd' || name === 'rmdir') return lower.some((a) => a === '/s');
  return lower.some((a) => a === '/f' || a === '/s' || a === '/q');
}

const GIT_GLOBAL_OPTIONS_WITH_VALUE = new Set(['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env', '--exec-path']);

/** Splits `git [global options] <subcommand> [args]`. */
export function gitSubcommand(argv) {
  let i = 1;
  while (i < argv.length) {
    const arg = argv[i];
    if (GIT_GLOBAL_OPTIONS_WITH_VALUE.has(arg)) {
      i += 2;
      continue;
    }
    if (arg.startsWith('-')) {
      i++;
      continue;
    }
    return { subcommand: arg, args: argv.slice(i + 1), globals: argv.slice(1, i) };
  }
  return { subcommand: null, args: [], globals: argv.slice(1) };
}

function hasShortFlag(args, letter) {
  return args.some((a) => a.startsWith('-') && !a.startsWith('--') && a.slice(1).includes(letter));
}

function gitDangerous(argv) {
  const { subcommand, args } = gitSubcommand(argv);
  const hit = (description) => ({ kind: 'git-destructive', argv, description });
  switch (subcommand) {
    case 'reset':
      if (args.some((a) => a === '--hard' || a === '--merge' || a === '--keep')) return hit('`git reset --hard` discards uncommitted work');
      return null;
    case 'clean':
      if (args.includes('--force') || hasShortFlag(args, 'f')) return hit('`git clean -f` deletes untracked files');
      return null;
    case 'checkout':
      if (args.includes('-f') || args.includes('--force') || args.includes('--') || args.includes('.') || args.includes('--ours') || args.includes('--theirs')) {
        return hit('`git checkout` that overwrites working-tree changes');
      }
      return null;
    case 'restore': {
      const staged = args.includes('--staged') || args.includes('-S');
      const worktree = args.includes('--worktree') || args.includes('-W');
      if (!staged || worktree) return hit('`git restore` discards working-tree changes');
      return null;
    }
    case 'switch':
      if (args.includes('--discard-changes') || args.includes('-f') || args.includes('--force')) return hit('`git switch --discard-changes`');
      return null;
    case 'stash':
      if (args[0] === 'drop' || args[0] === 'clear') return hit(`\`git stash ${args[0]}\` deletes stashed work`);
      return null;
    case 'branch':
      if (args.includes('-D') || ((args.includes('-d') || args.includes('--delete')) && (args.includes('-f') || args.includes('--force')))) {
        return hit('`git branch -D` force-deletes a branch');
      }
      return null;
    case 'reflog':
      if (args[0] === 'expire' || args[0] === 'delete') return hit(`\`git reflog ${args[0]}\` destroys recovery points`);
      return null;
    case 'gc':
    case 'prune':
      if (subcommand === 'prune' || args.some((a) => a.startsWith('--prune'))) return hit('git pruning destroys unreachable objects');
      return null;
    case 'update-ref':
      if (args.includes('-d')) return hit('`git update-ref -d` deletes a ref');
      return null;
    case 'filter-branch':
    case 'filter-repo':
      return hit(`\`git ${subcommand}\` rewrites history`);
    case 'worktree':
      if (args[0] === 'remove' && (args.includes('-f') || args.includes('--force'))) return hit('`git worktree remove --force`');
      return null;
    case 'rm':
      if (args.includes('-f') || args.includes('--force')) return hit('`git rm -f` deletes files with local changes');
      return null;
    case 'push':
      if (args.some((a) => a === '--force' || a === '-f' || a === '--mirror' || a === '--delete' || a === '-d' || /^\+/.test(a) || /^:/.test(a))) {
        return hit('`git push` that overwrites or deletes remote refs');
      }
      return null;
    default:
      return null;
  }
}

// ---------------------------------------------------------------------------
// Known-safe (read-only) commands

const SIMPLE_SAFE = new Set([
  'cat', 'cd', 'cut', 'echo', 'expr', 'false', 'grep', 'egrep', 'fgrep', 'head', 'id', 'ls', 'nl', 'paste',
  'pwd', 'rev', 'seq', 'stat', 'tail', 'tr', 'true', 'uname', 'wc', 'which', 'whoami', 'basename', 'dirname',
  'realpath', 'readlink', 'file', 'du', 'df', 'printf', 'test', '[', '[[', 'diff', 'cmp', 'comm', 'md5sum',
  'sha1sum', 'sha256sum', 'sha512sum', 'shasum', 'cksum', 'nproc', 'uptime', 'free', 'ps', 'type',
  'numfmt', 'tac', 'column', 'fold', 'fmt', 'expand', 'unexpand', 'od', 'hexdump', 'strings', 'jq', 'arch',
  'groups', 'tty', 'locale', 'getconf', 'lscpu', 'sleep', 'where', 'Get-ChildItem', 'Get-Content', 'Get-Location',
]);

const VERSION_PROBE_TOOLS = new Set([
  'node', 'npm', 'npx', 'pnpm', 'yarn', 'bun', 'deno', 'python', 'python3', 'pip', 'pip3', 'uv', 'poetry', 'go',
  'cargo', 'rustc', 'rustup', 'java', 'javac', 'gcc', 'g++', 'clang', 'make', 'cmake', 'git', 'docker', 'kubectl',
  'ruby', 'gem', 'php', 'dotnet', 'swift', 'gradle', 'mvn', 'terraform', 'conda', 'gh', 'agy', 'codex', 'tsc',
]);
const VERSION_FLAGS = new Set(['--version', '-V', 'version', '--help', '-h', 'help']);

const UNSAFE_FIND_OPTIONS = new Set(['-exec', '-execdir', '-ok', '-okdir', '-delete', '-fls', '-fprint', '-fprint0', '-fprintf']);

const SAFE_GIT_SUBCOMMANDS = new Set([
  'status', 'log', 'diff', 'show', 'rev-parse', 'ls-files', 'ls-tree', 'cat-file', 'blame', 'describe',
  'shortlog', 'grep', 'merge-base', 'name-rev', 'for-each-ref', 'count-objects', 'show-ref', 'whatchanged',
  'rev-list', 'show-branch', 'var', 'check-ignore', 'annotate',
]);
const UNSAFE_GIT_ARGS = new Set(['--output', '-o', '--ext-diff', '--textconv', '--exec', '--upload-pack', '--open-files-in-pager', '-O']);

/**
 * True when every command in the line is read-only and the line uses no
 * construct that could write files, hide what runs, or name a value the line
 * does not spell out — an environment variable can hold a credential, and the
 * command's output goes straight back to the agent.
 *
 * `variable` is rejected for that last reason: this list is what runs without
 * review when autoagy's own sandbox is not in force, and the hook inherits
 * agy's environment, which normally holds the API keys the user exported.
 * Without the sandbox there is no `--clearenv` to make `echo $KEY` harmless.
 * @param {CommandAnalysis | string} analysisOrSource
 */
export function isKnownSafeCommandLine(analysisOrSource) {
  const analysis = typeof analysisOrSource === 'string' ? analyzeCommandLine(analysisOrSource) : analysisOrSource;
  if (analysis.error || analysis.tooDeep) return false;
  for (const feature of ['substitution', 'process-substitution', 'redirect-write', 'background', 'function', 'heredoc', 'herestring', 'arith', 'variable']) {
    if (analysis.features.has(feature)) return false;
  }
  const topLevel = analysis.parsed.commands;
  if (topLevel.length === 0) return false;
  for (const command of topLevel) {
    if (command.argv.length === 0) {
      // Assignment-only or redirect-only commands.
      if (command.assignments.length > 0) return false;
      continue;
    }
    if (command.words[0]?.dynamic) return false;
    if (command.assignments.length > 0) return false;
    if (!isSafeArgv(command.argv)) return false;
  }
  return true;
}

/** @param {string[]} argv */
export function isSafeArgv(argv) {
  const name = executableName(argv[0]);
  const args = argv.slice(1);
  if (VERSION_PROBE_TOOLS.has(name) && args.length === 1 && VERSION_FLAGS.has(args[0])) return true;
  const script = shellScriptOf(argv);
  if (script !== null && SHELLS.has(name)) return script.trim() !== '' && isKnownSafeCommandLine(script);
  if (name === 'timeout' || name === 'nice' || name === 'time' || name === 'nohup' || name === 'env') {
    // Bare `env` prints the environment, which is the one thing this list must
    // not hand over unreviewed; `env A=1 cmd` is judged by what it runs.
    const inner = unwrapCommand(argv);
    return inner ? isSafeArgv(inner) : false;
  }
  if (SIMPLE_SAFE.has(name)) return true;
  switch (name) {
    case 'uniq':
      return args.filter((a) => !a.startsWith('-')).length <= 1;
    case 'sort':
      return !args.some((a) => a === '-o' || a.startsWith('--output') || a.startsWith('--compress-program') || /^-o./.test(a));
    case 'tree':
      return !args.includes('-o');
    case 'date':
      return !args.some((a) => a === '-s' || a.startsWith('--set'));
    case 'hostname':
      return args.every((a) => a.startsWith('-'));
    case 'xxd':
      return !args.some((a) => a === '-r' || a === '-revert');
    case 'base64':
      return !args.some((a) => a === '-o' || a.startsWith('--output'));
    case 'find':
      return !args.some((a) => UNSAFE_FIND_OPTIONS.has(a));
    case 'rg':
      return !args.some(
        (a) => a === '--search-zip' || a === '-z' || a === '--pre' || a.startsWith('--pre=') || a === '--hostname-bin' || a.startsWith('--hostname-bin='),
      );
    case 'sed':
      return isSafeSed(args);
    case 'git':
      return isSafeGit(argv);
    case 'cargo':
      return args[0] === 'check' || args[0] === 'tree' || args[0] === 'metadata';
    case 'npm':
    case 'pnpm':
    case 'yarn':
      return ['ls', 'list', 'view', 'outdated', 'why', 'config'].includes(args[0]) && (args[0] !== 'config' || ['get', 'list'].includes(args[1]));
    case 'pip':
    case 'pip3':
      return ['list', 'show', 'freeze'].includes(args[0]);
    case 'go':
      return ['env', 'list', 'vet', 'doc'].includes(args[0]);
    default:
      return false;
  }
}

function isSafeSed(args) {
  // Only `sed -n <print-range>p [file]`, mirroring Codex.
  if (args.length < 2 || args.length > 3) return false;
  if (args[0] !== '-n') return false;
  return /^(\d+|\$)(,(\d+|\$))?p$/.test(args[1]);
}

function isSafeGit(argv) {
  const { subcommand, args, globals } = gitSubcommand(argv);
  if (globals.some((g) => g === '-c' || g === '--config-env' || g.startsWith('--exec-path') || g === '-p' || g === '--paginate')) return false;
  if (!subcommand) return globals.includes('--version');
  if (args.some((a) => UNSAFE_GIT_ARGS.has(a) || a.startsWith('--output=') || a.startsWith('--ext-diff') || a.startsWith('--upload-pack'))) {
    return false;
  }
  if (SAFE_GIT_SUBCOMMANDS.has(subcommand)) return true;
  switch (subcommand) {
    case 'branch': {
      const listing = new Set(['-a', '--all', '-r', '--remotes', '-v', '-vv', '--verbose', '--list', '-l', '--show-current', '--merged', '--no-merged', '--contains', '--no-contains', '--sort', '--format', '--column', '--no-column', '--color', '--no-color', '--points-at']);
      return args.every((a) => listing.has(a) || a.startsWith('--sort=') || a.startsWith('--format=') || a.startsWith('--color=') || a.startsWith('--contains=') || a.startsWith('--merged=')) && !args.some((a) => !a.startsWith('-'));
    }
    case 'tag':
      return args.length === 0 || args.every((a) => a === '-l' || a === '--list' || a.startsWith('--sort') || a.startsWith('--contains') || a === '-n');
    case 'remote':
      return args.length === 0 || (args.length === 1 && (args[0] === '-v' || args[0] === '--verbose')) || args[0] === 'get-url' || args[0] === 'show';
    case 'stash':
      return args[0] === 'list' || args[0] === 'show';
    case 'worktree':
      return args[0] === 'list';
    case 'config':
      return args.length > 0 && args.every((a) => a.startsWith('--get') || a === '--list' || a === '-l' || a === '--show-origin' || a === '--global' || a === '--local' || a === '--system' || !a.startsWith('-')) && args.some((a) => a.startsWith('--get') || a === '--list' || a === '-l');
    case 'reflog':
      return args.length === 0 || args[0] === 'show' || args[0].startsWith('-');
    case 'submodule':
      return args[0] === 'status';
    default:
      return false;
  }
}

/** True when any top-level command writes to a file through a redirection. */
export function writesThroughRedirect(analysis) {
  return analysis.parsed.commands.some((c) => c.redirects.some(isFileWriteRedirect));
}
