# autoagy — Codex-style auto mode for Antigravity

[中文完整版 README.md](README.md) ｜ [设计依据与实测记录 docs/design.md](docs/design.md)

autoagy is a [Google Antigravity](https://antigravity.google) plugin that
implements Codex's **"Approve for me"** (auto-review) mode:

- safe actions — reading files, editing inside the workspace, commands in the
  terminal sandbox — **just run**, without interrupting you;
- risky ones — asking to leave the sandbox, editing outside the workspace,
  `rm -rf`, `git reset --hard`, MCP calls, network fetches, browser clicks — go to
  a **reviewer model** instead of a permission prompt;
- the reviewer applies Codex's safety policy, and when it refuses it tells the
  agent why, so the agent proposes something safer or comes back to you.

It is a per-item port of Codex v0.154.0 (`codex-rs/core/src/guardian`), adapted
against measurements of Antigravity's hook, permission and sandbox behaviour.
Every design decision in the full documentation carries the experiment behind it.

> **Status: experimental, and this is an unofficial plugin.** It is not made by,
> endorsed by, or supported by Google (Antigravity) or OpenAI (Codex). The
> behaviours it depends on were measured on agy 1.2.5–1.2.7 and agy updates
> itself, so treat it as something you are trying out rather than infrastructure.

---

## Read this before installing

**It asks Antigravity for standing permissions, and they outlive the plugin.**
`autoagy setup` adds `command(*)`, `mcp(*)` and `execute_url(*)` to
`~/.gemini/antigravity-cli/settings.json`, because a hook's `allow` cannot
override Antigravity's own permission prompts — without them, everything the
reviewer approves would still pop up at you. Those three grants do not disappear
when the plugin stops loading.

**So a sentinel watches them.** `setup` also registers a small program in
`~/.gemini/config/hooks.json` under the key `autoagy-tripwire` — a file
`agy plugin` does not manage, so it keeps running when the plugin is disabled,
replaced, or never installed properly. When it finds the plugin gone, it
**refuses every tool call**. agy will then be unable to do anything until you
deal with it. That is deliberate: the alternative is those three grants applying
with nobody reviewing, which is strictly worse than not having installed autoagy.

**The way out, when agy refuses everything:**

- Run `autoagy status`, then reinstall (`node scripts/install.mjs`) or remove it
  (`node scripts/install.mjs --uninstall`).
- If you cannot run commands at all: delete the `autoagy-tripwire` key from
  `~/.gemini/config/hooks.json`. **Leave the other keys alone — they are someone
  else's hooks.** Removing the sentinel puts the grants back to unguarded, so
  reinstall or uninstall right after.

**Do not pause autoagy with `agy plugin disable autoagy`** — the grants stay and
the sentinel will refuse everything. Use `autoagy mode off`, or uninstall.

**Two cases are still fail-open**, and you should know which:

- someone deletes the sentinel by hand while the grants remain;
- **Antigravity IDE / Antigravity 2.0**, where the grants are added by hand in
  the settings UI, `setup` does not write them, and no sentinel is registered for
  them (whether the IDE even loads `~/.gemini/config/hooks.json` has not been
  measured).

If the pinned node interpreter disappears, hook processes fail to start and tool
calls fail — fail-closed, not silent.

## Platform support

| Platform | Own sandbox | What you get |
| --- | --- | --- |
| **Linux + bubblewrap** | yes | First-class. Commands run in autoagy's own bwrap sandbox: workspace and temp writable, `.git` and agent metadata read-only, credential stores masked, **no network**, environment rebuilt from an allowlist, `AF_UNIX`-only sockets. |
| **Linux without bubblewrap, macOS** | no | Commands stay in Antigravity's terminal sandbox. In it, `.git` and the conversation log are **writable**, so a command can plant a git hook or edit the transcript the reviewer reads. The reviewer is told it cannot trust that transcript's user messages. |
| **Windows** | no | Also no way to scrub the environment (`env -i` is unavailable), agy's sandbox state cannot be inferred from settings, and prompts cannot reach you — so nearly every command is reviewed, and prompts become denials. Workable, but heavy. |
| **IDE / Antigravity 2.0** | your call | Add the three grants by hand and keep the terminal sandbox on, then set `"sandbox": "on"` in the config. That is a declaration, not a measurement. |

macOS is the largest gap: Codex solves the same problem with its seatbelt
sandbox, and autoagy has no equivalent there.

## What it changes on your machine

Everything below is written by `autoagy setup` (run by `scripts/install.mjs`)
and reverted by `teardown` / `--uninstall`.

1. **`~/.gemini/config/plugins/autoagy`** — the plugin itself, via `agy plugin install`.
2. **`~/.gemini/antigravity-cli/settings.json`** — backed up first to
   `<that file>.autoagy-backup-<timestamp>`, then:
   - `permissions.allow` gains `command(*)`, `mcp(*)`, `execute_url(*)`;
   - plus `write_file(<dir>)` for each directory in `writableRoots`, and
     `read_url(<domain>)` for each trusted domain when `networkGrants:
     "trusted-domains"` (off by default);
   - `enableTerminalSandbox: true`, `toolPermission: "proceed-in-sandbox"`;
   - `allowNonWorkspaceAccess: false` — the one check that happens at the moment
     agy writes, which is what caps an edit whose path was swapped after autoagy
     checked it.
3. **`~/.gemini/config/hooks.json`** — the sentinel registration, merged in. Your
   own hooks in that file are left alone; if the file is not valid JSON, `setup`
   writes **nothing at all** (no grants either) and tells you to fix it.
4. **`~/.gemini/autoagy/`** — `config.json`, `state/` (trust flags, tokens, locks),
   `logs/` (decisions; full review prompts only if you turn that on), and
   `bin/tripwire.mjs`. With `commandGrant: "executor"` also `bin/exec-confined.mjs`.
5. **The plugin's own `hooks.json`** — the node interpreter is pinned to an
   absolute path, so a broken `PATH` cannot silently stop every hook.

Undo: `node scripts/install.mjs --uninstall` (add `--purge` to delete
`~/.gemini/autoagy` too). If reverting the grants fails — usually because
`settings.json` is no longer valid JSON — teardown **stops** with exit 1 and
keeps the plugin, the sentinel and the setup record, including under `--purge`,
so the grants never become unrevertable. Repair the file and run it again.

## Install

Requirements: Node.js ≥ 20, Antigravity CLI (`agy`) ≥ 1.2. On Linux, install
`bubblewrap` for the own sandbox (`sudo apt install bubblewrap`).

```bash
git clone https://github.com/OWNER/autoagy autoagy && cd autoagy
node scripts/install.mjs --dry-run     # prints exactly what it would change
node scripts/install.mjs
alias autoagy="node ~/.gemini/config/plugins/autoagy/bin/autoagy.mjs"
```

Then use `agy` as usual.

```bash
node scripts/install.mjs --uninstall   # revert the settings and remove the plugin
```

## Day-to-day commands

| Command | What it is for |
| --- | --- |
| `autoagy status` | Mode, reviewer backend, whether the settings and grants are in place, whether the sentinel and the own sandbox are active, and when a hook last ran. This is the one to read when something feels wrong. |
| `autoagy log [-n 20]` | Recent decisions: what was reviewed, the verdict, the risk, how long it took. |
| `autoagy stats [--days 7]` | The same, counted: verdicts, review outcomes, review latency p50/p90/max, risk distribution. |
| `autoagy denials` / `autoagy approve <id>` | What was refused, and letting one retry through once (the reviewer sees your approval; critical risks still refuse). |
| `autoagy trust [<session>] [--all]` | Clears the sticky per-session marks and releases retained mount points. It refuses while a command may still be running; `--force` overrides. |
| `autoagy mode auto\|ask\|off` | `auto` = the reviewer decides; `ask` = risky actions prompt you (Codex's "Ask for approval"); `off` = no review, and the actions those three grants cover prompt you instead. |
| `autoagy review --tool run_command --args '{...}'` | Asks what a single call would be judged as, without starting an agent. |
| `autoagy setup` / `teardown` | Apply or revert the machine changes on their own. |

When the reviewer refuses, the agent receives Codex's original instruction: do not
work around it, either propose something genuinely safer or explain the risk and
ask you. If you then say "yes, I confirm", the next review counts your explicit
approval.

## Configuration worth knowing

`~/.gemini/autoagy/config.json` — the full table is in the
[configuration table in the Chinese README](README.md#配置geminiautoagyconfigjson). The four that change
what you experience:

| Field | Default | Why you would touch it |
| --- | --- | --- |
| `mode` | `"auto"` | `ask` to go back to prompts, `off` to pause everything. |
| `commandGrant` | `"wildcard"` | `"executor"` replaces `command(*)` with a grant naming one program that only redeems one-shot tokens the hook wrote — the command class then becomes fail-closed instead of fail-open. |
| `ownSandbox` | `"auto"` | Whether autoagy's bubblewrap sandbox is used where it could be. |
| `networkGrants` | `"none"` | `"trusted-domains"` stops the first fetch of each trusted domain from prompting. Cost depends on which sandbox is running; `autoagy status` says which. |

Also: `writableRoots` (outside directories editable without review — re-run
`autoagy setup` after changing it), `protectedPaths`, `credentialPaths`,
`mcp.allow`, `rules` (Codex-style prefix rules), `webSearch`, `browser`, and the
reviewer backend (`agy` by default; any OpenAI-compatible endpoint otherwise).

## What it does not protect against

These are documented, accepted limits — the full reasoning is in the
[design record](docs/design.md):

- **Edits and reads are executed by agy, outside every sandbox.** autoagy resolves
  the path before handing it over and re-checks afterwards, so a path whose
  symlink is re-pointed is detected and the session is marked untrusted — but a
  *real directory* swapped for a symlink between the check and the write cannot be
  prevented, only noticed. Codex applies patches inside its sandbox; this cannot
  until Antigravity does the same.
- **The reviewer has no tools.** Codex's guardian can look around; autoagy
  pre-collects facts for delete commands instead.
- **`mcp(*)` and `execute_url(*)` have no narrower form** — only the sentinel
  stands behind them.
- **A protected directory name that is itself a symlink can be replaced** by a
  command inside the sandbox.
- **Searching inside the workspace reads `.env` without review** (`grep -r`), and
  `search_web` is an outbound channel by default. Both match Codex's trade-off;
  the switches are `protectedPaths` and `webSearch: "review"`.
- **The reviewer cannot reuse a verdict.** The same action is reviewed again each
  time it is attempted: 4–12 seconds per review with the default backend.

## Privacy

With the default reviewer (`backend: "agy"`) a headless agent runs locally under
your own Antigravity login and **nothing is sent to any third party**.

With an OpenAI-compatible backend, each review POSTs: the policy text, a
budget-trimmed transcript (length caps only — **no redaction**, so anything
sensitive in your transcript goes as-is), the pending action's JSON, the paths of
files edited recently in the session, local environment facts (platform,
workspace roots, sandbox state), and the API key. Details in the
[Chinese README](README.md#隐私与数据流向).

## Development

```bash
npm test                 # unit and integration tests; the mock reviewer is
                         # selected from the config file, never from the environment
npm run validate         # agy plugin validate plugin (needs the agy CLI)
```

The suite is expected to run with **zero skips** on Linux with bubblewrap
installed; CI enforces that, because a skipped sandbox test means the sandbox was
never started while the run still looks green.

## License

Apache-2.0. It contains material adapted from OpenAI Codex, also Apache-2.0 —
see [NOTICE](NOTICE).
