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

---

## How it maps to Codex

| Codex "Approve for me" | autoagy |
| --- | --- |
| Commands inside the workspace-write sandbox just run | On Linux they run inside autoagy's own bubblewrap sandbox; elsewhere in Antigravity's terminal sandbox |
| `sandbox_permissions: require_escalated` goes to review | `BypassSandbox: true` goes to review |
| Forced review for `rm` (including `sudo`/`env`/`bash -c` nesting) | The same, plus destructive git commands (Antigravity has no `apply_patch`, so git is how history gets rewritten) |
| `apply_patch` runs when it only writes writable roots; `.git`/`.agents`/`.codex` stay read-only | The same for the edit tools; those directories are read-only in the sandbox too |
| MCP calls without a read-only annotation go to review | All of them go to review by default (stricter than Codex); `mcp.allow` or the annotation cache opens that up |
| execpolicy `prefix_rule` allow/prompt/forbidden | The `rules` setting, same semantics |
| guardian: policy prompt + trimmed transcript + planned action JSON | The same (the policy text is adapted from Codex, with the Antigravity-specific parts rewritten) |
| Output `{risk_level, user_authorization, outcome, rationale}` | The same |
| 90-second deadline, up to 3 attempts, errors deny (fail closed) | 90 seconds is the budget for **one attempt**, inside a 140-second deadline for the whole review (a stalled attempt is killed and asked again); errors deny the same way |
| The instructions handed to the agent on a refusal or timeout | Copied verbatim |
| 3 refusals in a row, or 10 in the last 50, end the turn | The same (a PostInvocation hook ends it) |
| The "Auto-review Denials" panel lets one through by hand | `autoagy denials` + `autoagy approve <id>` |

## Read this before installing

**It asks Antigravity for standing permissions, and they outlive the plugin.**
`setup` adds a command grant (on Linux one that names a single token-redeeming
program, elsewhere `command(*)`), `mcp(*)`, `execute_url(*)`, `read_file(/)` and —
where its own sandbox runs — `read_url(*)`. A hook's `allow` cannot override
Antigravity's own permission prompts, so without these, everything the reviewer
approves would still pop up at you. They do not disappear when the plugin stops
loading.

**So a sentinel watches them.** `setup` registers a small program in
`~/.gemini/config/hooks.json` under the key `autoagy-tripwire` — a file
`agy plugin` does not manage, so it keeps running when the plugin is disabled,
replaced or never installed properly. When it finds the plugin gone it **refuses
every tool call**, which is deliberate: agy doing nothing beats those grants
applying with nobody reviewing.

**The way out, when agy refuses everything:** run `autoagy status`, then reinstall
(`node scripts/install.mjs`) or uninstall (`node scripts/install.mjs --uninstall`).
If you cannot run commands at all, delete the `autoagy-tripwire` key from
`~/.gemini/config/hooks.json` — **the other keys there are someone else's** — and
then uninstall or reinstall, since the grants are unguarded until you do.

**Two cases are still fail-open:** someone deletes the sentinel by hand while the
grants remain, and Antigravity IDE / 2.0, where you add the grants in the settings
UI, `setup` writes nothing and no sentinel is registered (whether the IDE loads
`~/.gemini/config/hooks.json` at all has not been measured). If the pinned node
interpreter disappears, hooks fail to start and tool calls fail — fail-closed, not
silent.

The command class can be narrowed to fail-closed (`commandGrant: "executor"`, the
Linux default); `mcp(*)` and `execute_url(*)` have no narrower form and rest on the
sentinel alone. **This is a different shape from Codex**, which needs no host
permissions widened at all: turning auto mode off there returns to something
stricter, while autoagy has to widen first, which is why something has to watch
whether the plugin is still there.

## Install, uninstall, upgrade

Requirements: Node.js ≥ 20, Antigravity CLI (`agy`) ≥ 1.2 (measured on 1.2.5–1.2.7,
and agy updates itself). On Linux, install
`bubblewrap` for the own sandbox (`sudo apt install bubblewrap`).

```bash
git clone https://github.com/JXMss/autoagy autoagy && cd autoagy
node scripts/install.mjs --dry-run     # prints exactly what it would change
node scripts/install.mjs
alias autoagy="node ~/.gemini/config/plugins/autoagy/bin/autoagy.mjs"
```

Then use `agy` as usual. Uninstalling is the same script:

```bash
node scripts/install.mjs --uninstall             # revert the settings, remove the plugin and the sentinel
node scripts/install.mjs --uninstall --purge     # and delete ~/.gemini/autoagy (config, state, logs)
node scripts/install.mjs --uninstall --dry-run   # print what it would revert, change nothing
```

It takes the grants out first and removes nothing else unless they came out: when
they cannot (usually `settings.json` is no longer valid JSON) it stops with exit 1
and leaves the plugin, the sentinel and the setup record in place, since each of
them is what stands behind those grants. Repair the file and run it again. If you
cannot run anything at all, delete the `autoagy-tripwire` key from
`~/.gemini/config/hooks.json` and then uninstall or reinstall.

**Upgrading** is `git pull` followed by `node scripts/install.mjs` again. agy has
no plugin update command (`agy plugin` does install, uninstall, enable, disable,
validate), so no agy plugin updates itself and autoagy is no exception. Do not
upgrade with `agy plugin install ./plugin` directly: that overwrites the installed
`hooks.json` with the plugin's own, whose node interpreter is not pinned —
`autoagy status` warns when it finds that.

**What it writes** (all of it reverted by `--uninstall`):

1. `~/.gemini/config/plugins/autoagy` — the plugin, via `agy plugin install`.
2. `~/.gemini/antigravity-cli/settings.json` (backed up first to
   `<that file>.autoagy-backup-<timestamp>`) — the grants above,
   `write_file(<dir>)` per `writableRoots` entry, `enableTerminalSandbox: true`,
   `toolPermission: "proceed-in-sandbox"`, and `allowNonWorkspaceAccess: false`,
   the one check that happens at the moment agy writes.
3. `~/.gemini/config/hooks.json` — the sentinel registration, merged in. Your own
   hooks are left alone; if that file is not valid JSON, `setup` writes **nothing
   at all**, grants included, and says so.
4. `~/.gemini/autoagy/` — `config.json`, `state/`, `logs/`, `bin/tripwire.mjs`, and
   `bin/exec-confined.mjs` with `commandGrant: "executor"`.
5. The plugin's own `hooks.json` — the node interpreter is pinned to an absolute
   path, so a broken `PATH` cannot silently stop every hook.

Each item, with what was measured behind it, is in the reference manual:
[安装到底改了你机器上的什么](docs/reference.md#安装到底改了你机器上的什么) (Chinese, like
the design notes).

## Platform support

| Platform | Own sandbox | What you get |
| --- | --- | --- |
| **Linux + bubblewrap** | yes | First-class. Commands run in autoagy's own bwrap sandbox: workspace and temp writable, `.git` and agent metadata read-only, credential stores masked, **no network**, environment rebuilt from an allowlist, `AF_UNIX`-only sockets. |
| **Linux without bubblewrap, macOS** | no | Commands stay in Antigravity's terminal sandbox. In it, `.git` and the conversation log are **writable**, so a command can plant a git hook or edit the transcript the reviewer reads. The reviewer is told it cannot trust that transcript's user messages. |
| **Windows** | no | Also no way to scrub the environment (`env -i` is unavailable), agy's sandbox state cannot be inferred from settings, and prompts cannot reach you — so nearly every command is reviewed, and prompts become denials. Workable, but heavy. |
| **IDE / Antigravity 2.0** | your call | Add the three grants by hand and keep the terminal sandbox on, then set `"sandbox": "on"` in the config. That is a declaration, not a measurement. |

macOS is the largest gap: Codex solves the same problem with its seatbelt
sandbox, and autoagy has no equivalent there.

## Day-to-day commands

| Command | What it is for |
| --- | --- |
| `autoagy status` | Mode, reviewer backend, whether the settings and grants are in place, whether the sentinel and the own sandbox are active, and when a hook last ran. This is the one to read when something feels wrong. |
| `autoagy log [-n 20]` | Recent decisions: what was reviewed, the verdict, the risk, how long it took. |
| `autoagy stats [--days 7]` | The same, counted: verdicts, review outcomes, review latency p50/p90/max, risk distribution. |
| `autoagy denials` / `autoagy approve <id>` | What was refused, and letting one retry through once (the reviewer sees your approval; critical risks still refuse). |
| `autoagy trust [<session>] [--all]` | Clears the sticky per-session marks and releases retained mount points. It refuses while a command may still be running; `--force` overrides. |
| `autoagy mode auto\|ask\|off` | `auto` = the reviewer decides; `ask` = risky actions prompt you (Codex's "Ask for approval"); `off` = no review, and the actions those grants cover prompt you instead. |
| `autoagy review --tool run_command --args '{...}'` | Asks what a single call would be judged as, without starting an agent. |
| `autoagy setup` / `teardown` | Apply or revert the machine changes on their own. |

When the reviewer refuses, the agent receives Codex's original instruction: do not
work around it, either propose something genuinely safer or explain the risk and
ask you. If you then say "yes, I confirm", the next review counts your explicit
approval.

## Configuration worth knowing

`~/.gemini/autoagy/config.json` — the full table is in the
[full configuration table](docs/reference.md#配置全表). The ones that change
what you experience:

| Field | Default | Why you would touch it |
| --- | --- | --- |
| `mode` | `"auto"` | `ask` to go back to prompts, `off` to pause everything. |
| `commandGrant` | `"auto"` | `"auto"` is `"executor"` on Linux (measured on a real install: commands, deletes and `git commit` ran without a prompt) and `"wildcard"` elsewhere — the executor cannot run as a program on Windows, and nobody has tried it on macOS yet. `"executor"` replaces `command(*)` with a grant naming one program that only redeems one-shot tokens the hook wrote — the command class then becomes fail-closed instead of fail-open. |
| `ownSandbox` | `"auto"` | Whether autoagy's bubblewrap sandbox is used where it could be. |
| `readGrant` | `"anywhere"` | `"none"` leaves out `read_file(/)`, so reads outside the workspace prompt again. When autoagy itself fails or times out, content reads are refused while the grant is on, since agy would no longer ask. |
| `networkGrants` | `"auto"` | `"auto"` is `"all"` where autoagy's own sandbox can run when `setup` runs (Linux, bubblewrap starts, `ownSandbox` not `"off"`), `"none"` elsewhere. `"trusted-domains"` stops the first fetch of each trusted domain from prompting. Cost depends on which sandbox is running; `autoagy status` says which. `"all"` grants `read_url(*)`: no fetch prompts at all, each fetch outside `trustedDomains` still reviewed. That grant also gives agy's terminal sandbox the whole network, so autoagy stops counting it as a sandbox — free where autoagy's own sandbox runs the commands (Linux + bubblewrap), and elsewhere every command off the known read-only list is reviewed. |

Also: `writableRoots` (outside directories editable without review — re-run
`autoagy setup` after changing it), `protectedPaths` (its defaults are the home
files that run themselves outside every sandbox — shell rc files,
`~/.config/systemd/user/**`, `~/.config/autostart/**`, `~/.local/bin/**`,
`~/.gitconfig` — which only matters when the workspace *is* the home directory),
`credentialPaths`,
`mcp.allow`, `rules` (Codex-style prefix rules), `webSearch`, `browser`, and the
reviewer backend (next section).

## Reviewer backend

By default (`backend: "agy"`) the plugin's tool-less `autoagy-guardian` agent runs
headless under your own Antigravity login — no extra API key. It uses your agy's
current default model at reasoning effort `low`. A review takes 4–12 seconds and
each one spends your Antigravity quota — the same account the main agent uses, so
reviews slow down while it is busy. Measured over two days of ordinary use: a
median of 4.3s on one day, 9.1s on the next with 13 reviews between 60s and 80s
(the same machine idle measured 2–5s again, and 5s with all six cores pegged, so
it is the backend and not the machine). `reviewer.timeoutSec` (140) is the
deadline for the whole review, `attemptTimeoutSec` (90, Codex's number) the
budget for one attempt: a stalled attempt is killed and asked again, and only the
whole deadline running out counts as a timeout. Review sessions show up in `agy`'s
history under the `~/.gemini/autoagy/guardian` workspace, so they do not hijack
`agy -c` in your projects.

To change the model or the effort:

```json
{ "reviewer": { "agy": { "model": "gemini-3.8-flash-low", "effort": "low" } } }
```

`model` takes a name from the first column of `agy models` (the one above is only
an example); a wrong name makes every review fail, which counts as a refusal.
`effort` is `low`, `medium` or `high`.

Or use any **OpenAI-compatible** Chat Completions endpoint (faster, paid per use),
for example Gemini:

```json
{
  "reviewer": {
    "backend": "openai",
    "openai": {
      "baseUrl": "https://generativelanguage.googleapis.com/v1beta/openai",
      "apiKeyEnv": "GEMINI_API_KEY",
      "model": "gemini-flash-latest"
    }
  }
}
```

**The key is read from an environment variable** (the config file only names it),
from the environment agy itself was started in — so export it in the terminal you
start `agy` from and restart agy. A missing key, an unreachable endpoint or a wrong
model name makes every review fail, which counts as a refusal; three in a row end
the turn. Local Ollama, gateways needing extra headers, endpoints without
`response_format` support: see
[审核后端 OpenAI 兼容接口](docs/reference.md#审核后端-openai-兼容接口).

A config change applies from the next tool call. To try it without starting an
agent, review a single command:

```bash
autoagy review --tool run_command --args '{"CommandLine":"git push","BypassSandbox":true}'
```

## Rules and session trust

Layer one is deterministic and model-free: what runs untouched, what must be
reviewed, what is refused outright — plus a fence that stops waving through a
path whose target drifted earlier in the session. Both in full:
[决策规则](docs/reference.md#决策规则), [会话信任](docs/reference.md#会话信任).

## What it does not protect against

These are the boundaries the design has, not a to-do list. The full list of 19 is
in the reference manual
([已知限制完整清单](docs/reference.md#已知限制完整清单)); what is not finished, and
meant to be fixed, is in [docs/open-issues.md](docs/open-issues.md). The
reasoning behind each limit is in the [design record](docs/design.md):

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
your own Antigravity login and **nothing is sent to any third party**. It is a
real Antigravity session, though, so **each review spends your quota** — at
4–12 seconds a review, a day of heavy reviewing is not free. An OpenAI-compatible
backend trades that for API cost and for sending the material described below.

With an OpenAI-compatible backend, each review POSTs: the policy text, a
budget-trimmed transcript (length caps only — **no redaction**, so anything
sensitive in your transcript goes as-is), the pending action's JSON, the paths of
files edited recently in the session, local environment facts (platform,
workspace roots, sandbox state), and the API key. Details in the
[隐私与数据流向](docs/reference.md#隐私与数据流向).

## Development

```bash
npm test                 # unit and integration tests; the mock reviewer needs
                         # `reviewer.backend: "mock"` in the config file AND
                         # AUTOAGY_UNSAFE_MOCK_REVIEWER=1 in the environment
npm run validate         # agy plugin validate plugin (needs the agy CLI)
```

The suite runs with **zero skips** on Linux with bubblewrap installed, when no
real autoagy install exists — that is CI's case, and CI enforces the zero, because
a skipped sandbox test means the sandbox was never started while the run still
looks green. On a machine that does have one, `status.test.mjs` skips a single
test rather than writing over it.

## License

Apache-2.0. It contains material adapted from OpenAI Codex, also Apache-2.0 —
see [NOTICE](NOTICE).