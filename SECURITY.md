# Security policy

autoagy is not a library that fails on its own: it asks Antigravity for standing
permissions (a command grant, `mcp(*)`, `execute_url(*)`, `read_file(/)` and,
where its own sandbox runs, `read_url(*)`) and then sits in front of
every tool call as the only gate. A bypass therefore does not mean a wrong
answer — it means something ran on your machine with no review, which is the
exact thing the plugin exists to prevent. Its own documentation records nineteen
rounds of bypasses that were found and closed.

## Reporting a vulnerability

**Please do not open a public issue with the details or a proof of concept.**
A public report is a working exploit against everyone who has already installed
the plugin.

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability**
on this repository. If that form is not available, open an issue that says only
that you have a security report and how to reach you — no details, no PoC.

中文：发现绕过请不要直接开 issue。用仓库的 Security → Report a vulnerability 私下报告；用不了就开一个 issue，只说你有一个安全问题以及联系方式，不要写细节或 PoC。

## What a useful report contains

- `agy --version`, your platform, and whether autoagy's own sandbox is active
  (`autoagy status` prints it, along with the self-check result).
- The relevant configuration: `mode`, `commandGrant`, `ownSandbox`,
  `sandbox`, `networkGrants`, and any `rules` / `mcp.allow` / `protectedPaths`
  entries you set.
- The exact tool call that gets through, and what you expected. One call can be
  reproduced without starting an agent:

  ```
  autoagy review --tool run_command --args '{"CommandLine":"…","BypassSandbox":true}'
  ```

- Whether the action reached the host, the network, a credential store, or the
  conversation log — that is, which layer the report claims failed (the sandbox,
  the reviewer, the sentinel, the pinning, or the state under `~/.gemini/autoagy`).
- Whether the README's 已知限制 / Known limitations section already describes it.
  A report that one of those exists is welcome, but it will usually be closed as
  documented — **unless** you can show the documented claim is wrong, which is a
  real finding and has happened before.

## What is out of scope

- Anything that requires the user to run with settings the documentation warns
  about, unless the warning itself is wrong.
- The limitations the README already states as accepted, including: edits and
  reads are executed by agy outside every sandbox; the reviewer has no tools;
  `mcp(*)` and `execute_url(*)` have no narrower form; a protected directory name
  that is itself a symlink can be replaced; and on macOS no bundle-level sandbox
  is used at all.
- Reports about Antigravity, `agy`, or Codex itself. Report those upstream.

## What to expect

This is a single-maintainer project, so: an initial reply within about a week,
best effort after that. Fixes come with a regression test that fails against the
old code — that is the house rule. You will be credited in the release notes
unless you would rather not be. Please give a fix a chance to ship before
publishing; if nothing has shipped in 90 days, publish.

## Not affiliated

This is an unofficial plugin. It is not made by, endorsed by, or supported by
Google (Antigravity) or OpenAI (Codex). Report problems with those products to
their own trackers.
