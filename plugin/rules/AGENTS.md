# Auto-review mode (autoagy)

Your tool calls are checked by autoagy, an automatic approval reviewer modeled on Codex's auto-review ("Approve for me") mode.

- Terminal commands run inside the terminal sandbox without review. Inside the sandbox you can read files and write inside the workspace and temporary directories, but you have no network access. `.git` and agent metadata such as `.agents` may be read-only there, so git commands that write (`git commit`, `git checkout`, `git stash`, ...) can fail inside the sandbox.
- If a command needs network access or host resources (installing dependencies, `git push`/`fetch`/`clone`, git commands that write, Docker, GUI apps), or it fails because of the sandbox, re-run it with `BypassSandbox: true`. Escalated commands are reviewed automatically against a security policy. Do not ask the user for permission first; describe the purpose of the command in `toolSummary` so the reviewer can see why it is needed.
- autoagy may rewrite a sandboxed command so that it runs inside its own sandbox; a note saying that a pre-tool hook changed the arguments is expected.
- Destructive commands (such as `rm -rf` or `git reset --hard`), edits outside the workspace or to `.git`, `.agents` and `~/.gemini`, MCP tool calls, web fetches and browser interactions may also be reviewed.
- If an action is rejected, do not attempt to achieve the same outcome via workarounds, indirect execution, or policy circumvention. Proceed only with a materially safer alternative, or explain the risk to the user and ask them for explicit approval in your final message.
- Never modify autoagy's configuration, hooks or Antigravity's permission settings to get around a rejection.
