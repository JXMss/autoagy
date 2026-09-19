# autoagy — 给 Antigravity 的 Codex 式 Auto 模式

autoagy 是一个 [Google Antigravity](https://antigravity.google) 插件，按 OpenAI Codex 的 **“Approve for me”（auto-review）** 模式实现了 Antigravity 的 auto 模式：

- 安全的操作（读文件、改工作区内的文件、在终端沙箱里跑命令……）**直接执行**，不打断你；
- 有风险的操作（请求绕过沙箱、改工作区外的文件、`rm -rf`、`git reset --hard`、MCP 调用、联网、浏览器点击……）**交给一个审核模型（guardian）裁决**，而不是弹窗问你；
- 审核模型按 Codex 的安全策略判断风险与用户授权，拒绝时把理由告诉 agent，让它换更安全的做法或回来问你。

它基于对 Codex v0.154.0 源码（`codex-rs/core/src/guardian`）的逐项移植，并针对 Antigravity 的 hook、权限和沙箱机制做了实测适配（见 [docs/design.md](docs/design.md)）。

## 与 Codex 的对应关系

| Codex “Approve for me” | autoagy |
| --- | --- |
| workspace-write 沙箱内的命令直接运行 | Linux 上在 autoagy 自己的 bubblewrap 沙箱里直接运行（规则同 workspace-write，见下文）；否则在 Antigravity 终端沙箱里运行 |
| `sandbox_permissions: require_escalated` 走审核 | `BypassSandbox: true` 走审核 |
| 强制 `rm`（含 `sudo`/`env`/`bash -c` 嵌套）走审核 | 同左，另加破坏性 git 命令（Antigravity 沙箱不保护 `.git`） |
| `apply_patch` 只写可写根目录则放行，`.git/.agents/.codex` 只读 | 编辑工具同理；`.git/.agents/.gemini`、`~/.gemini` 等需审核。autoagy 自己的沙箱里 shell 命令对这些目录同样只读 |
| MCP 调用（非只读注解）走审核 | `call_mcp_tool` / `mcp_*` 走审核，可用 `mcp.allow` 白名单 |
| execpolicy `prefix_rule` allow/prompt/forbidden | `rules` 配置，语义相同 |
| guardian：策略 prompt + 精简 transcript + planned action JSON | 同左（策略文本改编自 Codex，transcript 预算与选取规则相同） |
| 输出 `{risk_level, user_authorization, outcome, rationale}` | 同左 |
| 90 秒期限、最多 3 次尝试、出错即拒绝（fail closed） | 同左 |
| 拒绝/超时时给 agent 的指令 | 原文照搬 |
| 同一轮连续 3 次或最近 50 次中 10 次被拒 → 中断本轮 | 同左（PostInvocation hook 终止循环） |
| “Auto-review Denials” 面板手动放行一次 | `autoagy denials` + `autoagy approve <id>`，或直接在对话里明确同意 |

## 安装

要求：Node.js ≥ 20，Antigravity CLI（`agy`）≥ 1.2。

```bash
git clone <this repo> autoagy && cd autoagy
node scripts/install.mjs            # 先看会改什么：node scripts/install.mjs --dry-run
```

安装脚本会：

1. `agy plugin install ./plugin`，插件装到 `~/.gemini/config/plugins/autoagy`；
2. 在插件的 `hooks.json` 里把 `node` 固定为当前 Node 的绝对路径（避免 Antigravity 找不到 node 导致所有工具调用失败）；
3. 创建 `~/.gemini/autoagy/config.json`；
4. 修改 `~/.gemini/antigravity-cli/settings.json`（先备份）：
   - `permissions.allow` 加入 `command(*)`、`mcp(*)`、`execute_url(*)`——否则被 autoagy 批准的操作仍会被 Antigravity 自己再弹窗；
   - 确保 `enableTerminalSandbox: true`、`toolPermission: "proceed-in-sandbox"`、`allowNonWorkspaceAccess: true`。

**故意不授予 `read_url(*)`**：Antigravity 会把 `read_url` 规则同时当作终端沙箱的网络白名单，授予后沙箱内未经审核的命令就能访问任意网络（等于关掉 Codex 的“沙箱无网络”这一层）。

卸载（还原上面的设置改动并移除插件）：

```bash
node scripts/install.mjs --uninstall          # 加 --purge 同时删除 ~/.gemini/autoagy
```

> 注意：如果只用 `agy plugin disable autoagy` 停用插件，上面的授权仍然存在，绕过沙箱的命令、MCP 调用和浏览器操作会不经审核、也不弹窗直接执行。请用 `autoagy mode off` 暂停（此时这三类操作会改为弹窗问你），或用 `--uninstall` 彻底卸载。

**Antigravity IDE / Antigravity 2.0**：插件格式相同，但权限在设置界面里（Settings → Permission Grants）。请手动加上同样三条授权并保持终端沙箱开启，然后在 `config.json` 里设 `"sandbox": "on"`（autoagy 只能自动识别 CLI 的沙箱设置）。

## 使用

装好后正常使用 `agy` 即可。建议加个别名：

```bash
alias autoagy="node ~/.gemini/config/plugins/autoagy/bin/autoagy.mjs"
```

| 命令 | 作用 |
| --- | --- |
| `autoagy status` | 查看模式、审核后端、Antigravity 设置与授权是否就绪 |
| `autoagy log [-n 20]` | 最近的决策（被审核的操作、结论、风险、耗时） |
| `autoagy denials` | 最近被拒绝的操作及理由 |
| `autoagy approve <id>` | 对某次拒绝放行**一次重试**（审核模型会看到你的批准；critical 风险仍会拒绝） |
| `autoagy mode auto\|ask\|off` | `auto`=审核模型裁决；`ask`=有风险的操作弹窗问你（相当于 Codex “Ask for approval”）；`off`=不审核；上述授权覆盖的操作（绕过沙箱的命令、MCP、浏览器操作）改为弹窗问你，其余交给 Antigravity 自己的权限流程 |
| `autoagy review --tool run_command --args '{"CommandLine":"...","BypassSandbox":true}'` | 不启动 agent，直接测试某个操作会被怎么判 |
| `autoagy setup` / `autoagy teardown` | 单独执行/撤销设置改动 |

被拒绝时，agent 会收到 Codex 的原文指令（不得绕过；只能换更安全的做法，或向你说明风险并请求明确批准）。如果你确认要做，直接在对话里说明“我确认要执行 xxx”，下一次审核会把你的明确批准计入（Codex 的 post-denial approval 规则）。

## autoagy 自己的沙箱（Linux）

Antigravity 的终端沙箱允许命令写工作区里的 `.git`，也允许写本会话的对话日志 `brain/<id>/.system_generated/logs/`（agy 1.2.6 实测）。前者让沙箱内的命令可以植入 git hook，等到下次在沙箱外运行 git 时执行；后者让它可以伪造 transcript，而审核模型正是从 transcript 里判断用户授权的。Codex 的沙箱把 `.git` 设为只读，所以没有这个问题。

因此在 Linux 上，autoagy 改用自己的 [bubblewrap](https://github.com/containers/bubblewrap) 沙箱：agent 没有请求绕过沙箱的命令，会被 hook 的 `overwrite` 改写成在 bwrap 里运行。在 Antigravity 看来这是一条 `BypassSandbox` 命令，所以需要 setup 加的 `command(*)` 授权。沙箱规则与 Codex 的 workspace-write 相同：

- 可写：工作区、临时目录、本会话的 artifact 和 scratch 目录、`writableRoots`；
- 只读：其余所有路径，其中包括工作区里的 `.git`、`.agents`、`.gemini` 等目录，autoagy 自己的目录，以及对话日志；
- 隐藏：`credentialPaths` 里以 `~/` 开头的凭据位置（`~/.ssh`、`~/.aws`、`~/.netrc`……）在沙箱里显示为空目录或空文件；
- 无网络；`socket`/`socketpair` 只允许 `AF_UNIX`，建立和使用的调用（`connect`、`bind`、`listen`、`sendto`……）一律以 `EPERM` 失败，另外禁掉 `ptrace`、`process_vm_*`、`io_uring_*`（`--unshare-net` 只挡 IP 网络，挡不住文件系统上的 Unix socket）。

工作区里还不存在的受保护目录（比如不是 git 仓库时的 `.git`）：`--ro-bind` 对不存在的路径会直接跳过，而工作区是可写的，沙箱里的命令本来可以把它建出来，等它被别的工具在沙箱外加载。所以这类路径会被就地挂一个只读空 tmpfs，挂载点只在命令执行期间存在，命令结束后 autoagy 会在 PostToolUse 里把它删掉。副作用：命令执行的那一瞬间，工作区里会短暂出现一个空的 `.agents` 之类的目录（Codex 用同样的做法）。

`ownSandbox: "auto"`（默认）的启用条件：Linux；`/usr/bin/bwrap`（root 所有）存在且能创建沙箱，这需要非特权 user namespace；CLI 设置里有 `command(*)`。安装 bubblewrap：`sudo apt install bubblewrap`，或用发行版对应的包。`autoagy status` 会显示它是否生效。

与 Antigravity 的沙箱相比，有这些变化：

- 会写 `.git` 的 git 命令（`commit`、`checkout`、`stash`……）在沙箱里会失败，agent 需要加 `BypassSandbox: true` 重试并经过审核，这一点与 Codex 相同；
- 沙箱里完全没有网络，`read_url(...)` 授权过的域名在沙箱里也访问不到；
- agent 看到的工具结果前面会多一行 “A pre-tool hook changed the arguments of this tool call”。

**自检**：这套做法依赖 agy 没有公开的行为，而 agy 会自动更新。所以每条被改写的命令执行后，autoagy 都会在 PostToolUse 里核对 agy 实际执行的参数。只要有一次对不上（比如更新后的 agy 不再执行改写），autoagy 就对这个 agy 版本停用自己的沙箱：`auto` 退回 Antigravity 的沙箱，`on` 改为把命令送审。同时会拒绝下一条命令一次，让 agent 告诉你发生了什么。agy 换了版本会重新检查。`autoagy status` 会显示自检结果。

`ownSandbox: "on"`：不满足条件时不退回 Antigravity 的沙箱，而是把所有非只读命令送审。IDE 用户需要手动设为 `"on"`，因为 autoagy 读不到 IDE 的授权设置。`"off"`：不使用。

## 审核后端

默认用 **agy**：插件自带一个无工具的 `autoagy-guardian` agent，用你的 Antigravity 登录态以 headless 方式运行，无需额外 API key。实测每次审核约 4～12 秒。审核会话会出现在 `agy` 的历史里，归在 `~/.gemini/autoagy/guardian` 这个工作区下，不影响你项目里的 `agy -c`。

也可以用任意 **OpenAI 兼容**接口（更快，需要 API key），例如 Gemini：

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

OpenAI、DeepSeek、本地 Ollama 等同理，改 `baseUrl` / `apiKeyEnv` / `model` 即可。

## 配置（`~/.gemini/autoagy/config.json`）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `mode` | `"auto"` | `auto` / `ask` / `off` |
| `sandbox` | `"auto"` | Antigravity 的沙箱是否真的隔离命令；`auto` 从 CLI 设置和启动参数判断，`on`/`off` 强制指定。没有沙箱时只有已知只读命令免审 |
| `ownSandbox` | `"auto"` | autoagy 自己的 bubblewrap 沙箱（见上文）：`auto` 满足条件时启用，`on` 强制启用（不可用时命令送审），`off` 不使用 |
| `reviewer.backend` | `"agy"` | `agy` / `openai` / `none`（`none` 等同 `ask`） |
| `reviewer.timeoutSec` / `maxAttempts` | `90` / `3` | Codex 的审核期限与重试次数 |
| `reviewer.agy.model` / `effort` | 默认模型 / `"low"` | 审核用的 agy 模型与推理强度 |
| `onDenied` / `onTimeout` / `onError` | `"deny"` | 改为 `"ask"` 时，审核拒绝/超时/出错会转为弹窗让你决定 |
| `trustedDomains` | `localhost` 等 | 抓取网页、浏览器导航到这些域名（含子域名）免审 |
| `writableRoots` | `[]` | 额外允许免审编辑的目录 |
| `protectedPaths` | `[]` | 额外需要审核才能修改的路径（glob） |
| `credentialPaths` | `~/.ssh/**`、`**/.env` 等 | 凭据位置。文件工具读取这些文件（包括经符号链接读取）、`grep_search` 搜索包含它们的目录需要审核。以 `~/` 或绝对路径开头的条目还会在 autoagy 自己的沙箱里被隐藏；不在该沙箱里时，命令行里直接写出这些路径的命令需要审核（尽力而为：只识别字面路径、`~` 和 `$HOME`）。`**/.env` 这类没有固定位置的模式只对文件工具生效 |
| `rules` | `[]` | Codex execpolicy 风格前缀规则，例如 `{"pattern": ["terraform", "destroy"], "decision": "forbidden"}`；`allow` 仅对不含重定向、替换、变量、通配的简单命令生效 |
| `mcp.allow` | `[]` | 免审的 MCP 工具（`"server/tool"` glob，如 `"github/get_*"`） |
| `browser` | `"review"` | 浏览器点击/输入/执行 JS 是否审核 |
| `policy.file` / `policy.extra` | — | 替换/追加组织安全策略（对应 Codex 的 tenant policy），例如声明哪些仓库、域名是可信的 |
| `circuitBreaker` | `3 / 10 / 50` | 连续拒绝次数 / 窗口内拒绝次数 / 窗口大小 |
| `log.allowed` / `log.reviews` | `false` | 记录所有放行的操作 / 保存完整审核 prompt 与回复 |

配置只从全局文件读取：工作区里的文件 agent 自己能改，所以不接受工作区级配置。环境变量也不能改变策略（hook 继承 agy 的环境变量，而一条获批的越权命令可以给它启动的 agy 设任意环境变量）；只有 `AUTOAGY_HOME` 能换配置目录，所以提到 `AUTOAGY_` 的命令会被送审。

## 决策规则（第一层，无模型）

| 工具调用 | 结果 |
| --- | --- |
| 读文件、列目录、搜索、查看终端/任务状态、`search_web` | 放行（读取凭据类文件、搜索包含凭据位置的目录需审核） |
| 编辑工作区、会话 artifact 目录、临时目录内的文件 | 放行 |
| 编辑工作区外的文件，或 `.git`、`.agents`、`~/.gemini` 等 | 审核 |
| 编辑 autoagy 自己的配置/插件目录 | 直接拒绝（防止 agent 关掉自己的监管） |
| 沙箱内的命令 | 放行（Linux 上改写为在 autoagy 自己的沙箱里运行）；破坏性命令（强制 `rm`、`git reset --hard`、`git clean -f`、`find -delete`……）审核 |
| `BypassSandbox: true` 的命令、`notebook_execution` | 审核 |
| 无沙箱环境（关闭沙箱或 `--dangerously-skip-permissions`） | 已知只读命令放行，其余审核 |
| `invoke_subagent` 启动不继承 customizations、又带工具的自定义 agent | 审核（这种 agent 的工具调用不经过 autoagy） |
| MCP、网页抓取/浏览器导航（非可信域名）、浏览器交互、`define_subagent`、未知工具 | 审核 |

被审核的删除命令会附带 autoagy 预先检查的目标事实（是否存在、类型、条目数、是否在工作区内、是否是 git 仓库；路径经过符号链接时，按 `rm` 实际会删除的位置判断，并给出 `resolves_to`），弥补审核模型没有工具、无法像 Codex 那样自己去看的问题。

## 已知限制

- **没有启用 autoagy 自己的沙箱时**（macOS、Windows、没装 bubblewrap、IDE 没设 `ownSandbox: "on"`），沙箱内的命令仍然能写 `.git`（植入 git hook）和对话日志（伪造审核模型看到的用户消息），autoagy 只能靠静态检查拦截常见的破坏性命令。在这些环境下，autoagy 的保护弱于 Codex。
- Antigravity 的 hook 返回 `allow` 不能覆盖它自己的权限弹窗，hook 返回的 `permissionOverrides` 也不会授予权限（实测），所以需要上面的全局授权；对未授权域名的网页抓取仍会由 Antigravity 弹窗询问（这是为保住沙箱网络隔离做的取舍）。
- hook 负载里没有可信的用户消息（`lastUserInput` 等字段存在但未填），autoagy 只能从 transcript 里识别用户说的话，而 transcript 的完整性依赖上面的沙箱。
- 审核模型没有工具（Codex 的 guardian 可以做只读检查）；autoagy 用确定性的目标检查部分弥补。
- **文件编辑本身不在任何沙箱里执行**：写文件的是 agy 自己（Codex 的 `apply_patch` 在文件系统沙箱里跑），autoagy 只能在写入前检查一次目标路径。如果一条后台的沙箱命令在这中间把路径换成了符号链接，写入就会落到别处（检查时刻和使用时刻不一致）。PostToolUse 会在写入后重新解析目标并比对：对不上就记一条 `edit-target-changed` 并熔断本轮，但它只能事后发现，不能阻止那一次写入。根治要等 Antigravity 把编辑也放进沙箱。
- 子 agent 的授权以根会话里用户的话为准（通过父会话的 `invoke_subagent` 记录回溯），找不到父会话时按不可信处理。
- Windows 上命令解析是尽力而为（PowerShell 语法与 POSIX shell 不同，但会偏向保守）。
- 用 `--dangerously-skip-permissions` 启动 agy 时 Antigravity 的沙箱实际不生效：启用了 autoagy 自己的沙箱时命令仍在其中运行（实测 `overwrite` 在该模式下照样生效）；否则 autoagy 按无沙箱处理，审核会变多；`force_ask` 在该模式下会被自动同意，所以 autoagy 在此模式下只使用 allow/deny。

## 开发

```bash
npm test                 # 单元与集成测试（在测试用的配置文件里选 `reviewer.backend: "mock"`，不调用模型）
npm run validate         # agy plugin validate plugin
```

目录结构：

```
plugin/                  安装到 ~/.gemini/config/plugins/autoagy 的插件本体
  plugin.json  hooks.json  rules/AGENTS.md  agents/autoagy-guardian.md
  prompts/               审核策略（改编自 Codex）
  bin/autoagy.mjs        hook 入口 + 管理命令
  lib/                   shell 解析、命令安全、第一层策略、transcript、guardian、后端、状态、日志、安装
scripts/install.mjs      安装/卸载
test/                    node:test 测试
docs/design.md           调研记录、实测的 Antigravity 行为、与 Codex 的差异
```

## 许可

Apache-2.0。审核策略文本和若干规则改编自 [OpenAI Codex](https://github.com/openai/codex)（Apache-2.0），详见 [NOTICE](NOTICE)。
