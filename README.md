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

> **装它之前要知道的一件事。** autoagy 要向 Antigravity 申请 `command(*)`、`mcp(*)`、`execute_url(*)` 三条授权，之后 hook 就是唯一的闸门。hook 自己失败是 fail-closed（工具调用报错），但**插件没加载是 fail-open**：`agy plugin disable`、`agy plugin install` 用未钉住的 `hooks.json` 覆盖、或钉住的解释器失效——这三种情况下授权都还在，闸门没了。
>
> 这跟 Codex 的形状不同，而且方向是反的：Codex 关掉 auto 模式会回到更严格的状态（它本来不需要放宽任何宿主权限），autoagy 关掉会回到**比从未安装更宽松**的状态。`autoagy status` 会报「hooks 最后一次运行」的时间，据此可以查（这一节末尾那条 `agy plugin disable` 的说明是同一件事的另一种说法）。彻底的解法是不授予这三条通配，代价是 autoagy 大部分能力失效。

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

> 注意：如果只用 `agy plugin disable autoagy` 停用插件，上面的授权仍然存在，绕过沙箱的命令、MCP 调用和浏览器操作会不经审核、也不弹窗直接执行。请用 `autoagy mode off` 暂停（此时这三类操作会改为弹窗问你；但如果 agy 是用 `--dangerously-skip-permissions` 启动的，弹窗会被自动同意，所以那种情况下改为直接拒绝），或用 `--uninstall` 彻底卸载。

**Antigravity IDE / Antigravity 2.0**：插件格式相同，但权限在设置界面里（Settings → Permission Grants）。请手动加上同样三条授权并保持终端沙箱开启，然后在 `config.json` 里设 `"sandbox": "on"`（autoagy 只能自动识别 CLI 的沙箱设置）。

## 使用

装好后正常使用 `agy` 即可。建议加个别名：

```bash
alias autoagy="node ~/.gemini/config/plugins/autoagy/bin/autoagy.mjs"
```

| 命令 | 作用 |
| --- | --- |
| `autoagy status` | 查看模式、审核后端、Antigravity 设置与授权是否就绪，以及 **hook 最后一次运行的时间**——插件被 disable、钉子被覆盖、解释器失效，三种失效都只表现为"hooks 不再运行"，这个时间戳是唯一能从内部看到的痕迹（超过一天会明确告警） |
| `autoagy log [-n 20]` | 最近的决策（被审核的操作、结论、风险、耗时） |
| `autoagy denials` | 最近被拒绝的操作及理由 |
| `autoagy approve <id>` | 对某次拒绝放行**一次重试**（审核模型会看到你的批准；critical 风险仍会拒绝） |
| `autoagy trust [<会话>] [--all] [--force]` | 解除会话的标记（见下文「会话信任」）并释放为它保留的只读挂载点。不带参数时只列出被标记的会话。执行前它自己会先查一次工作区锁：还有命令在跑就拒绝，`--force` 才强行释放 |
| `autoagy mode auto\|ask\|off` | `auto`=审核模型裁决；`ask`=有风险的操作弹窗问你（相当于 Codex “Ask for approval”）；`off`=不审核；上述授权覆盖的操作（绕过沙箱的命令、MCP、浏览器操作）改为弹窗问你，其余交给 Antigravity 自己的权限流程。`off` 下弹窗在 `--dangerously-skip-permissions` 里会被自动同意，所以那个模式下改为直接拒绝；不可信会话的编辑和读取也照常弹窗 |
| `autoagy review --tool run_command --args '{"CommandLine":"...","BypassSandbox":true}'` | 不启动 agent，直接测试某个操作会被怎么判 |
| `autoagy setup` / `autoagy teardown` | 单独执行/撤销设置改动 |

被拒绝时，agent 会收到 Codex 的原文指令（不得绕过；只能换更安全的做法，或向你说明风险并请求明确批准）。如果你确认要做，直接在对话里说明“我确认要执行 xxx”，下一次审核会把你的明确批准计入（Codex 的 post-denial approval 规则）。

## autoagy 自己的沙箱（Linux）

Antigravity 的终端沙箱允许命令写工作区里的 `.git`，也允许写本会话的对话日志 `brain/<id>/.system_generated/logs/`（agy 1.2.6 实测）。前者让沙箱内的命令可以植入 git hook，等到下次在沙箱外运行 git 时执行；后者让它可以伪造 transcript，而审核模型正是从 transcript 里判断用户授权的。Codex 的沙箱把 `.git` 设为只读，所以没有这个问题。

因此在 Linux 上，autoagy 改用自己的 [bubblewrap](https://github.com/containers/bubblewrap) 沙箱：agent 没有请求绕过沙箱的命令，会被 hook 的 `overwrite` 改写成在 bwrap 里运行。在 Antigravity 看来这是一条 `BypassSandbox` 命令，所以需要 setup 加的 `command(*)` 授权。沙箱规则与 Codex 的 workspace-write 相同：

- 可写：工作区、临时目录、本会话的 artifact 和 scratch 目录、`writableRoots`；
- 只读：其余所有路径，其中包括工作区里的 `.git`、`.agents`、`.gemini` 等目录，autoagy 自己的目录，以及对话日志；
- 隐藏：`credentialPaths` 里以 `~/` 开头的凭据位置（`~/.ssh`、`~/.aws`、`~/.netrc`……）在沙箱里显示为空目录或空文件；
- 无网络；`socket`/`socketpair` 只允许 `AF_UNIX`，建立和使用的调用（`connect`、`bind`、`listen`、`sendto`……）一律以 `EPERM` 失败，另外禁掉 `ptrace`、`process_vm_*`、`io_uring_*`（`--unshare-net` 只挡 IP 网络，挡不住文件系统上的 Unix socket）；
- 环境变量从白名单重建（`--clearenv` + `--setenv`）：`PATH`、`HOME`、`USER`、`LOGNAME`、`SHELL`、`TERM`、`TMPDIR`、`TZ`、`PWD`、`LANG` 和 `LC_*`，值原样传递。hook 继承的是 agy 的环境，里面通常有你 export 的 API key；不清理的话，沙箱里一条 `printenv` 就能读到它，而且这条命令是免审的。需要额外变量时用 `ownSandboxEnvPassThrough`（见下表）。

  注意两点。一是这些变量（包括 `PATH` 和 `HOME`）的值会逐字写进改写后的命令行（`--setenv NAME VALUE`），而改写后的参数是 agent 能看到的内容，所以**白名单和 `ownSandboxEnvPassThrough` 里都不要放密钥**。二是 autoagy **不会**过滤 `PATH`：沙箱内工作区是可写且可执行的，命令本来就能按路径运行工作区里的任何文件，过滤 `PATH` 买不到任何隔离，只会让 `.venv/bin`、`node_modules/.bin` 里的工具找不到或用错解释器。真正危险的是**沙箱外**的命令通过工作区里的 `PATH` 目录解析到被改过的可执行文件——那条路会送审（见「已知限制」里的 `command-from-writable-root`）。

  这个沙箱不生效时（macOS、Windows、没装 bwrap），命令拿到的就是 hook 继承来的那份环境——**注意 Antigravity 自己的终端沙箱并不清环境**，所以「有沙箱」不等于读不到。判据因此不是「有没有沙箱」，而是**这条命令的环境有没有被重建**：只有 autoagy 自己的沙箱（`--clearenv`）和 `commandEnv.mode: "scrub"`（`env -i`）会重建它。两者都不生效时，读环境按凭据读取处理，送审的有：`printenv`、裸 `env`、`ps` 和 `jq` 取环境的写法，以及**命令展开的任何 `$变量`，只要这个名字不在沙箱白名单里、而继承来的环境里确实有它**。所以 `$PATH`、`$HOME` 照常免审，循环里的 `$f` 这种不在环境里的名字也照常，`$OPENAI_API_KEY` 和 `$JAVA_HOME` 送审——判据就是「沙箱会不会把这个变量传进去」，`ownSandboxEnvPassThrough` 同时放宽两边。动态拼出来的名字（`eval`、`base64 | sh`）仍然拦不住，见「已知限制」。

工作区里还不存在的受保护目录（比如不是 git 仓库时的 `.git`）：`--ro-bind` 对不存在的路径会直接跳过，而工作区是可写的，沙箱里的命令本来可以把它建出来，等它被别的工具在沙箱外加载。所以这类路径会被就地挂一个只读空 tmpfs。副作用：命令执行的那一瞬间，工作区里会短暂出现一个空的 `.agents` 之类的目录（Codex 用同样的做法）。

每个受保护目录会被**挂两次**：先一个空的只读挂载，再一个指向真实目录的只读绑定（后挂的赢）。目录存在时按真实内容只读绑定，所以沙箱里 `.git` 照样能读；目录不存在（或在这条命令启动前被回收掉了）时那个绑定被跳过，空挂载留下。这一点是必须的——只挂一个绑定时，目录一旦在「构造命令行」和「bwrap 启动」之间消失，绑定会静默跳过，命令就会写进真实的受保护目录（实测过）。

挂载点什么时候能回收，取决于**还有没有命令在跑**。autoagy 从不自己启动 bwrap（执行改写后命令行的是 agy），拿不到进程号，所以它让每条被改写的命令行自己持有证据：命令行最前面加一层 `flock -s <锁文件> <bwrap> …`，共享锁从 bwrap 启动一直持有到它退出，后台命令也一样。要回收挂载点时，autoagy 去抢排他锁——抢得到说明没有命令在跑，抢不到就保留。锁文件放在 `~/.gemini/autoagy/state/` 下（沙箱内是只读挂载，命令删不掉也重建不了，这是这个办法成立的前提）。

在拿不到可信 `flock` 的主机上退回一个弱信号（`IsDaemon: true`、`Blocking: false`、正的 `WaitMsBeforeAsync`，或出现过终端类工具）：一旦出现，本会话的挂载点就保留到 `autoagy trust` 为止。`autoagy status` 会明确报告这种降级状态——`flock` 来自 util-linux，正常机器上都在，所以真碰上了值得看一眼。开新会话**不会**释放旧的——挂载点按会话记录，而删掉另一个会话的挂载点正是上面那条要避免的事。保留的代价只是工作区里多出一个空的 `.agents` 之类的目录；保护本身不丢，`autoagy status` 会列出这些会话。

保留是刻意的，因为**提前回收会真的拆掉保护**：bwrap 把只读 tmpfs 挂在子进程自己的 mount namespace 里、挂在一个目录项上，而 `rmdir` 会把宿主上那个目录项摘掉——子进程里这条路径随之不再解析，而工作区根仍是可写的 bind，于是**还在运行的命令会重建这个目录，直接写到宿主上**。实测：不回收时 `mkdir .agents/hooks/pre-commit` 得到 `Read-only file system`；在命令还在跑时回收，同一条命令就在宿主上把文件建出来了。这正是占位机制要拦的那件事。

（`--tmpfs` 挂到一个已被删掉的目录**不会**让 bwrap 失败：在工作区这种可写 bind 下 bwrap 会自己把挂载点建出来，实测退出码 0；只有父目录只读时才会 `Can't mkdir ... : Read-only file system` 退出 1。）

如果回收时发现挂载点里**有东西**：bwrap 的 tmpfs 挂在子进程的 namespace 里，宿主上这个目录在命令期间应当是空的，所以有内容说明有东西绕过了挂载。autoagy 保留目录作为证据、记一条 `placeholder-dirty`、并在 stderr 上告警。**是否把会话标记为不可信取决于谁在回收**：只有 PostToolUse（刚跑完的确实是一条沙箱命令）才会标记；回合结束时的兜底清扫只记录，因为那时目录也可能是 agy 自己的编辑工具写进去的——它本来就写在所有沙箱之外，为一次已获批准的正常编辑把整个会话标黑是误报。

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
| `trustedDomains` | `localhost` 等 | **抓取**网页到这些域名（含子域名）免审 |
| `browserTrustedDomains` | `[]` | **浏览器导航**到这些域名免审。默认空白：抓取拿到的是文本，导航会把页面脚本放进一个能联网、不在任何沙箱里的浏览器里跑，而本地开发服务器提供的页面通常正是 agent 免审就能改的工作区文件。要恢复「浏览器打开 localhost 免审」就把 `localhost` 加进来 |
| `webSearch` | `"allow"` | `search_web` 是否送审。搜索把 agent 写的 query 发给搜索引擎，而请求是 agy 自己发的——没有任何沙箱在这条路上（`--unshare-net` 挡的是沙箱内命令的网络）。默认 `"allow"`，与 Codex 一致：Codex 的 web search 是托管工具，不经过审批流程，改由配置限制（`web_search` 模式、受管 `requirements.toml` 里的 `allowed_web_search_modes`）。需要审核每次搜索就设为 `"review"`，此时 autoagy 自身出错或超时的那条失败路径也照样拒绝——否则它恰好在监管最弱的时候失效 |
| `ownSandboxEnvPassThrough` | `[]` | 除白名单外额外传给沙箱内命令的环境变量名（支持 `PREFIX_*`）。沙箱默认清空环境，列在这里的变量对免审命令可读，属于削弱沙箱。**值会写进改写后的命令行，agent 能看到，不要放密钥** |
| `commandEnv` | `{"mode": "inherit"}` | 没有自己沙箱的平台（macOS、没装 bwrap——**Windows 不在内**：那里没有 root 所有的 `env`，这条改写跑不起来，`status` 会直说而不是假装待命）上命令用什么环境。`inherit`（默认）＝命令拿到 hook 继承的环境，也就是你 export 的那些——Codex 的 `shell_environment_policy` 默认同样是 `inherit = all` 且默认排除关闭。`scrub` 会把命令改写成在 `env -i` 下运行，环境用与沙箱**同一份**白名单（外加 `ownSandboxEnvPassThrough`）重建，`HOME` 取钉住的那个（与沙箱一致，这样命令里的 `~` 就是凭据清单依据的 `~`），于是免审命令打不出环境变量，已批准的命令也倒不进 transcript。实测：agy 会应用不带 `BypassSandbox` 的 `overwrite`，命令仍在 Antigravity 的沙箱里，所以**不需要 `command(*)` 授权**。autoagy 自己的沙箱始终清空环境，这个开关只管没有沙箱的平台 |
| `writableRoots` | `[]` | 额外允许免审编辑的目录 |
| `protectedPaths` | `[]` | 额外需要审核才能修改的路径（glob） |
| `credentialPaths` | `~/.ssh/**`、`**/.env` 等 | 凭据位置。文件工具读取这些文件（包括经符号链接读取）、`grep_search` 搜索包含它们的目录需要审核。以 `~/` 或绝对路径开头的条目还会在 autoagy 自己的沙箱里被隐藏；没有固定位置的模式（`**/.env`、`**/*.pem`）隐藏不了，所以命令行里字面写出这种路径（`cat .env`）也要审核，沙箱内外一样。不在该沙箱里时，命令行里直接写出**任何**这类路径的命令都需要审核（尽力而为：只识别字面路径、`~` 和 `$HOME`，不解析变量）。另外 `/proc` 一概按凭据位置处理：`/proc/<pid>/environ`、`/proc/<pid>/cmdline` 这类文件被直接读到要审核，而 `/proc` 本身或其中**目录**被遍历（`grep_search /proc`、`grep -r /proc`）也要审核——遍历会读到一个进程一份的 environ；`/proc/cpuinfo`、`/proc/self/status` 这种单个文件不受影响。沙箱内这些都不送审：那里是私有的 /proc，读到的是清空后的环境 |
| `rules` | `[]` | Codex execpolicy 风格前缀规则，例如 `{"pattern": ["terraform", "destroy"], "decision": "forbidden"}`；`allow` 仅对不含重定向、替换、变量、通配的简单命令生效 |
| `mcp.allow` | `[]` | 免审的 MCP 工具（`"server/tool"` glob，如 `"github/get_*"`） |
| `browser` | `"review"` | 浏览器点击/输入/执行 JS，以及 `browser_subagent` 是否审核 |
| `policy.file` / `policy.extra` | — | 替换/追加组织安全策略（对应 Codex 的 tenant policy），例如声明哪些仓库、域名是可信的 |
| `circuitBreaker` | `3 / 10 / 50` | 连续拒绝次数 / 窗口内拒绝次数 / 窗口大小 |
| `log.allowed` / `log.reviews` | `false` | 记录所有放行的操作 / 保存完整审核 prompt 与回复 |

配置只从全局文件读取：工作区里的文件 agent 自己能改，所以不接受工作区级配置。环境变量也不能改变策略（hook 继承 agy 的环境变量，而一条获批的越权命令可以给它启动的 agy 设任意环境变量）。

配置目录和 `home` 有两个来源：环境变量（`AUTOAGY_HOME`，否则 `HOME`）和 `autoagy setup` 在安装时写进 `hooks.json` 的绝对路径。装了插件之后**以钉子为准**，环境变量说了不算——否则一条命令就能把 hook 指向它自己写的配置目录，或者用 `HOME=/tmp/x` 把整个 `~`（连同凭据清单和「不可编辑路径」）搬走。`hooks.json` 在插件目录里，而插件目录属于策略的「不可编辑路径」，所以 agent 改不动这个钉子。另外，以 `agy` 为可执行名的命令、以及给 `HOME`/`AGY_*`/`ANTIGRAVITY_*`/`JETSKI_*` 赋值的命令都会送审。`reviewer.backend: "mock"` 只在设置了 `AUTOAGY_UNSAFE_MOCK_REVIEWER=1`（测试用）时生效，否则回退到默认后端。

## 决策规则（第一层，无模型）

| 工具调用 | 结果 |
| --- | --- |
| 读文件、列目录、搜索、查看终端/任务状态、`search_web` | 放行（读取凭据类文件、搜索包含凭据位置的目录需审核；`webSearch: "review"` 时 `search_web` 送审） |
| 编辑工作区、会话 artifact 目录、临时目录内的文件 | 放行 |
| 编辑工作区外的文件，或 `.git`、`.agents`、`~/.gemini` 等 | 审核 |
| 编辑 autoagy 自己的配置/插件目录 | 直接拒绝（防止 agent 关掉自己的监管） |
| 沙箱内的命令 | 放行（Linux 上改写为在 autoagy 自己的沙箱里运行）；破坏性命令（强制 `rm`、`git reset --hard`、`git clean -f`、`find -delete`……）审核 |
| 读进程环境的命令（`printenv`、裸 `env`、`ps auxe`、`jq env`，或展开一个沙箱白名单之外、而环境里确实存在的 `$变量`） | 审核——除非这条命令的环境已被重建（autoagy 自己的沙箱，或 `commandEnv.mode: "scrub"`），那时它读不到东西，不送审 |
| `BypassSandbox: true` 的命令、`notebook_execution` | 审核 |
| 无沙箱环境（关闭沙箱或 `--dangerously-skip-permissions`） | 已知只读命令放行，其余审核 |
| `invoke_subagent` 启动不继承 customizations、又带工具的自定义 agent | 审核（这种 agent 的工具调用不经过 autoagy） |
| `browser_subagent`、`generate_image`、`delete_knowledge` | 审核：前者的导航和点击是它自己做的，不逐条经过本策略；后者写出的路径策略看不到；删除的知识无法从工作区恢复 |
| 以 `agy` 为可执行名的命令（启动另一个 Antigravity 实例） | 审核：那个实例是否加载这些 hook，由它自己的配置和环境决定，而这条命令两样都能设 |
| 命令里给 `HOME` 或 `AGY_*`/`ANTIGRAVITY_*`/`JETSKI_*` 赋值 | 审核：`HOME` 决定 `~` 指向哪里，也就决定了策略里的凭据清单和「不可编辑路径」 |
| `send_command_input` | 只在 autoagy 自己的沙箱生效时放行（`config.sandbox: "on"` 是声明，Antigravity 的沙箱也让 `.git` 和日志可写）；macOS/Windows/无 bwrap 时一律审核 |
| 向用户申请权限（`ask_permission`、`ask_custom_permission`） | 放行——正常情况下弹窗会到你手里，由你决定，autoagy 没什么可加的。但 `--dangerously-skip-permissions` 下 agy 会自己同意所有工具权限（它自己的字符串就是这么写的：`auto-approving all tool permissions`），平台读不到 agy 参数时也无法排除这个标志——那时没有人能回答，申请就送审（策略里「削弱 agent 自身的监管」属于持续性安全削弱） |
| MCP（含 `read_resource` / `list_resources` 这类 MCP 资源读取）、网页抓取/浏览器导航（非可信域名）、浏览器交互、`define_subagent`、未知工具 | 审核 |
| **会话被标记为不可信之后**（见下）的文件编辑和读取文件内容 | 审核；触及监管文件的命令改为直接拒绝 |

被审核的删除命令会附带 autoagy 预先检查的目标事实（是否存在、类型、条目数、是否在工作区内、是否是 git 仓库；路径经过符号链接时，按 `rm` 实际会删除的位置判断，并给出 `resolves_to`），弥补审核模型没有工具、无法像 Codex 那样自己去看的问题。

## 会话信任

有两种情况说明「环境做了监管没批准的事」，autoagy 会把**整个会话**标记为不可信：

1. 文件编辑的目标在批准时和执行时解析到了不同位置（`edit-target-changed`）——agy 的写入不在任何沙箱里，只能在写之前检查一次；
2. 只读挂载点里出现了文件（`placeholder-dirty`）——一条刚跑完的沙箱命令写进了本该被它挡住的位置。仅限 PostToolUse 判定；回合结束时的兜底清扫只记录不标记，理由见上文。

后果：文件编辑和「读取文件内容」的工具从这时起一律送审；触及 autoagy 自身、`AUTOAGY_*` 或对话日志的命令改为**直接拒绝**（此时审核所依据的正是可疑的那部分证据）。审核材料里会带上漂移的原因和最近编辑过的文件清单。

这个标记**不随新一轮对话自动清除**：换了轮次，磁盘上被换掉的符号链接并不会自己变回去。确认磁盘现状之后用 `autoagy trust [<会话 id 前缀>]`（或 `--all`）解除；不带参数时它只列出被标记的会话，因为一次性解除所有会话是关于磁盘状态的判断，应该由人来做。`autoagy approve` 只放行一次重试，不解除此标记。

同一个 `trust` 也负责释放「可能有后台命令在跑」时保留的只读挂载点——那个标记同样不会自动消失。**执行前请确认后台命令确实已经结束**，否则释放等于把上面说的那个提前回收做一遍。

审核材料里会带上漂移的原因和最近编辑过的文件清单；后者只覆盖**编辑工具**改过的文件（路径），经沙箱命令改写的文件不在其中。

## 已知限制

- **没有启用 autoagy 自己的沙箱时**（macOS、Windows、没装 bubblewrap、IDE 没设 `ownSandbox: "on"`），沙箱内的命令仍然能写 `.git`（植入 git hook）和对话日志（伪造审核模型看到的用户消息）。autoagy 能做的只有把命令里字面出现 `.system_generated`、autoagy 自身路径或凭据位置的命令送审——这是原始命令行上的子串匹配，变量拼接或 base64 之类可以绕过，而且事后没有任何完整性校验能发现日志被改过。**这不是「和 Linux 上差不多」，而是明显更弱**，也不能靠配置补上。审核模型现在会收到一行明确的提示，知道在此配置下不能把 transcript 里的用户发言当作已确立的授权。
- **环境变量：判据是「这条命令的环境有没有被重建」，不是「有没有沙箱」。** hook 继承的是 agy 的环境，里面通常有你 export 的 API key，而 Antigravity 自己的终端沙箱**不清环境**——只有 autoagy 自己的沙箱（`--clearenv`）和 `commandEnv.mode: "scrub"`（`env -i`）会重建它。两者都不生效时（macOS、Windows、没装 bwrap、IDE 没设 `ownSandbox: "on"`，且 `commandEnv` 仍是默认的 `inherit`），这些会送审：`printenv`、裸 `env`、`ps` 里取环境变量的写法（`ps auxe`、`ps eww`、`-E`、`-o env`；`ps -ef` 是「所有进程」，不受影响）、`jq` 的 `env` 与 `$ENV` 内建、**PowerShell 的 `Env:` 提供程序**（按**参数**判定而不是按命令名——`ls`、`cat`、`type` 是那两个 cmdlet 的别名，按名字列的白名单永远列不全自己的别名，所以 `ls Env:`、`cat Env:\OPENAI_API_KEY` 一样送审）、`/proc/<pid>/environ` 与 `/proc/<pid>/cmdline`、对 `/proc` 或其中目录做遍历的搜索（`grep_search /proc`、`grep -r /proc`），以及**命令展开的任何 `$变量`，只要那个名字不在沙箱白名单里而环境里确实有它**（包括 `bash -c`、不带引号的 heredoc 这类外层看不见的位置）。最后这条把「读环境」从枚举命令名换成了枚举变量名，但**仍然不是证明**：运行时拼出来的名字拦不住（`eval`、`base64 | sh`、`${X}${Y}`），白名单里某个命令新版本新增的取值方式也一样。真正的缓解是 autoagy 自己的沙箱，或者在没有它的平台上打开 `commandEnv.mode: "scrub"`（把命令改写到 `env -i` 下、环境按同一份白名单重建——那才是闭合集合；自检失败时会自动停用并告警一次，不会假装还在 scrub），再或者不要把密钥放在环境里。（**Windows 例外**：没有 root 所有的 `env` 可用，这条改写跑不起来，那里只有上面这份清单。）
- **Windows 上从设置文件推断沙箱状态已被停用**：Windows 读不到 agy 进程的参数，`--dangerously-skip-permissions` 无法识别，而 `autoagy setup` 写进设置文件的那两个值正是检查所依据的。所以那里不再声称「沙箱有效」，而是按无沙箱处理——后果是不带沙箱的普通命令（`npm test`、`ls`、`curl`）从免审变成送审。同样因为读不到启动参数，Windows 上**弹窗一律改为拒绝**：那个标志无法排除，弹窗可能被静默自动同意，宁可不问。
- **沙箱外的已知只读命令要看它解析到哪里。** autoagy 自己的沙箱不跑的时候（macOS、Windows、没装 bwrap），命令用的是继承来的 `PATH`，很多开发环境会包含 `.venv/bin`、`node_modules/.bin` 这类目录——都在可写根内，改动免审。已知只读的白名单只比较 basename，所以 `ls` 会被当作安全的，哪怕实际执行的是 agent 刚写进 `node_modules/.bin` 的那个 `ls`。现在这条链会被送审：无沙箱时，如果命令解析到的文件落在可写根内，就不放行（`command-from-writable-root`）。代价是这类环境里从 `.venv/bin` 调工具会多一次审核——这是刻意的，因为那正是「先写后执行」成立的地方。autoagy 自己的沙箱内不问这个问题：沙箱已经限定了任何二进制能碰到什么。
- Antigravity 的 hook 返回 `allow` 不能覆盖它自己的权限弹窗，hook 返回的 `permissionOverrides` 也不会授予权限（实测），所以需要上面的全局授权；对未授权域名的网页抓取仍会由 Antigravity 弹窗询问（这是为保住沙箱网络隔离做的取舍）。
- hook 负载里没有可信的用户消息（`lastUserInput` 等字段存在但未填），autoagy 只能从 transcript 里识别用户说的话，而 transcript 的完整性依赖上面的沙箱。
- 审核模型没有工具（Codex 的 guardian 可以做只读检查）；autoagy 用确定性的目标检查部分弥补。
- **文件编辑本身不在任何沙箱里执行**：写文件的是 agy 自己（Codex 的 `apply_patch` 在文件系统沙箱里跑），autoagy 只能在写入前检查一次目标路径。如果一条后台的沙箱命令在这中间把路径换成了符号链接，写入就会落到别处（检查时刻和使用时刻不一致）。PostToolUse 会在写入后重新解析目标并比对：对不上就记一条 `edit-target-changed`、熔断本轮，并把整个会话标记为不可信（见「会话信任」）。这些都只能事后发现，不能阻止那一次写入。**读取凭据类文件的检查没有任何事后核对**：它只在执行前判断一次，读类工具没有对应的 PostToolUse 检查。根治要等 Antigravity 把编辑也放进沙箱。
- 子 agent 的授权以根会话里用户的话为准（通过父会话的 `invoke_subagent` 记录回溯），找不到父会话时按不可信处理。
- Windows 上命令解析是尽力而为（PowerShell 语法与 POSIX shell 不同，但会偏向保守）。
- 用 `--dangerously-skip-permissions` 启动 agy 时 Antigravity 的沙箱实际不生效：启用了 autoagy 自己的沙箱时命令仍在其中运行（实测 `overwrite` 在该模式下照样生效）；否则 autoagy 按无沙箱处理，审核会变多；`force_ask` 在该模式下会被自动同意，所以 autoagy 在此模式下只使用 allow/deny——这条现在也覆盖 `mode: off` 的弹窗路径。
- **工作区里「写了之后会在沙箱外执行」的文件是免审的**：`.envrc`（direnv 自动加载）、`.husky/`（`git commit` 时执行）、`.vscode/tasks.json`、`package.json` 的 `postinstall`、`Makefile`，以及任何被别的工具读取后执行的脚本。暴露面和 `.git` 属于同一类（先写后执行），区别是 `git` 几乎必然会在沙箱外运行，而这一类要等某个工具去执行它。**Codex 在这里的取舍是同样的**——它的 workspace-write 只保护 `.git`、`.agents`、`.codex` 三个名字（`PROTECTED_METADATA_PATH_NAMES`），所以 autoagy 默认也保持这个集合（多出的 `.agent`/`_agents`/`.gemini` 是 Antigravity 自己会读的 agent 配置）。需要更严就用 `protectedPaths` 把它们加进去，代价是 agent 每次改这些文件都要过一次审核。
- **`search_web` 默认免审，而它是一条出网通道**：query 是 agent 写的文本，请求由 agy 发出，不在任何沙箱里（`--unshare-net` 只约束沙箱内的命令），策略里那套 Data Exfiltration 规则看不到它。默认放行是照 Codex 的做法：它的 web search 是托管工具，不走审批流程，由配置限制（`web_search` 模式、受管 `requirements.toml` 的 `allowed_web_search_modes`）；autoagy 对应的开关是 `webSearch: "review"`——代价是每次搜索多一次审核延迟（agy 后端实测 4～12 秒）。
- **危险命令识别是有解析器支撑的模式表，不是纯字面黑名单，但也不要高估。** `shell.mjs` 是真正的 POSIX shell 解析器，会去引号、还原转义、解开 `sudo`/`env`/`nohup`/`timeout`/`xargs`/`flock`/`nice` 等包装，并从 `bash -c`、`eval`、`trap`、`watch`、`su -c`、`find -exec`、heredoc 里取出内层脚本，递归到 8 层，解析失败一律送审。所以「引号拼接」「全路径」「组合短选项」「多层包装」都拦得住。**拦不住的**是动态构造的命令名：`$CMD -rf`、`rm${IFS}-rf`、`$(printf rm)`、`base64|sh`、把脚本塞给解释器的 `-c`。另外，沙箱内这条模式表才是决定性判据（能解析、没命中就放行），无沙箱路径上起决定作用的是已知只读白名单（不在白名单里的一律送审）。

## 隐私与数据流向

默认的 `reviewer.backend: "agy"` 用你自己的 Antigravity 登录态在本地跑一个无工具的 agent，**不把任何内容发给第三方**。

改成 `"openai"`（或任何兼容 baseUrl，如 DeepSeek、Gemini、本地 Ollama）之后，每次审核都会把下面这些 POST 到那个地址：

- 组织策略文本（`policy.md`）；
- **经过预算裁剪的**对话记录，不是原始 `transcript_full.jsonl`：按规则选取，每条条目有长度上限，超出部分从中间截断，总量有上限，被丢弃时会附一句 “Some conversation entries were omitted.”；**没有任何脱敏**，只是截断——如果 transcript 或工具输出里出现了凭据，它会原样发出去；
- 子会话场景下根会话的用户消息（同样有上限）；
- 待审操作的 JSON（含工具调用参数）；
- 该后端的 API key（作为 `Authorization` 头）。

还会发送：

- 本地环境信息：平台、工作区根目录、沙箱状态，以及**本会话日志在此配置下是否受保护**；
- **本会话最近编辑过的文件路径**（最多 20 条，含解析后的真实路径）——因为经过裁剪的 transcript 可能已经把较早的编辑丢掉，而审核模型需要知道某个即将被重新执行的脚本前不久刚被改过；
- 沙箱内命令的 `--setenv` 值，即白名单和 `ownSandboxEnvPassThrough` 里那些变量的值（`PATH`、`HOME` 等）——它们逐字写进改写后的命令行，因而也出现在工具调用参数里。

文件内容只以「工具调用参数」的形式出现，即 agent 当时写下/读取的内容。**没有任何脱敏**，只有长度截断。

## 开发

```bash
npm test                 # 单元与集成测试（配置文件里选 `reviewer.backend: "mock"`，并设 AUTOAGY_UNSAFE_MOCK_REVIEWER=1 打开它，不调用模型）
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
