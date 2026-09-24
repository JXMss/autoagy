# autoagy — 给 Antigravity 的 Codex 式 Auto 模式

[English](README.en.md) ｜ [设计依据与实测记录](docs/design.md)

> **非官方项目**：与 Google（Antigravity）和 OpenAI（Codex）都没有关联，也未获其背书。

autoagy 是一个 [Google Antigravity](https://antigravity.google) 插件，按 OpenAI Codex 的 **“Approve for me”（auto-review）** 模式实现了 Antigravity 的 auto 模式：

- 安全的操作（读文件、改工作区内的文件、在终端沙箱里跑命令……）**直接执行**，不打断你；
- 有风险的操作（请求绕过沙箱、改工作区外的文件、`rm -rf`、`git reset --hard`、MCP 调用、联网、浏览器点击……）**交给一个审核模型（guardian）裁决**，而不是弹窗问你；
- 审核模型按 Codex 的安全策略判断风险与用户授权，拒绝时把理由告诉 agent，让它换更安全的做法或回来问你。

它基于对 Codex v0.154.0 源码（`codex-rs/core/src/guardian`）的逐项移植，并针对 Antigravity 的 hook、权限和沙箱机制做了实测适配（见 [docs/design.md](docs/design.md)）。

## 与 Codex 的对应关系

| Codex “Approve for me” | autoagy |
| --- | --- |
| workspace-write 沙箱内的命令直接运行 | Linux 上在 autoagy 自己的 bubblewrap 沙箱里直接运行（规则同 workspace-write，[细节见参考手册](docs/reference.md#autoagy-自己的沙箱)）；否则在 Antigravity 终端沙箱里运行 |
| `sandbox_permissions: require_escalated` 走审核 | `BypassSandbox: true` 走审核 |
| 强制 `rm`（含 `sudo`/`env`/`bash -c` 嵌套）走审核 | 同左，另加破坏性 git 命令（Antigravity 沙箱不保护 `.git`） |
| `apply_patch` 只写可写根目录则放行，`.git/.agents/.codex` 只读 | 编辑工具同理；`.git/.agents/.gemini`、`~/.gemini` 等需审核。autoagy 自己的沙箱里 shell 命令对这些目录同样只读 |
| MCP 调用（非只读注解）走审核 | 默认全部走审核（比 Codex 严），可用 `mcp.allow` 白名单；`mcp.annotations: "trust"` + 一次 `autoagy mcp-scan` 之后就与 Codex 一致：只读注解免审 |
| execpolicy `prefix_rule` allow/prompt/forbidden | `rules` 配置，语义相同 |
| guardian：策略 prompt + 精简 transcript + planned action JSON | 同左（策略文本改编自 Codex，transcript 预算与选取规则相同） |
| 输出 `{risk_level, user_authorization, outcome, rationale}` | 同左 |
| 90 秒期限、最多 3 次尝试、出错即拒绝（fail closed） | 90 秒是**单次**尝试的期限，整次审核 140 秒（卡住的那次会被杀掉重问）；出错即拒绝同左 |
| 拒绝/超时时给 agent 的指令 | 原文照搬 |
| 同一轮连续 3 次或最近 50 次中 10 次被拒 → 中断本轮 | 同左（PostInvocation hook 终止循环） |
| “Auto-review Denials” 面板手动放行一次 | `autoagy denials` + `autoagy approve <id>`，或直接在对话里明确同意 |

## 装它之前要知道的

**它会向 Antigravity 申请几条长期授权**——命令（Linux 上默认只授权一个一次性令牌的执行器，其他平台是 `command(*)`）、`mcp(*)`、`execute_url(*)`，加上免得读取和抓取弹窗的 `read_file(/)` 与 `read_url(*)`。之后 hook 就是唯一的闸门，而**这些授权不会跟着插件一起消失**。

**所以 `setup` 同时在 `~/.gemini/config/hooks.json` 里登记一个哨兵**（键名 `autoagy-tripwire`）。那个文件不归 `agy plugin` 管，所以插件被停用、被覆盖、或根本没装到位时它照样运行——发现插件不在，它**拒绝每一次工具调用**。宁可让 agy 全面罢工，也不让那几条授权在没人审的情况下生效。

**agy 突然什么都干不了时的出路**：跑 `autoagy status`，然后重装（`node scripts/install.mjs`）或卸载（`node scripts/install.mjs --uninstall`）。连命令都跑不了，就删掉 `~/.gemini/config/hooks.json` 里 `autoagy-tripwire` 这**一个**键——同一个文件里别的键是别人的，别动；删完紧接着卸载或重装，因为授权此刻又没人把守了。

**仍然 fail-open 的只剩两种**：哨兵被人手动删掉而授权还在；以及 Antigravity IDE／2.0——那里的授权是你在设置界面手动加的，`setup` 不写、也不为它们登记哨兵。

命令这一类可以收窄成 fail-closed（`commandGrant: "executor"`，Linux 默认就是），`mcp(*)` 和 `execute_url(*)` 没有对应办法，只靠哨兵兜着。完整清单见[参考手册](docs/reference.md#安装到底改了你机器上的什么)。

**这跟 Codex 的形状确实不同**：Codex 不需要放宽任何宿主权限，关掉 auto 模式就回到更严格的状态；autoagy 必须先放宽，所以「插件还在不在」这件事本身需要有东西盯着——哨兵就是它，`autoagy status` 会报它在不在、以及 hook 最后一次运行的时间。彻底的解法是不授予这几条通配，代价是 autoagy 大部分能力失效。

## 安装、卸载、升级

要求：Node.js ≥ 20，Antigravity CLI（`agy`）≥ 1.2。

```bash
git clone https://github.com/JXMss/autoagy autoagy && cd autoagy
node scripts/install.mjs            # 先看会改什么：node scripts/install.mjs --dry-run
```

**用 `node scripts/install.mjs`，不要只跑 `autoagy setup`。** 两者不是一回事：`setup` 只改 Antigravity 的设置（写那三条授权、钉住配置目录），它**不会把插件装到 agy 会加载的位置**。只跑 `setup` 的结果是三条授权生效、而一个 hook 都不会运行——正是本节开头那条 fail-open，自己造出来的。真发生了也能兜住：`setup` 写授权的同时一定会装哨兵，而哨兵盯的是 `~/.gemini/config/plugins/autoagy`（agy 唯一加载插件 hook 的位置），插件不在那儿就拒绝一切工具调用；`autoagy status` 也会在第一行喊出来。补救是 `agy plugin install ./plugin` 然后重跑 `autoagy setup`，或者 `autoagy teardown` 把授权收回去。

卸载（还原下面列出的全部改动并移除插件）：

```bash
node scripts/install.mjs --uninstall            # 加 --purge 同时删掉 ~/.gemini/autoagy（配置、状态、日志）
node scripts/install.mjs --uninstall --dry-run  # 只打印会撤掉什么，什么都不动
```

卸载先撤授权，撤成功了才拆别的。撤不回来的时候（通常是 `settings.json` 不是合法 JSON）它会整个停下、退出码 1：插件、哨兵和 setup 记录都原样保留——它们正是站在那几条授权后面的东西，而 setup 记录是日后还能撤回授权的唯一依据，`--purge` 也不例外。修好文件再跑一次即可。`autoagy teardown` 同理。

> 注意：不要用 `agy plugin disable autoagy` 来暂停。授权不会跟着消失，所以哨兵会因此拒绝**每一次**工具调用——这是故意的，否则绕过沙箱的命令、MCP 调用和浏览器操作会不经审核、也不弹窗直接执行。要暂停用 `autoagy mode off`（此时这三类操作会改为弹窗问你；但如果 agy 是用 `--dangerously-skip-permissions` 启动的，弹窗会被自动同意，所以那种情况下改为直接拒绝），或用 `--uninstall` 彻底卸载。

**升级**：`git pull` 之后再跑一次 `node scripts/install.mjs`。agy 没有插件更新命令（`agy plugin` 只有 `install`／`uninstall`／`enable`／`disable`／`validate` 这些），所以**任何** agy 插件都不会自己更新，autoagy 也一样。别直接用 `agy plugin install ./plugin` 升级：那样会用插件自带的、没钉住解释器的 `hooks.json` 覆盖掉已装的那份，`autoagy status` 会就此告警。

它在你机器上改了哪些文件、写了哪几条授权，逐项列在[参考手册](docs/reference.md#安装到底改了你机器上的什么)；`node scripts/install.mjs --dry-run` 会先把要改的东西打印出来。

## 平台支持

| 平台 | 自带沙箱 | 实际形态 |
| --- | --- | --- |
| **Linux + bubblewrap** | 有 | 主要目标。命令在 autoagy 自己的 bwrap 沙箱里跑：工作区和临时目录可写，`.git` 与 agent 元数据只读，凭据位置被遮盖，**没有网络**，环境按白名单重建，socket 只放 AF_UNIX。 |
| **Linux 无 bubblewrap、macOS** | 没有 | 命令留在 Antigravity 的终端沙箱里。那里 `.git` 和会话日志**可写**，所以一条命令可以植 git hook 或改审核要读的 transcript；审核模型会被告知这份 transcript 里的用户消息不可信。 |
| **Windows** | 没有 | 另外也没法清理环境（没有 `env -i`），沙箱状态推断不出来，弹窗也到不了你——所以几乎每条命令都会送审，该弹窗的地方直接变成拒绝。能用，但很重。 |
| **IDE / Antigravity 2.0** | 你自己定 | 手动加那几条授权、保持终端沙箱开着，然后在配置里写 `"sandbox": "on"`。那是一句声明，不是观测。 |

macOS 是最大的缺口：Codex 在那儿用 seatbelt 沙箱解决同一个问题，autoagy 还没有对应实现。

## 使用

装好后正常使用 `agy` 即可。建议加个别名：

```bash
alias autoagy="node ~/.gemini/config/plugins/autoagy/bin/autoagy.mjs"
```

| 命令 | 作用 |
| --- | --- |
| `autoagy status` | 查看模式、审核后端、Antigravity 设置与授权是否就绪（按设置文件里**实际有的**授权报，包括以前的 setup 留下、配置已经不要的），自带沙箱生效时还会在当前目录**真的启动一次**沙箱、报告它起不起得来（自检只比对命令行、看不到退出码，挂载被 bwrap 拒绝时只有这一步看得见），以及 **hook 最后一次运行的时间**——插件被 disable、钉子被覆盖、解释器失效，三种失效都只表现为"hooks 不再运行"，这个时间戳是唯一能从内部看到的痕迹（超过一天会明确告警） |
| `autoagy log [-n 20]` | 最近的决策（被审核的操作、结论、风险、耗时） |
| `autoagy stats [--days 7]` | 把决策日志汇总成数字：审核次数与结果（通过/拒绝/失败/超时）、审核耗时 p50/p90/最大值与总计、风险分布、按类别与工具的次数。**免审放行的操作默认不记**（`log.allowed` 打开后每个工具调用一行），所以那一栏会显示 `0` 并说明原因——这是刻意分开的两件事：`allow` 里既有"审核后放行"也有"根本不用审核" |
| `autoagy denials` | 最近被拒绝的操作及理由 |
| `autoagy approve <id>` | 对某次拒绝放行**一次重试**（审核模型会看到你的批准；critical 风险仍会拒绝） |
| `autoagy trust [<会话>] [--all] [--force]` | 解除会话的标记（[会话信任](docs/reference.md#会话信任)）、清除嵌套仓库的 hook 植入记录，并释放为它保留的只读挂载点。不带参数时只列出被标记的会话。执行前它自己会先查一次工作区锁：还有命令在跑就拒绝，`--force` 才强行释放 |
| `autoagy mode auto\|ask\|off` | `auto`=审核模型裁决；`ask`=有风险的操作弹窗问你（相当于 Codex “Ask for approval”）；`off`=不审核；上述授权覆盖的操作（绕过沙箱的命令、MCP、浏览器操作）改为弹窗问你，其余交给 Antigravity 自己的权限流程。`off` 下弹窗在 `--dangerously-skip-permissions` 里会被自动同意，所以那个模式下改为直接拒绝；不可信会话的编辑和读取也照常弹窗 |
| `autoagy review --tool run_command --args '{"CommandLine":"...","BypassSandbox":true}'` | 不启动 agent，直接测试某个操作会被怎么判 |
| `autoagy mcp-scan [--timeout 10]` | 逐个启动配置里的 MCP 服务器，问它 `tools/list`，把每个工具的只读/破坏性注解记成快照（配合 `mcp.annotations: "trust"`）。会逐条打印哪个工具声明了什么、以及连不上的服务器 |
| `autoagy setup` / `autoagy teardown` | 单独执行/撤销设置改动 |

被拒绝时，agent 会收到 Codex 的原文指令（不得绕过；只能换更安全的做法，或向你说明风险并请求明确批准）。如果你确认要做，直接在对话里说明“我确认要执行 xxx”，下一次审核会把你的明确批准计入（Codex 的 post-denial approval 规则）。

## 配置（`~/.gemini/autoagy/config.json`）

改完下一次工具调用就生效。下面是最常改的几项，[全表在参考手册](docs/reference.md#配置全表)（含 `rules`、`protectedPaths`、`credentialPaths`、`writableRoots`、MCP、浏览器、环境清理等三十多项）。

| 键 | 默认 | 作用 |
| --- | --- | --- |
| `mode` | `"auto"` | `ask` 回到弹窗，`off` 全部暂停。 |
| `ownSandbox` | `"auto"` | 自带沙箱。`"on"` 表示条件不满足时不退回 agy 的沙箱，而是把所有非只读命令送审（IDE 用户要手动设）。 |
| `commandGrant` | `"auto"` | Linux 上是只认一次性令牌的执行器（命令这一类因此 fail-closed），其他平台是 `command(*)`。 |
| `networkGrants` | `"auto"` | 自带沙箱能跑时写 `read_url(*)`，抓网页不再弹窗（每次仍先送审）；否则 `"none"`。 |
| `readGrant` | `"anywhere"` | 写 `read_file(/)`，读项目外的文件不弹窗；凭据仍然先送审。 |
| `reviewer.backend` | `"agy"` | `"openai"` 换任何 OpenAI 兼容接口，`"none"` 等于 `mode: "ask"`。 |
| `reviewer.timeoutSec` / `attemptTimeoutSec` / `maxAttempts` | `140` / `90` / `3` | 整次审核期限、单次尝试期限、尝试次数。卡住的那次会被杀掉重问，期限用完才算超时（按 `onTimeout`，默认拒绝）。 |
| `onDenied` / `onTimeout` / `onError` | 都是 `"deny"` | Codex 的行为。改成 `"ask"` 就把这一类交还给你决定。 |
| `writableRoots` | `[]` | 工作区外可免审编辑的目录（改完要重跑 `autoagy setup`）。 |

## 审核后端

默认用 **agy**：插件自带一个无工具的 `autoagy-guardian` agent，用你的 Antigravity 登录态以 headless 方式运行，无需额外 API key。模型是你 agy 当前的默认模型，推理强度 `low`。实测每次审核约 4～12 秒，每次都花你的 Antigravity 额度——它和主 agent 用的是同一个账号，所以主 agent 正忙的时候审核也会慢：连续用两天的实测里，一天的中位数 4.3 秒，另一天 9.1 秒、有 13 次落在 60～80 秒（同一台机器空载时重测仍是 2～5 秒，把 6 个核心全部跑满也只有 5 秒，所以慢的是后端而不是本机）。审核会话会出现在 `agy` 的历史里，归在 `~/.gemini/autoagy/guardian` 这个工作区下，不影响你项目里的 `agy -c`。

换审核用的模型或推理强度：

```json
{ "reviewer": { "agy": { "model": "gemini-3.8-flash-low", "effort": "low" } } }
```

`model` 填 `agy models` 输出的第一列（上面只是示例）；填错了每次审核都会失败，按拒绝处理。`effort` 可选 `low` / `medium` / `high`。

也可以换成任何 **OpenAI 兼容**接口（Chat Completions，更快但按量付费，Gemini／OpenAI／DeepSeek／本地 Ollama 都行）：配置样例和注意事项（密钥只从环境变量读、失败按拒绝处理、`jsonMode`）在[参考手册](docs/reference.md#审核后端-openai-兼容接口)。

配置改完，下一次工具调用就生效。想先试一下，可以不启动 agent，单独审一条命令：

```bash
autoagy review --tool run_command --args '{"CommandLine":"git push","BypassSandbox":true}'
```

## 决策规则与会话信任

第一层是不用模型的确定性规则（哪些动作直接放行、哪些必须送审、哪些一律拒绝），加上一条「同一会话里路径漂移过就不再免审」的围栏。两节全文都在参考手册：[决策规则](docs/reference.md#决策规则)、[会话信任](docs/reference.md#会话信任)。

## 已知限制

下面挑的是**会影响你怎么用它**的几条，设计上就存在。[完整清单在参考手册](docs/reference.md#已知限制完整清单)（20 条），还没做完、准备要修的事在 [docs/open-issues.md](docs/open-issues.md)。

- **没有启用 autoagy 自己的沙箱时**（macOS、Windows、没装 bubblewrap、IDE 没设 `ownSandbox: "on"`），沙箱内的命令仍然能写 `.git`（植入 git hook）和对话日志（伪造审核模型看到的用户消息）。autoagy 能做的只有把命令里字面出现 `.system_generated`、autoagy 自身路径或凭据位置的命令送审——这是原始命令行上的子串匹配，变量拼接或 base64 之类可以绕过，而且事后没有任何完整性校验能发现日志被改过。**这不是「和 Linux 上差不多」，而是明显更弱**，也不能靠配置补上。审核模型现在会收到一行明确的提示，知道在此配置下不能把 transcript 里的用户发言当作已确立的授权。
- **临时的工作区外编辑批准了也执行不了。** setup 设的 `allowNonWorkspaceAccess: false` 是在写入那一刻按真实落点判的，所以「帮我改一下 `~/.gitconfig`」这种事先没声明的区外编辑，即使审核模型批准，agy 仍会要一次 `write_file` 权限——交互下多一次确认，**headless 下直接失败**。autoagy 补不上这个：授权是 agy 启动时读一次就缓存的（实测），没法在批准的那一刻即时补一条。固定要写的目录请放进 `writableRoots`（会拿到自己的窄授权）；真要恢复旧行为就把 `allowNonWorkspaceAccess` 设回 `true`，代价是丢掉问题里唯一一道写入时的封顶。
- **凭据读取的审核是按路径名判的，按目录搜索就绕过去了。** `read_file .env`、`cat .env` 会送审，但 `grep_search {SearchPath: <工作区>}` 和沙箱里的 `grep -r API_KEY .` 读的是同一个文件、返回的是命中行，两者都免审。原因是 `**/.env`、`**/*.pem` 这类没有固定位置的模式列举不出来，只有 `~/.ssh/**` 这种锚定的位置才进得了「搜索的目录里包含凭据位置」这条检查。这条没有堵：Codex 根本没有 credentialPaths 这个概念（工作区文件本来就可读），而要堵住它就得审核所有全库搜索，那是 agent 最常用的操作。把工作区的 `.env` 隐藏掉也不行——那会让所有用 dotenv 的项目在沙箱里跑不起来。真正的边界仍然是「工作区内的文件 agent 都读得到」。
- Antigravity 的 hook 返回 `allow` 不能覆盖它自己的权限弹窗，hook 返回的 `permissionOverrides` 也不会授予权限（实测），所以需要上面的全局授权；对未授权域名的网页抓取仍会由 Antigravity 弹窗询问——**这是 autoagy 唯一答不上的弹窗**，也是默认配置下日常最可能剩下的那一个。要消掉它有两档（见配置表 `networkGrants`）：`"trusted-domains"` 只放开 `trustedDomains` 里那几个域名；`"all"` 授予 `read_url(*)`，任何域名都不再弹窗，每次抓取仍先经过审核（Codex 对联网请求也是交给审核）。`read_url(*)` 同时会让 agy 的终端沙箱能访问所有网站，所以一旦授予，autoagy 就**不再把 agy 的沙箱当沙箱**：在 Linux＋bwrap 上这没有代价，因为命令跑在 autoagy 自己的断网沙箱里（真机实测：抓取不弹窗、审核 3.7 秒批准；沙箱里的 `curl` 仍是 `Could not resolve host`）；在没有自带沙箱的机器上，已知只读以外的命令都会改为送审——多审核，而不是放一条能联网的命令过去。`autoagy status` 会报这台机器上它值多少代价。
- 用 `--dangerously-skip-permissions` 启动 agy 时 Antigravity 的沙箱实际不生效：启用了 autoagy 自己的沙箱时命令仍在其中运行（实测 `overwrite` 在该模式下照样生效）；否则 autoagy 按无沙箱处理，审核会变多；`force_ask` 在该模式下会被自动同意，所以 autoagy 在此模式下只使用 allow/deny——这条现在也覆盖 `mode: off` 的弹窗路径。
- **工作区里「写了之后会在沙箱外执行」的文件是免审的**：`.envrc`（direnv 自动加载）、`.husky/`（`git commit` 时执行）、`.vscode/tasks.json`、`package.json` 的 `postinstall`、`Makefile`，以及任何被别的工具读取后执行的脚本。暴露面和 `.git` 属于同一类（先写后执行），区别是 `git` 几乎必然会在沙箱外运行，而这一类要等某个工具去执行它。**Codex 在这里的取舍是同样的**——它的 workspace-write 只保护 `.git`、`.agents`、`.codex` 三个名字（`PROTECTED_METADATA_PATH_NAMES`），所以 autoagy 默认也保持这个集合（多出的 `.agent`/`_agents`/`.gemini` 是 Antigravity 自己会读的 agent 配置）。**一处例外**：`.git` 在 autoagy 自己的沙箱里是递归保护的（嵌套仓库的 `.git` 也只读），Codex 只保护每个可写根下的那一层——因为 autoagy 的编辑工具本来就挡住任何带 `.git` 段的路径，两条路不一致时弱的那条正是沙箱存在的理由。需要更严就用 `protectedPaths` 把它们加进去：在 Linux 上（autoagy 自己的沙箱生效时）它们会被**挂成只读**，沙箱里的命令根本改不动——前提是那个文件已经存在，且条目能指出具体位置（见配置表那一行）；其余情况（macOS/Windows、没有 bwrap，或 `src/**/gen*` 这类指不出位置的 glob）仍然只是「送审」。代价是 agent 每次改这些文件都要过一次审核，而挂只读的那些它改不了、只能来问你。
- **`search_web` 默认免审，而它是一条出网通道**：query 是 agent 写的文本，请求由 agy 发出，不在任何沙箱里（`--unshare-net` 只约束沙箱内的命令），策略里那套 Data Exfiltration 规则看不到它。默认放行是照 Codex 的做法：它的 web search 是托管工具，不走审批流程，由配置限制（`web_search` 模式、受管 `requirements.toml` 的 `allowed_web_search_modes`）；autoagy 对应的开关是 `webSearch: "review"`——代价是每次搜索多一次审核延迟（agy 后端实测 4～12 秒）。

## 隐私与数据流向

默认的审核后端在你自己的机器上用你的 Antigravity 登录态跑，**不往第三方发任何东西**；换成 OpenAI 兼容接口时，送出去的是精简后的对话记录加这次的动作，**只截断、不脱敏**。决策日志留在 `~/.gemini/autoagy/logs`，完整的审核 prompt 默认不存。

[完整的数据流向清单在参考手册](docs/reference.md#隐私与数据流向)：每次审核到底发出去哪些字段、哪些东西会出现在 agent 能看到的命令行里、日志里存什么。

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