# dshost-plugin

[![npm version](https://img.shields.io/npm/v/dshost-plugin.svg)](https://www.npmjs.com/package/dshost-plugin)
[![license](https://img.shields.io/npm/l/dshost-plugin.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/dshost-plugin.svg)](https://www.npmjs.com/package/dshost-plugin)
[![GitHub](https://img.shields.io/badge/GitHub-NoelJudeNoel%2Fdshost--plugin-blue)](https://github.com/NoelJudeNoel/dshost-plugin)

**DSHost 官方 DSH 远程中继插件** — 在你的 dsh（DeepSeek Harness）实例上运行一个 Agent，
通过 `wss` 主动外连 DSHost 中继，让你在世界任何地方用浏览器安全访问自己的 dsh Web UI，
无需公网 IP、无需端口映射。

*Official remote cloud relay plugin for DSHost (dshost.me): securely access your
dsh Web UI from anywhere.*

## 特性

- **零公网 IP**：Agent 主动外连中继（`wss://dshost.me/agent`），本机不开任何入站端口
- **零破坏性多版本兼容**：同时支持 dsh `0.0.1-rc.*` / `0.1.0-rc.*` / `0.1.1-*` ~ `0.1.5-*`
- **安全**：中继层 Host/Origin 重写遵守 dsh 信任栅栏；`settings.describe` 密钥脱敏下发；
  生产环境强制 `wss://`
- **随 dsh 启动**：以 cordis 插件身份随 `dsh web` 加载，自动重连、休眠省流

## 快速开始

### 1. 申请 Token

在 [dshost.me](https://dshost.me) 注册/登录（支持 GitHub OAuth），创建实例获得
`dsh_` 开头的接入 Token。

### 2. 一键安装（推荐）

```bash
# macOS / Linux
curl -fsSL https://dshost.me/install.sh | RELAY_HOST=dshost.me bash
# Windows (PowerShell)
$env:RELAY_HOST='dshost.me'; irm https://dshost.me/install.ps1 | iex
```

脚本会安装 pnpm、通过 `dsh plugin add dshost-plugin` 把插件装入当前 profile，
并写入 profile 的 `cordis.patch.yml`。

### 3. 手动安装

```bash
# 装入 dsh profile（等价于在 profile 目录执行 pnpm add dshost-plugin）
dsh plugin add dshost-plugin
```

然后在 profile 的 `cordis.patch.yml` 里声明插件（新增行必须放在 `- insert:` 块内）：

```yaml
- insert:
    - id: dshost-agent
      name: 'dshost-plugin'
      config:
        token: dsh_your_token_here
        relayUrl: wss://dshost.me/agent
        autoConnect: true
```

### 4. 重启 dsh

```bash
sudo systemctl restart dsh   # 或你的启动方式
```

启动后控制台（dshost.me）应看到实例上线。

## 配置项

| 字段 | 必填 | 说明 |
|---|---|---|
| `token` | ✔ | 中继接入 Token（`dsh_` 前缀，在 dshost.me 申请） |
| `relayUrl` | ✔ | 中继 WebSocket 地址，生产必须 `wss://` |
| `autoConnect` | ✕ | 默认 `true`；启动即连接 |
| `dshHost` / `dshPort` | ✕ | 本机 dsh web 地址，默认 `127.0.0.1:3080` |

## 兼容性

| dsh 版本 | 支持 |
|---|---|
| `0.1.5-*`（已实证 `0.1.5-rc.1`） / `0.1.4-*` / `0.1.3-*` | ✔ |
| `0.1.2-*`（含 `--trusted-host`、BrowserAuth、remote.mux） | ✔ |
| `0.1.1-*` / `0.1.0-rc.7+`（insert 块 patch 格式） | ✔ |
| `0.1.0-rc.2 ~ rc.6` / `0.0.1-rc.*` | ✔（旧包名 `@noeljude/dsh-remote-plugin` 亦可解析） |

## 仓库结构

```
├── package.json         # npm 包定义（dsh.bundle.patch 指向 cordis.patch.yml）
├── cordis.patch.yml     # bundle patch（有意为空：插件入口由用户 profile 声明）
├── lib/index.js         # 插件入口（cordis apply）
├── agent/core.js        # Agent 引擎（与独立 agent 共享的唯一源）
├── common/protocol.js   # 中继协议
└── scripts/prepack.mjs  # npm pack 时物化 lib/core.js + lib/protocol.js
```

`prepack.mjs` 是布局自适应的：在本 monorepo（源码位于 `src/agent`、`src/common`）与
本仓库独立检出（`agent/`、`common/` 位于包根）下均可运行，支持
`npm i github:NoelJudeNoel/dshost-plugin` 的 git 直装（经 `prepare` 构建）。

## 发布流程

npm 与 GitHub 同步发布：改动主仓源码 → bump `version` → `npm publish` →
`bash scripts/publish-github.sh`（同步 GitHub、打 `vX.Y.Z` tag、刷新 topics）。
完整标准规则见 [`docs/github-release-sop.md`](./docs/github-release-sop.md)。

## License

[MIT](./LICENSE) © 2026 dsh-remote contributors
