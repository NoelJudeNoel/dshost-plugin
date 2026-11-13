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
  生产环境强制 `wss://`；WebRTC 数据面走 DTLS 端到端加密，中继仅见信令
- **随 dsh 启动**：以 cordis 插件身份随 `dsh web` 加载，自动重连、休眠省流

## 传输模式

`dshost-plugin ≥ 0.1.22` 搭配最新 dshost.me 中继时，浏览器与本机 dsh 自动选择链路（无感回落）：

- **WebRTC P2P 直连（默认优先）**：浏览器 ↔ Agent 一条 DataChannel（DTLS 端到端加密）直传
  `/api/*` 流量；中继仅交换 SDP 信令、读不到明文。对称 NAT 打洞失败自动回落加密中继
- **局域网 / VPN（EasyTier · Tailscale）自动直连**：同一 WiFi / 局域网 / mesh 网段可达时，
  自动走 WebRTC host 候选直连（0 中继流量，通常 <5ms），无需任何配置
- **应用层分片（plugin ≥ 0.1.25）**：SCTP 单帧超限（`max-message-size`）时按 32KB
  切片重传，大会话 `snapshot` 超 256KB 也能完整加载（hello/auth 的 `features:['chunk']` 能力协商，老端保持旧行为）
- **公网中继（自动回退）**：TLS + WSS（dshost.me 边缘节点），任意网络可达

手动控制：URL 参数 `transport=webrtc` 只走 P2P（失败即断开，不偷偷降级）；
`transport=relay` 强制只走中继；缺省 = 自动。单活跃浏览器规则（仅最近活跃浏览器
保留实时流）在 P2P 模式下同样生效。

*Transport modes (plugin ≥ 0.1.22, with the current dshost.me relay).*

- **WebRTC P2P (preferred, automatic)**: browser ↔ agent DataChannel (DTLS E2E)
  carries `/api/*`; the relay only exchanges SDP and cannot read payloads.
  Hole-punch failure falls back to the encrypted relay transparently.
- **LAN / VPN (EasyTier · Tailscale) direct**: when the browser and the instance
  share a reachable LAN/mesh segment, ICE host candidates connect directly
  (0 relay bytes, typically <5ms). No configuration needed.
- **App-level chunking (plugin ≥ 0.1.25)**: frames exceeding SCTP `max-message-size`
  are split into 32KB slices and reassembled (`dc:chunk`), so long-session
  snapshots (>256KB) load completely. Negotiated via `hello` / `auth` `features:['chunk']`;
  legacy peers keep the old behaviour.
- **Public relay (automatic fallback)**: TLS + WSS via dshost.me edge nodes.

Force a mode via URL param: `transport=webrtc` (P2P only) or `transport=relay`
(relay only). The default is automatic. The single-active-browser rule applies
in P2P mode too — a superseded session's PeerConnection is revoked by the agent.

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
