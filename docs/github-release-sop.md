# DSH 插件 GitHub 同步发布 SOP（标准流程）

> 适用：dshost-plugin 及今后所有自研 DSH 插件。
> 原则：**npm 与 GitHub 同步发布**——npm 是运行时分发渠道，GitHub 是代码托管/
> 问题反馈/版本档案渠道；两者版本号必须一致（git tag `vX.Y.Z` == npm `version`）。

## 1. 单一事实源与仓库布局

| 内容 | 位置 |
|---|---|
| 插件源码（唯一修改处） | dshost 主仓 `src/plugin/`（包定义）+ `src/agent/core.js` + `src/common/protocol.js` |
| GitHub 独立仓库 | `github.com/NoelJudeNoel/dshost-plugin`（公开，包根==仓库根） |
| 本地 staging clone | `/root/publish/dshost-plugin/`（脚本维护，勿手工改） |
| GitHub PAT | `/root/.config/dshost/github-token`（600，仅 API 用；git 推送走 SSH） |

同步脚本 `scripts/publish-github.sh` 把主仓源码物化成独立仓库布局
（`agent/`、`common/` 平铺在包旁），`scripts/prepack.mjs` 布局自适应，
两种检出下都能构建 `lib/`。

## 2. 发布标准规则（每次发布必查）

**package.json 必备字段**
- `name` / `version`（semver；发布即 bump）/ `description`（一句话说清是什么）
- `license`（MIT）+ `files`（`lib`、`cordis.patch.yml`、`scripts`）
- `dsh.bundle.patch` → `./cordis.patch.yml`（dsh 插件识别标记）
- `engines.node`（跟随 dsh 要求，当前 `>=22.5.0`）
- `repository` / `bugs` / `homepage`（指向 GitHub 仓库 / dshost.me）
- `keywords`（同时作为 GitHub topics：`dsh` `dsh-plugin` `cordis` 等，小写连字符）
- `prepare` 脚本（dsh 支持 git 直装：`pnpm add github:NoelJudeNoel/<repo>` 安装时经 prepare 构建）

**cordis.patch.yml**
- 插件自带的 bundle patch 保持**空数组**；插件入口（`- id: ...` + `config`）由
  用户 profile 的 patch 以 `- insert:` 声明。两边都声明会导致 loader 重复 id →
  dsh 启动崩溃（历史教训，勿回退）。

**git 标签**
- 每次发布打**annotated tag** `v<version>`，与 package.json 严格一致；
  同版本不重发、不挪 tag，修正内容必须 bump。

**README**
- 徽章（npm version / license / node / GitHub）、一句话定位、特性、
  快速开始（申请 token → 安装 → profile patch 示例 → 重启）、配置项表、
  兼容性矩阵、安全说明、仓库结构、发布流程、License。

**安全（发布前硬性检查）**
- 暂存树扫描真实凭据格式（`dsh_`/`ghp_`/`github_pat_`/`sk-`），命中即终止；
  示例配置一律用 `dsh_your_token_here` 占位。

## 3. 标准操作流程

```bash
# ① 改代码（只改主仓）：src/agent、src/plugin、src/common
# ② bump 版本：src/plugin/package.json 的 "version"
cd /root/dshost
# ③ npm 发布（prepack 自动物化 lib/）
cd src/plugin && npm publish && cd -
# ④ GitHub 同步（建库/元数据/topics/同步/tag/推送，全幂等）
bash scripts/publish-github.sh
# ⑤ 验证
npm view dshost-plugin version           # npm 侧版本
curl -s https://api.github.com/repos/NoelJudeNoel/dshost-plugin/tags | head
# git 直装冒烟（可选但推荐）
tmp=$(mktemp -d) && cd $tmp && npm i github:NoelJudeNoel/dshost-plugin && ls node_modules/dshost-plugin/lib/
```

## 4. 排障

- **clone 失败/推送 403**：检查 `ssh -T git@github.com` 是否返回 NoelJudeNoel。
- **API 401/403**：token 过期或无 repo 权限 → 更新 `/root/.config/dshost/github-token`。
- **tag 已存在但内容有变**：不要 `tag -f`；bump 版本重走流程。
- **同步后 npm 侧还是旧 metadata**：repository/keywords 等字段随**下一次**
  npm publish 生效（同版本号无法重发）。
