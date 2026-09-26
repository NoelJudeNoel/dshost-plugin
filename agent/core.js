// Shared agent core used by both the standalone agent (src/agent/dsh-remote.js)
// and the dsh plugin (src/plugin/lib/index.js). Keeps the two entry points
// thin so the forwarding/robustness logic cannot drift between them.

import http from 'http';
import os from 'os';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { execFileSync } from 'child_process';
import WebSocket from 'ws';
import { send, b64, un64, sanitizeCloseCode } from '../common/protocol.js';

// ── Backpressure / robustness limits ─────────────────────────────────
const MAX_WS_BUFFERED_BYTES = parseInt(process.env.MAX_WS_BUFFERED_BYTES || String(16 * 1024 * 1024), 10);
const MAX_PENDING_FRAMES = 1024;      // frames buffered while local WS connects
const LOCAL_WS_CONNECT_TIMEOUT_MS = 15000; // give up if local dsh WS never opens
const WS_SEND_HIGH_WATER = parseInt(process.env.WS_SEND_HIGH_WATER || String(8 * 1024 * 1024), 10);
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS = 60000;

/** First non-internal IPv4 of this host (for the dashboard), or null. */
function localIPv4() {
  try {
    for (const addrs of Object.values(os.networkInterfaces())) {
      for (const a of addrs || []) {
        if (a.family === 'IPv4' && !a.internal) return a.address;
      }
    }
  } catch {}
  return null;
}

// Stable per-process instance id. MUST NOT change across reconnects: the
// relay binds sessions/tickets to an instanceId, and a random id per
// registration made the binding go stale the moment the agent reconnected
// (user saw an offline page for an online host).
let cachedInstanceId = null;
function getInstanceId() {
  if (cachedInstanceId) return cachedInstanceId;
  // 稳定实例 ID：hostname + systemd machine-id 的哈希前缀。machine-id 由系统
  // 安装时生成、跨重启持久 —— 此前两版（纯随机 / 首个MAC哈希）分别败于 agent
  // 重启与 Docker/虚拟网卡导致的 MAC 集合变化，都会让浏览器标签页的实例引用
  // 失效并触发 503 重试风暴。同名主机由 machine-id 区分。
  let mid = '';
  for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) {
    try {
      const s = fs.readFileSync(f, 'utf8').trim();
      if (s) { mid = s; break; }
    } catch {}
  }
  if (!mid) {
    // 无 machine-id 的兜底：全部非内部 MAC 的联合哈希（排序拼接，不依赖
    // 枚举顺序与单个网卡的存在性）
    try {
      const macs = [];
      for (const addrs of Object.values(os.networkInterfaces())) {
        for (const a of addrs || []) {
          if (a && !a.internal && a.mac && a.mac !== '00:00:00:00:00:00') macs.push(a.mac);
        }
      }
      mid = 'mac:' + macs.sort().join(',');
    } catch {}
  }
  const h = crypto.createHash('sha256').update(os.hostname() + '|' + mid).digest('hex');
  cachedInstanceId = os.hostname() + '-' + parseInt(h.slice(0, 8), 16).toString(36).slice(0, 4);
  return cachedInstanceId;
}

/**
 * Effective instance id. DSH_INSTANCE_ID (env) overrides the derived id —
 * used when a dedicated services agent coexists with the dsh-hosted plugin
 * on the SAME machine: both derive the identical hostname+machine-id id,
 * and the relay would treat them as one instance, evicting each other in a
 * reconnect war. The override must be stable across restarts (it is the
 * key sessions/tickets bind to).
 */
function getEffectiveInstanceId() {
  const override = (process.env.DSH_INSTANCE_ID || '').trim();
  if (override && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(override)) return override;
  return getInstanceId();
}

/**
 * Collect every real disk partition (df -kPT), not just the root filesystem.
 * Filters to physical filesystems (/dev/* or common on-disk types), excludes
 * tmpfs/proc/sys/overlay etc. Falls back to statfsSync('/') if df is missing
 * or yields nothing (e.g. minimal containers).
 */
function collectDisks() {
  let disks = [];
  try {
    const out = execFileSync('df', ['-kPT'], { encoding: 'utf8' });
    const lines = out.trim().split('\n');
    for (let i = 1; i < lines.length; i++) {
      const parts = lines[i].trim().split(/\s+/);
      const [dev, type, blocks, used, avail, , mount] = parts;
      if (!dev || !type || !mount) continue;
      const isReal = (dev.startsWith('/dev/') && !dev.startsWith('/dev/loop'))
        || /^(ext[234]|xfs|btrfs|zfs|vfat|ntfs|exfat|hfsplus|apfs|f2fs|jfs|reiserfs)$/.test(type);
      if (!isReal) continue;
      disks.push({
        mount,
        total: parseInt(blocks || 0) * 1024,
        used: parseInt(used || 0) * 1024,
        free: parseInt(avail || 0) * 1024,
      });
    }
  } catch {}
  // Fallback: single root partition via statfs
  if (disks.length === 0) {
    try {
      const s = fs.statfsSync('/');
      const total = Number(s.blocks) * Number(s.bsize);
      const free = Number(s.bavail) * Number(s.bsize);
      disks = [{ mount: '/', total, used: total - free, free }];
    } catch {}
  }
  return disks;
}

/**
 * Locate the dsh runtime this agent actually serves and reports.
 *
 * dsh >= 0.1.2 installs are frequently built from a source checkout with
 * /usr/bin/dsh symlinked into it (e.g. /root/dsh-src/apps/cli/lib/bin.js),
 * which leaves the historical hardcoded npm-global package.json stale the
 * moment the host upgrades — the dashboard then keeps showing the previous
 * release's version forever. Resolution order:
 *   1. DSH_VERSION env var (explicit pin / tests)
 *   2. the CLI entry that started this process (the plugin runs inside
 *      `dsh web`, so process.argv[1] IS the runtime, symlink included)
 *   3. the first `dsh` executable on PATH (standalone agent / manual runs)
 *   4. legacy npm global install path (dsh <= 0.1.1 behavior)
 * Only a package.json of the dsh package itself is accepted while walking
 * up, so an unrelated ancestor package (this repo's own package.json among
 * them) can never be mistaken for the runtime.
 * @returns {{version?: string, root?: string}}
 */
function findDshRuntime() {
  if (process.env.DSH_VERSION) return { version: process.env.DSH_VERSION };
  const entryPoints = [];
  const pushEntry = (p) => { try { entryPoints.push(fs.realpathSync(p)); } catch {} };
  if (process.argv[1]) pushEntry(process.argv[1]);
  try {
    for (const dir of (process.env.PATH || '').split(path.delimiter)) {
      if (!dir) continue;
      const bin = path.join(dir, 'dsh');
      let st = null;
      try { st = fs.statSync(bin); } catch { continue; }
      if (st.isFile()) { pushEntry(bin); break; }
    }
  } catch {}
  for (const entry of entryPoints) {
    let dir = path.dirname(entry);
    for (let depth = 0; depth < 8; depth++) {
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
        const name = pkg.name || '';
        if (pkg.version && (name === '@deepseek-ai/dsh' || name === 'dsh' || name.startsWith('@deepseek-ai/dsh'))) {
          return { version: pkg.version, root: dir };
        }
      } catch {}
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  try {
    const legacyRoot = '/usr/lib/node_modules/@deepseek-ai/dsh';
    const pkg = JSON.parse(fs.readFileSync(path.join(legacyRoot, 'package.json'), 'utf8'));
    if (pkg.version) return { version: pkg.version, root: legacyRoot };
  } catch {}
  return {};
}

/** Version of <name> as installed under <rootDir>/node_modules, or ''. */
function pluginVersionAt(rootDir, name) {
  try {
    return JSON.parse(fs.readFileSync(path.join(rootDir, 'node_modules', name, 'package.json'), 'utf8')).version || '';
  } catch { return ''; }
}

/** Automatically detect local DSH runtime metadata (version + installed profile plugins with exact versions) */
function detectDshMetadata() {
  const runtime = findDshRuntime();
  const dshVersion = runtime.version || '0.1.0-rc.7';
  // Where bundled dsh plugins may live: the runtime package itself plus the
  // workspace roots above it (source-checkout / pnpm layouts hoist deps to
  // the repo root), then the legacy npm global install.
  const dshModuleRoots = [];
  if (runtime.root) {
    let dir = runtime.root;
    for (let depth = 0; depth < 3; depth++) {
      dshModuleRoots.push(dir);
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  dshModuleRoots.push('/usr/lib/node_modules/@deepseek-ai/dsh');
  let plugins = [];
  try {
    const profileDir = os.homedir() + '/.dsh/profiles/web';
    const profilePkgPath = profileDir + '/package.json';
    if (fs.existsSync(profilePkgPath)) {
      const profilePkg = JSON.parse(fs.readFileSync(profilePkgPath, 'utf8'));
      const deps = Object.keys(profilePkg.dependencies || {});
      const bundles = profilePkg.dsh?.profile?.bundles || [];
      const allNames = Array.from(new Set([...bundles, ...deps]));

      plugins = allNames.map(name => {
        let ver = '';
        // 1. Check profile node_modules
        try {
          const p1 = profileDir + '/node_modules/' + name + '/package.json';
          if (fs.existsSync(p1)) ver = JSON.parse(fs.readFileSync(p1, 'utf8')).version || '';
        } catch {}
        // 2. Check dsh runtime node_modules (npm global / source checkout)
        if (!ver) {
          for (const root of dshModuleRoots) {
            ver = pluginVersionAt(root, name);
            if (ver) break;
          }
        }
        // 3. Check global node_modules
        if (!ver) {
          try {
            const p3 = '/usr/lib/node_modules/' + name + '/package.json';
            if (fs.existsSync(p3)) ver = JSON.parse(fs.readFileSync(p3, 'utf8')).version || '';
          } catch {}
        }
        // 4. Fallback to package.json dependency declaration
        if (!ver && profilePkg.dependencies && profilePkg.dependencies[name]) {
          ver = String(profilePkg.dependencies[name]).replace(/^[\^~>=<]/, '');
        }
        return { name, version: ver ? 'v' + ver : '' };
      });
    }
  } catch {}
  return { dshVersion, plugins };
}

/** Collect local system info for the relay dashboard. */
export function collectSystemInfo(defaultVersion) {
  const disks = collectDisks();
  const diskTotal = disks.reduce((a, d) => a + d.total, 0);
  const diskUsed = disks.reduce((a, d) => a + d.used, 0);
  const diskFree = disks.reduce((a, d) => a + d.free, 0);
  const cpus = os.cpus();
  const meta = detectDshMetadata();
  return {
    instanceId: getEffectiveInstanceId(),
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    ip: localIPv4(),
    cpuModel: cpus[0]?.model || '',
    cpuCores: cpus.length,
    loadAvg: os.loadavg(),
    totalMem: os.totalmem(),
    freeMem: os.freemem(),
    disks,
    diskTotal,
    diskUsed,
    diskFree,
    dshVersion: defaultVersion || meta.dshVersion,
    plugins: meta.plugins,
    // 服务旁挂：独立 services agent（DSH_SERVICES_ONLY=1，无本地 dsh 承载）
    // 上报 role=services，relay 不将其注册为主实例，只挂到同 hostname 的主实例下
    role: process.env.DSH_SERVICES_ONLY === '1' ? 'services' : 'dsh',
    // 无头检测：供 relay 注入脚本决定产物点击行为(新窗口HTTP直出 vs 本地打开)
    headless: !process.env.DISPLAY && !process.env.WAYLAND_DISPLAY,
  };
}

// ── Plugin workspace services（config.services）───────────────────────
// 实例在 cordis.patch.yml（插件配置）或 standalone agent 的 DSH_SERVICES env
// JSON 中声明的本地/内网上游清单。relay 只能经本 agent 隧道触达这些上游。
// 安全关键：上游白名单在此强制 —— 回环 + EasyTier mesh 10.144.144.0/24 +
// AGENT_UPSTREAM_ALLOW 显式追加。被攻破的 relay 也无法借隧道横移到宿主者
// 未声明的任意内网地址；仅接受字面 IP（localhost 归一为 127.0.0.1），
// 不做 DNS 解析，杜绝 DNS rebinding 绕过白名单。
const SVC_ID_RE = /^[a-z0-9][a-z0-9_-]{0,31}$/;

function parseUpstream(raw) {
  const m = /^(.+):(\d{1,5})$/.exec(String(raw || '').trim());
  if (!m) return null;
  const host = m[1].toLowerCase() === 'localhost' ? '127.0.0.1' : m[1];
  const port = parseInt(m[2], 10);
  if (!/^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+$/i.test(host)) return null;
  if (port < 1 || port > 65535) return null;
  return { host, port };
}

function upstreamAllowed(host) {
  if (host === '::1' || /^127\./.test(host)) return true;
  if (/^10\.144\.144\./.test(host)) return true; // EasyTier wolo-mesh 网段
  const extra = (process.env.AGENT_UPSTREAM_ALLOW || '').split(',').map((s) => s.trim()).filter(Boolean);
  return extra.includes(host);
}

/**
 * Normalize + validate the declared services list. Invalid entries are
 * skipped with a warning, never thrown — one bad line must not take down
 * the dsh remote tunnel.
 * @returns {Array<{id,name,desc,icon,auth,entry,ssoSecret,host,port}>}
 */
export function normalizeServices(raw, log) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  const seen = new Set();
  for (const s of raw) {
    if (!s || typeof s !== 'object') continue;
    const id = String(s.id || '').trim();
    const up = parseUpstream(s.upstream);
    if (!SVC_ID_RE.test(id) || id === 'dsh') {
      log?.warn?.(`[agent] service "${id || '(unnamed)'}": invalid/reserved id, skipped`);
      continue;
    }
    if (seen.has(id)) continue;
    if (!up) {
      log?.warn?.(`[agent] service "${id}": bad upstream "${s.upstream}" (want host:port), skipped`);
      continue;
    }
    if (!upstreamAllowed(up.host)) {
      log?.warn?.(`[agent] service "${id}": upstream ${up.host} not in allowlist (loopback / 10.144.144.0/24 / AGENT_UPSTREAM_ALLOW), skipped`);
      continue;
    }
    seen.add(id);
    out.push({
      id,
      name: String(s.name || id).slice(0, 64),
      desc: String(s.desc || '').slice(0, 200),
      icon: String(s.icon || '').slice(0, 32),
      auth: s.auth === 'sso' ? 'sso' : 'open',
      entry: typeof s.entry === 'string' && s.entry.startsWith('/') ? s.entry : '/',
      ssoSecret: typeof s.ssoSecret === 'string' && s.ssoSecret ? s.ssoSecret : '',
      spa: s.spa === true,
      basicUser: typeof s.basicUser === 'string' ? s.basicUser : '',
      basicPassword: typeof s.basicPassword === 'string' ? s.basicPassword : '',
      host: up.host,
      port: up.port,
    });
  }
  return out;
}

/**
 * Start the agent connection loop.
 * @param {object} opts
 * @param {string} opts.token        agent registration token
 * @param {string} opts.relayUrl     relay WebSocket URL (wss:// in production)
 * @param {string} [opts.version]    agent version reported at registration
 * @param {string} [opts.dshHost]    local dsh host (default 127.0.0.1)
 * @param {number} [opts.dshPort]    local dsh port (default 3080)
 * @param {string} [opts.webToken]   local dsh web launch token (dsh >= 0.1.2 auth mode)
 * @param {object} [opts.log]        logger with log/warn/error (default console)
 * @param {string} [opts.dshVersion] reported dsh version (default rc.6)
 * @param {Array}  [opts.services]   plugin workspace services (see normalizeServices)
 * @returns {{ stop: () => void }}
 */
export function startAgent(opts) {
  const {
    token,
    relayUrl,
    version = '0.1.0',
    dshHost = '127.0.0.1',
    dshPort = 3080,
    log = console,
    dshVersion,
    services = [],
  } = opts;

  const svcList = normalizeServices(services, log);
  const svcMap = new Map(svcList.map((s) => [s.id, s]));
  let relayUsername = null; // set on 'registered'; subject of SSO trust headers
  if (svcList.length) {
    log.log?.(`[agent] plugin services: ${svcList.map((s) => `${s.id}->${s.host}:${s.port}${s.auth === 'sso' ? ' (sso)' : ''}`).join(', ')}`);
  }

  if (!token) {
    log.error?.('[agent] No token configured.');
    return { stop() {} };
  }
  if (process.env.NODE_ENV === 'production' && !relayUrl.startsWith('wss://')) {
    log.error?.('[agent] FATAL: NODE_ENV=production requires a wss:// relayUrl (got ' + relayUrl + ')');
    return { stop() {} };
  }

  // ── Local web auth (dsh >= 0.1.2 one-time launch token → signed cookie) ──
  // dsh 0.1.2 gates its web UI behind a per-process launch token: GET
  // /?token=X mints a signed authority-bound browser cookie, everything else
  // 401s. When the plugin runs inside the dsh host process it hands us the
  // live token via setWebToken() (see plugin index.js ctx.inject hook);
  // standalone agents can use DSH_WEB_TOKEN. With a token on file we mint a
  // cookie once and inject it into proxied HTTP/WS requests; a 401 drops the
  // cookie and re-mints (covers dsh restarts rotating the token). On
  // dsh <= 0.1.1 there is no web auth: with no token source nothing is
  // injected and behavior is identical to plugin 0.1.5 (ApiProxy era).
  let webToken = opts.webToken || process.env.DSH_WEB_TOKEN || null;
  let authCookie = null;
  let minting = null;

  function mintAuthCookie() {
    if (minting) return minting;
    if (!webToken) return Promise.resolve(null);
    minting = new Promise((resolve) => {
      const req = http.get(
        `http://${dshHost}:${dshPort}/?token=${encodeURIComponent(webToken)}`,
        { timeout: 5000 },
        (res) => {
          res.resume();
          const set = res.headers['set-cookie'];
          if (res.statusCode === 303 && Array.isArray(set) && set[0]) {
            authCookie = set[0].split(';')[0];
            log.log?.('[agent] local web auth cookie minted');
            resolve(authCookie);
          } else {
            log.warn?.(`[agent] local web auth mint failed (HTTP ${res.statusCode})`);
            resolve(null);
          }
        },
      );
      req.on('timeout', () => req.destroy(new Error('mint timeout')));
      req.on('error', (err) => {
        log.warn?.(`[agent] local web auth mint error: ${err.message}`);
        resolve(null);
      });
    });
    minting.then(() => { minting = null; }, () => { minting = null; });
    return minting;
  }

  function setWebToken(token) {
    if (!token || token === webToken) return;
    webToken = token;
    authCookie = null;
    log.log?.('[agent] web launch token acquired (dsh 0.1.2 auth mode)');
    mintAuthCookie();
  }

  if (webToken) mintAuthCookie();

  const streams = new Map();
  let registered = false;
  let reconnectTimer = null;
  let heartbeatInterval = null;
  let reconnectAttempt = 0;

  function connect() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }

    log.log?.(`[agent] Connecting to ${relayUrl} ...`);
    const ws = new WebSocket(relayUrl);

    // 握手超时看门狗：如果 WS open 事件在 20s 内未到达（TCP 连上但 upgrade
    // 响应丢失——WiFi 恢复期/代理链路抖动时常见），主动 terminate 触发 close
    // → 重连，避免永久挂死在 CONNECTING 状态（旧逻辑的致命缺陷：startHeartbeat
    // 只在 registered 后启动，握手挂死时无任何看门狗看管新连接）。
    const handshakeTimer = setTimeout(() => {
      if (ws.readyState === WebSocket.CONNECTING) {
        log.log?.('[agent] handshake timeout (20s, no WS open), forcing reconnect');
        try { ws.terminate(); } catch (eT) {}
      }
    }, 20000);

    ws.on('open', () => {
      clearTimeout(handshakeTimer);
      log.log?.('[agent] Connected to relay');
      send(ws, { type: 'register', token, version });
    });

    ws.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }

      if (msg.type === 'registered') {
        registered = true;
        reconnectAttempt = 0;
        relayUsername = msg.username || null;
        log.log?.(`[agent] Registered as ${msg.username} (session ${msg.sessionId || ''})`);
        send(ws, { type: 'system-info', info: collectSystemInfo(dshVersion) });
        // 插件工作区：上报本实例声明的服务清单（relay 存实例维度，供 /p 路由校验）
        // DSH_SERVICES_ONLY=1：独立 services agent，relay 不注册主实例（服务旁挂到同机 dsh 实例）
        send(ws, {
          type: 'services',
          servicesOnly: process.env.DSH_SERVICES_ONLY === '1' || undefined,
          services: svcList.map(({ id, name, desc, icon, auth, entry, spa }) => ({ id, name, desc, icon, auth, entry, spa })),
        });
        startHeartbeat(ws);
        return;
      }

      if (msg.type === 'heartbeat') return;

      if (msg.type === 'http:request') {
        // [Artifact Viewer] 是 dsh UI 注入脚本的专属旁路；插件流不经过它。
        if (!msg.target && serveArtifactIfRequested(ws, msg)) return;
        handleHttpRequest(ws, msg);
      } else if (msg.type === 'http:body') {
        const ab = artifactFormBodies.get(msg.streamId);
        if (ab) { ab.push(un64(msg.data)); return; }
        const stream = streams.get(msg.streamId);
        if (stream && stream.dshReq) stream.dshReq.write(un64(msg.data));
      } else if (msg.type === 'http:end') {
        const ab = artifactFormBodies.get(msg.streamId);
        if (ab) { artifactFormBodies.delete(msg.streamId); serveArtifactFromForm(ws, msg.streamId, Buffer.concat(ab)); return; }
        const stream = streams.get(msg.streamId);
        if (stream && stream.dshReq) stream.dshReq.end();
      } else if (msg.type === 'ws:open') {
        // dsh >= 0.1.2: make sure the auth cookie exists before the upgrade
        // （仅 dsh 目标需要本地 web auth cookie；插件上游不做 cookie 注入）。
        if ((!msg.target || msg.target === 'dsh') && (webToken || authCookie) && !authCookie) {
          mintAuthCookie().then(() => handleWsOpen(ws, msg));
        } else {
          handleWsOpen(ws, msg);
        }
      } else if (msg.type === 'ws:frame') {
        const stream = streams.get(msg.streamId);
        if (stream && stream.dshWs) {
          if (stream.dshWs.readyState === WebSocket.OPEN) {
            if (stream.dshWs.bufferedAmount > MAX_WS_BUFFERED_BYTES) {
              log.warn?.(`[agent] ws stream ${msg.streamId} slow local consumer, closing`);
              stream.dshWs.close(1013, 'Slow consumer');
              send(ws, { type: 'ws:close', streamId, code: 1013, reason: 'Slow consumer' });
              streams.delete(msg.streamId);
              return;
            }
            if (msg.binary) {
              stream.dshWs.send(un64(msg.data), { binary: true });
            } else {
              stream.dshWs.send(msg.data);
            }
          } else if (stream.dshWs.readyState === WebSocket.CONNECTING && stream.pending) {
            if (stream.pending.length >= MAX_PENDING_FRAMES) {
              log.warn?.(`[agent] ws stream ${msg.streamId} pending buffer overflow, closing`);
              stream.dshWs.terminate();
              send(ws, { type: 'ws:close', streamId, code: 1013, reason: 'Pending overflow' });
              streams.delete(msg.streamId);
              return;
            }
            stream.pending.push({ data: msg.data, binary: msg.binary });
          }
        }
      } else if (msg.type === 'ws:close') {
        const stream = streams.get(msg.streamId);
        if (stream && stream.dshWs) {
          stream.dshWs.close(sanitizeCloseCode(msg.code), typeof msg.reason === 'string' ? msg.reason : '');
        }
        streams.delete(msg.streamId);
      }
    });

    ws.on('close', (code, reason) => {
      clearTimeout(handshakeTimer);
      if (heartbeatInterval) { clearInterval(heartbeatInterval); heartbeatInterval = null; }
      log.log?.(`[agent] Disconnected (${code}): ${reason}`);
      registered = false;
      for (const [, stream] of streams) {
        if (stream.dshReq) stream.dshReq.destroy();
        if (stream.dshWs) stream.dshWs.close();
      }
      streams.clear();
      // Exponential backoff 1s -> 60s with jitter
      const delay = Math.min(RECONNECT_BASE_MS * Math.pow(2, reconnectAttempt), RECONNECT_MAX_MS) + Math.random() * 1000;
      reconnectAttempt += 1;
      log.log?.(`[agent] Reconnecting in ${Math.round(delay / 1000)}s (attempt ${reconnectAttempt}) ...`);
      reconnectTimer = setTimeout(connect, delay);
    });

    ws.on('error', (err) => {
      clearTimeout(handshakeTimer);
      log.error?.(`[agent] WS Error: ${err.message}`);
      ws.close();
    });
  }

  function startHeartbeat(ws) {
    if (heartbeatInterval) clearInterval(heartbeatInterval);
    // 半开死链看门狗：只发不收时 TCP 仍 ESTAB（FIN 被代理链路吞掉的场景），
    // close 事件永远不来，agent 变僵尸。每次 ping 记账，收到任意下行帧清零；
    // 连续 3 个周期（45s）无下行则主动 terminate() 触发重连。
    let lastRx = Date.now();
    ws.on('message', () => { lastRx = Date.now(); });
    heartbeatInterval = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      send(ws, { type: 'heartbeat', ts: Date.now() });
      if (Date.now() - lastRx > 45000) {
        log.log?.('[agent] heartbeat watchdog: no inbound for 45s, forcing reconnect');
        try { ws.terminate(); } catch (eT) {}
      }
    }, 15000);
  }

  // [Artifact Viewer] 无头机产物 HTTP 直出：GET /api/host.artifact?path=...
  // 由注入脚本在浏览器劫持 openPath 点击后以新窗口打开 —— 无显示环境无法
  // "本地打开"，改为把文本/代码类产物以对应 MIME 直出给浏览器渲染。
  const ARTIFACT_TEXT_EXT = new Set([
    '.md', '.markdown', '.txt', '.log', '.json', '.yml', '.yaml', '.toml', '.ini',
    '.cfg', '.conf', '.env', '.csv', '.tsv', '.js', '.mjs', '.cjs', '.ts', '.tsx',
    '.jsx', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.c', '.h', '.cpp', '.hpp',
    '.cs', '.php', '.sh', '.bash', '.zsh', '.sql', '.html', '.htm', '.css', '.scss',
    '.less', '.vue', '.svelte', '.swift', '.lua', '.r', '.pl', '.xml', '.svg',
  ]);
  const ARTIFACT_MIME = {
    '.md': 'text/markdown; charset=utf-8', '.markdown': 'text/markdown; charset=utf-8',
    '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8', '.scss': 'text/x-scss; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
    '.cjs': 'text/javascript; charset=utf-8', '.ts': 'text/typescript; charset=utf-8',
    '.tsx': 'text/typescript; charset=utf-8', '.jsx': 'text/typescript; charset=utf-8',
    '.json': 'application/json; charset=utf-8', '.xml': 'application/xml; charset=utf-8',
    '.svg': 'image/svg+xml', '.py': 'text/x-python; charset=utf-8',
    '.sh': 'text/x-shellscript; charset=utf-8', '.bash': 'text/x-shellscript; charset=utf-8',
    '.csv': 'text/csv; charset=utf-8', '.yml': 'text/yaml; charset=utf-8',
    '.yaml': 'text/yaml; charset=utf-8', '.sql': 'text/x-sql; charset=utf-8',
  };
  const ARTIFACT_MAX_BYTES = 2 * 1024 * 1024;

  function artifactRespond(ws, streamId, status, headers, body) {
    send(ws, { type: 'http:response', streamId, status, headers });
    if (body) send(ws, { type: 'http:data', streamId, data: b64(body) });
    send(ws, { type: 'http:end', streamId });
  }

  const artifactFormBodies = new Map();

  function serveArtifactFromForm(ws, sid, body) {
    let pth = '';
    const ct = 'application/x-www-form-urlencoded';
    try { pth = new URLSearchParams(body.toString('utf8')).get('path') || ''; } catch {}
    serveArtifactResolved(ws, sid, pth);
  }

  function serveArtifactResolved(ws, sid, rawPath) {
    const fail = (status, text) => artifactRespond(ws, sid, status,
      { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
      Buffer.from(JSON.stringify({ ok: false, error: { code: 'artifact', message: text } })));
    return serveArtifactFile(ws, sid, rawPath, fail);
  }

  function serveArtifactIfRequested(ws, msg) {
    let u;
    try { u = new URL(msg.path, 'http://local'); } catch { return false; }
    if (u.pathname !== '/api/host.artifact') return false;
    const sid = msg.streamId;
    if (msg.method === 'POST') {
      // [EO规避] 该URL的GET响应会被EdgeOne静默吞杀(三出口实测)，改走POST表单体
      artifactFormBodies.set(sid, []);
      return true;
    }
    if (msg.method === 'GET') {
      const pth = u.searchParams.get('path') || '';
      return serveArtifactResolved(ws, sid, pth);
    }
    return false;
  }

  function serveArtifactFile(ws, sid, rawPath, fail) {
    const ext = path.extname(rawPath).toLowerCase();
    const dotfile = /(^|\/)(\.[a-z0-9_.-]+)$/i.test(path.basename(rawPath));
    if (!ARTIFACT_TEXT_EXT.has(ext) && !dotfile) return fail(415, `unsupported artifact type: ${ext || '(none)'}`);
    let st;
    try { st = fs.statSync(rawPath); } catch { return fail(404, 'file not found'); }
    if (!st.isFile()) return fail(400, 'not a regular file');
    if (st.size > ARTIFACT_MAX_BYTES) return fail(413, `artifact too large (${st.size} bytes > ${ARTIFACT_MAX_BYTES})`);
    let buf;
    try { buf = fs.readFileSync(rawPath); } catch (e) { return fail(500, 'read failed: ' + e.message); }
    const mime = ARTIFACT_MIME[ext] || 'text/plain; charset=utf-8';
    // [EO实测] 响应头只保留 content-type + content-length：
    // 携带 cache-control/content-disposition 时 EdgeOne 会静默吞掉该响应
    artifactRespond(ws, sid, 200, {
      'content-type': mime,
      'content-length': String(buf.length),
    }, buf);
    log.log?.(`[agent] artifact served: ${rawPath} (${buf.length}B)`);
    return true;
  }

  function respondError(ws, streamId, status, message) {
    send(ws, {
      type: 'http:response',
      streamId,
      status,
      headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
    });
    send(ws, { type: 'http:data', streamId, data: b64(Buffer.from(message)) });
    send(ws, { type: 'http:end-response', streamId });
    streams.delete(streamId);
  }

  /** Resolve msg.target to a dial target. null = plugin not declared. */
  function resolveTarget(msg) {
    const t = msg.target || 'dsh';
    if (t === 'dsh') return { id: 'dsh', host: dshHost, port: dshPort, dsh: true, svc: null };
    const svc = svcMap.get(t);
    if (!svc) return null;
    return { id: t, host: svc.host, port: svc.port, dsh: false, svc };
  }

  /** auth:'sso' 服务出站的信任头（M3：relay↔业务系统共享密钥的 HMAC 链）。 */
  function ssoHeaders(svc) {
    if (!svc || svc.auth !== 'sso' || !svc.ssoSecret || !relayUsername) return {};
    const ts = Date.now().toString();
    const sig = crypto.createHmac('sha256', svc.ssoSecret).update(`${relayUsername}.${ts}`).digest('hex');
    return { 'x-sso-user': relayUsername, 'x-sso-ts': ts, 'x-sso-sig': sig };
  }

  /** auth:'open' 服务的上游 Basic 凭据注入（服务自身保留 Basic Auth 时的代填）。 */
  function basicHeader(svc) {
    if (!svc || svc.auth !== 'open' || !svc.basicPassword) return undefined;
    return 'Basic ' + Buffer.from(`${svc.basicUser || 'user'}:${svc.basicPassword}`).toString('base64');
  }

  function handleHttpRequest(ws, msg, isRetry) {
    const { streamId, method, path, headers } = msg;
    const target = resolveTarget(msg);
    if (!target) {
      respondError(ws, streamId, 404, `dsh-remote: plugin "${msg.target}" is not declared on this instance`);
      return;
    }

    // dsh >= 0.1.2 web auth: inject the minted browser cookie when we have
    // one. dsh <= 0.1.1 has no web auth; with no token/cookie nothing is
    // injected and requests go out exactly like plugin 0.1.5 sent them.
    // 插件上游：不注入 dsh cookie，注入 SSO 信任头（若声明），剥除 Origin。
    const issue = (cookie) => {
      const upstreamHeaders = {
        ...headers,
        host: `${target.host}:${target.port}`,
      };
      if (target.dsh) {
        upstreamHeaders.origin = `http://${target.host}:${target.port}`;
        if (cookie) upstreamHeaders.cookie = cookie;
      } else {
        delete upstreamHeaders.origin;
        // 插件上游不透传 dshost 站点 Cookie（dsh_session 等），业务自身的
        // Bearer authorization 保留（relay 侧已放行）。
        delete upstreamHeaders.cookie;
        Object.assign(upstreamHeaders, ssoHeaders(target.svc));
        const basic = basicHeader(target.svc);
        if (basic) upstreamHeaders.authorization = basic;
      }
      delete upstreamHeaders['content-length'];

      const dshReq = http.request({
        hostname: target.host,
        port: target.port,
        path,
        method,
        headers: upstreamHeaders,
      }, (dshRes) => {
        if (target.dsh && dshRes.statusCode === 401 && cookie) {
          // Cached cookie rejected (launch token rotated, e.g. dsh restarted).
          // Re-mint; body-less requests are retried once with the fresh
          // cookie, everything else forwards the 401 and the browser app
          // retries its next action with the fresh cookie.
          dshRes.resume();
          authCookie = null;
          const remint = mintAuthCookie();
          if ((method === 'GET' || method === 'HEAD') && !isRetry) {
            log.log?.('[agent] local dsh 401, re-minting web auth cookie and retrying');
            remint.then((c) => {
              if (c) handleHttpRequest(ws, msg, true);
              else respondError(ws, streamId, 502, 'dsh-remote: local web auth re-mint failed');
            });
          } else {
            log.log?.('[agent] local dsh 401 on body request, re-minting web auth cookie for next requests');
          }
          return;
        }
        const respHeaders = { ...dshRes.headers };
        // The dsh index carries no cache-control; a heuristically cached stale
        // HTML from a previous build references dead module revs and breaks
        // the client module system. HTML must always revalidate.
        if (String(respHeaders['content-type'] || '').includes('text/html')) {
          respHeaders['cache-control'] = 'no-store';
        }
        send(ws, {
          type: 'http:response',
          streamId,
          status: dshRes.statusCode,
          headers: respHeaders,
        });

        // Backpressure: pause reading from dsh when the relay link is slow.
        // NOTE: the ws library does NOT emit 'drain' (verified), so resume is
        // driven by polling bufferedAmount down below the high-water mark —
        // a once('drain') here would never fire and would deadlock (truncated
        // responses, hanging browsers).
        dshRes.on('data', (chunk) => {
          if (ws.bufferedAmount > WS_SEND_HIGH_WATER) {
            dshRes.pause();
            const resumeWhenDrained = () => {
              if (ws.readyState !== WebSocket.OPEN) return;
              if (ws.bufferedAmount < WS_SEND_HIGH_WATER / 2) {
                dshRes.resume();
              } else {
                setTimeout(resumeWhenDrained, 50);
              }
            };
            setTimeout(resumeWhenDrained, 50);
          }
          send(ws, { type: 'http:data', streamId, data: b64(chunk) });
        });
        dshRes.on('end', () => {
          send(ws, { type: 'http:end-response', streamId });
          streams.delete(streamId);
        });
        dshRes.on('error', () => {
          send(ws, { type: 'error', streamId, message: `${target.dsh ? 'Local dsh' : `Plugin ${target.id}`} response error` });
          streams.delete(streamId);
        });
      });

      dshReq.on('error', (err) => {
        log.error?.(`[agent] HTTP Error: ${err.message}`);
        send(ws, { type: 'error', streamId, message: `${target.dsh ? 'local dsh' : `plugin ${target.id}`} upstream: ${err.message}` });
        streams.delete(streamId);
      });

      streams.set(streamId, { dshReq, dshRes: null, chunks: [] });

      // Body-less requests are complete the moment they are created: end them
      // now so a 401-retry (whose http:end frame was already consumed by the
      // first attempt) still transmits. The later http:end frame, when it
      // arrives, calls dshReq.end() again — a safe no-op. Body-bearing
      // requests keep waiting for http:body/http:end frames as before.
      if (method === 'GET' || method === 'HEAD') dshReq.end();
    };

    if (!target.dsh) {
      issue(undefined);
    } else if ((webToken || authCookie) && !authCookie) {
      // A token is known but the eager mint has not landed yet (startup
      // race): mint first, then issue. Body frames arriving during the mint
      // window are dropped (no streams entry yet) — only POSTs racing the
      // very first mint are affected; the eager mint on token acquisition
      // makes this path practically unreachable.
      mintAuthCookie().then((c) => issue(c));
    } else {
      issue(authCookie || undefined);
    }
  }

  function handleWsOpen(ws, msg) {
    const { streamId, path, headers } = msg;
    const target = resolveTarget(msg);
    if (!target) {
      send(ws, { type: 'error', streamId, message: `dsh-remote: plugin "${msg.target}" is not declared on this instance` });
      return;
    }
    const dshWsUrl = `ws://${target.host}:${target.port}${path || '/'}`;
    log.log?.(`[agent] WS OPEN stream ${streamId} -> ${target.id}@${dshWsUrl}`);

    const options = {
      headers: {
        ...headers,
        host: `${target.host}:${target.port}`,
      },
      rejectUnauthorized: false,
    };
    if (target.dsh) {
      // dsh 信任栅栏要求 Origin 与本地 web 一致
      options.headers.origin = `https://${target.host}:${target.port}`;
      // dsh >= 0.1.2 gates the WS upgrade behind the same browser cookie.
      if (authCookie) options.headers.cookie = authCookie;
    } else {
      delete options.headers.origin;
      Object.assign(options.headers, ssoHeaders(target.svc));
      const basic = basicHeader(target.svc);
      if (basic) options.headers.authorization = basic;
    }

    const dshWs = new WebSocket(dshWsUrl, undefined, options);
    const pending = [];

    const openTimeout = setTimeout(() => {
      if (dshWs.readyState === WebSocket.CONNECTING) {
        log.warn?.(`[agent] ws stream ${streamId} local connect timeout`);
        dshWs.terminate();
        send(ws, { type: 'error', streamId, message: 'Local websocket connect timeout' });
        streams.delete(streamId);
      }
    }, LOCAL_WS_CONNECT_TIMEOUT_MS);

    dshWs.on('open', () => {
      clearTimeout(openTimeout);
      log.log?.(`[agent] WS OPENED stream ${streamId}`);
      for (const item of pending) {
        if (item.binary) {
          dshWs.send(un64(item.data), { binary: true });
        } else {
          dshWs.send(item.data);
        }
      }
      pending.length = 0;
    });

    dshWs.on('message', (data, isBinary) => {
      if (ws.bufferedAmount > WS_SEND_HIGH_WATER) {
        log.warn?.(`[agent] relay link slow on stream ${streamId}, dropping frame to protect memory`);
        return;
      }
      send(ws, {
        type: 'ws:frame',
        streamId,
        data: isBinary ? b64(Buffer.from(data)) : data.toString(),
        binary: isBinary,
      });
    });

    dshWs.on('close', (code, reason) => {
      clearTimeout(openTimeout);
      send(ws, { type: 'ws:close', streamId, code: sanitizeCloseCode(code), reason: reason?.toString() || '' });
      streams.delete(streamId);
    });

    dshWs.on('error', (err) => {
      clearTimeout(openTimeout);
      log.error?.(`[agent] WS Error: ${err.message}`);
      send(ws, { type: 'error', streamId, message: err.message });
      streams.delete(streamId);
    });

    streams.set(streamId, { dshWs, pending });
  }

  connect();

  return {
    /** Provide the local dsh web launch token (dsh >= 0.1.2 auth mode). */
    setWebToken,
    stop() {
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
    },
  };
}
