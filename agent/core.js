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

const IGNORE_IFACE_RE = /^(lo|docker\d*|br-[0-9a-f]+|veth[0-9a-f]+|virbr\d*|cni\d*|flannel\d*)$/i;
const TRANSPARENT_GIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

/**
 * Enumerate and classify all candidate IPv4 addresses for intranet direct probing.
 * Excludes loopback, internal interfaces, Docker bridges, container veths,
 * sing-box/clash virtual tun interfaces (e.g. 172.18.0.1), and public WAN IPs.
 * Categorizes EasyTier (10.144.x.x), Tailscale (100.64-127.x.x), and LAN (192.168.x.x, 10.x.x.x).
 * @returns {Array<{ip: string, name: string, type: 'lan'|'vpn', desc: string, prio: number}>}
 */
export function collectCandidateIpv4s() {
  const list = [];
  const seenIps = new Set();
  try {
    const ifaces = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(ifaces)) {
      if (IGNORE_IFACE_RE.test(name)) continue;
      for (const a of addrs || []) {
        if (a.family !== 'IPv4' || a.internal) continue;
        const ip = a.address;
        if (!ip || ip.startsWith('127.') || ip.startsWith('169.254.') || ip === '0.0.0.0') continue;
        if (seenIps.has(ip)) continue;

        // 1. Identify virtual tun/tap interfaces
        const isTunTap = /^(tun|tap|utun)/i.test(name);
        const isEasyTier = ip.startsWith('10.144.') || /easytier/i.test(name);
        const isTailscale = /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip) || /tailscale/i.test(name);

        // If it's a tun/tap interface but NOT a recognized mesh VPN, it is a local proxy
        // (e.g. sing-box/clash fake-ip or 172.18.0.1 tun) -> STRICTLY EXCLUDE.
        if (isTunTap && !isEasyTier && !isTailscale) {
          continue;
        }

        // 2. Filter out 172.16.0.0/12 (Docker networks, sing-box tun endpoints)
        if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) {
          continue;
        }

        let type = null;
        let desc = name;
        let prio = 99;

        if (isEasyTier) {
          type = 'vpn';
          desc = 'EasyTier 专网';
          prio = 1; // Prioritize mesh VPN across heterogeneous networks
        } else if (isTailscale) {
          type = 'vpn';
          desc = 'Tailscale 专网';
          prio = 1;
        } else if (ip.startsWith('192.168.')) {
          type = 'lan';
          desc = '物理局域网 (192.168.x)';
          prio = 2;
        } else if (ip.startsWith('10.')) {
          type = 'lan';
          desc = '私有内网 (10.x)';
          prio = 3;
        } else {
          // Public WAN IPs MUST NEVER be reported as intranet direct probe candidates!
          continue;
        }

        seenIps.add(ip);
        list.push({ ip, name, type, desc, prio });
      }
    }
  } catch {}

  // Explicit override or additional candidate IPs via env var
  const envCandidates = (process.env.DSH_CANDIDATE_IPS || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const raw of envCandidates) {
    if (!seenIps.has(raw) && /^(\d{1,3}\.){3}\d{1,3}$/.test(raw)) {
      seenIps.add(raw);
      list.unshift({ ip: raw, name: 'env', type: 'lan', desc: '指定内网地址', prio: 0 });
    }
  }

  list.sort((a, b) => a.prio - b.prio);
  return list;
}

/** First non-internal IPv4 of this host (for the dashboard), or null. */
function localIPv4() {
  const c = collectCandidateIpv4s();
  if (c.length > 0) return c[0].ip;
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
export function collectSystemInfo(defaultVersion, lanBridgeInfo = null) {
  const disks = collectDisks();
  const diskTotal = disks.reduce((a, d) => a + d.total, 0);
  const diskUsed = disks.reduce((a, d) => a + d.used, 0);
  const diskFree = disks.reduce((a, d) => a + d.free, 0);
  const cpus = os.cpus();
  const meta = detectDshMetadata();
  const candidates = collectCandidateIpv4s();
  const bridgePort = lanBridgeInfo?.port || parseInt(process.env.LAN_BRIDGE_PORT || '3088', 10);
  const bridgeEnabled = lanBridgeInfo ? lanBridgeInfo.enabled : process.env.LAN_BRIDGE_ENABLED === '1';
  return {
    instanceId: getEffectiveInstanceId(),
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    ip: candidates[0]?.ip || localIPv4(),
    network: {
      bridgePort,
      bridgeEnabled,
      candidates,
    },
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
 * Start lightweight LAN bridge listener for browser probing and direct LAN offloading.
 * - Handles /__dsh_probe.gif and /__dsh_probe with CORS + Private Network Access headers.
 * - Reverse proxies all other requests to local DSH (127.0.0.1:3080) rewriting Host/Origin.
 * - Forwards WebSocket upgrades cleanly.
 */
export function startLanBridge({
  port = 3088,
  dshHost = '127.0.0.1',
  dshPort = 3080,
  getInstanceId: getInstId = getInstanceId,
  getWebToken = null,
  getAuthCookie = null,
  mintAuthCookie = null,
  log = console,
}) {
  let isListening = false;
  // Track authenticated client IPs with expiration (7 days)
  const authenticatedClients = new Map();

  function isClientAuthed(ip, cookieHeader = '') {
    if (cookieHeader.includes('dsh-auth-') || cookieHeader.includes('dsh_lan_auth=1')) {
      return true;
    }
    const exp = authenticatedClients.get(ip);
    if (exp && exp > Date.now()) {
      return true;
    }
    return false;
  }

  function markClientAuthed(ip) {
    if (ip) {
      authenticatedClients.set(ip, Date.now() + 7 * 86400000);
      if (authenticatedClients.size > 1000) {
        const now = Date.now();
        for (const [k, v] of authenticatedClients) {
          if (v <= now) authenticatedClients.delete(k);
        }
      }
    }
  }

  const server = http.createServer((req, res) => {
    // CORS + PNA headers for modern browser cross-network access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, HEAD');
    res.setHeader('Access-Control-Allow-Headers', '*');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    const rawUrl = req.url || '/';
    const pathOnly = rawUrl.split('?')[0];

    // 1. Lightweight probe image for PNA / Mixed Content bypass
    if (pathOnly === '/__dsh_probe.gif') {
      res.setHeader('Content-Type', 'image/gif');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.writeHead(200);
      res.end(TRANSPARENT_GIF);
      return;
    }

    // 2. JSON probe endpoint
    if (pathOnly === '/__dsh_probe') {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.writeHead(200);
      res.end(JSON.stringify({
        ok: true,
        instanceId: getInstId ? getInstId() : null,
        hostname: os.hostname(),
        ts: Date.now(),
      }));
      return;
    }

    const clientIp = req.socket?.remoteAddress;
    const incomingCookie = req.headers.cookie || '';

    // Check if request query contains a launch/direct token
    let hasValidTokenInQuery = false;
    let queryToken = null;
    try {
      const u = new URL(rawUrl, 'http://127.0.0.1');
      queryToken = u.searchParams.get('token');
      const activeToken = getWebToken ? getWebToken() : null;
      if (queryToken && activeToken && queryToken === activeToken) {
        hasValidTokenInQuery = true;
        markClientAuthed(clientIp);
      }
    } catch {}

    const clientAuthed = hasValidTokenInQuery || isClientAuthed(clientIp, incomingCookie);

    // 3. Reverse proxy to local dsh on 127.0.0.1:3080
    const dshHeaders = { ...req.headers };
    dshHeaders.host = `${dshHost}:${dshPort}`;
    if (dshHeaders.origin) {
      dshHeaders.origin = `http://${dshHost}:${dshPort}`;
    }
    if (clientIp) {
      dshHeaders['x-forwarded-for'] = clientIp;
    }

    // Auth injection: If request lacks dsh-auth- cookie, but client is authenticated
    // (via token exchange, dsh_lan_auth cookie, or client IP match),
    // inject active authCookie so local DSH never 401s on browser cross-origin redirects
    const currentAuthCookie = getAuthCookie ? getAuthCookie() : null;
    if (!incomingCookie.includes('dsh-auth-') && clientAuthed && currentAuthCookie) {
      dshHeaders.cookie = incomingCookie ? `${incomingCookie}; ${currentAuthCookie}` : currentAuthCookie;
    }

    const dshReq = http.request(
      `http://${dshHost}:${dshPort}${rawUrl}`,
      {
        method: req.method,
        headers: dshHeaders,
      },
      (dshRes) => {
        const resHeaders = { ...dshRes.headers };

        // Rewrite Set-Cookie: SameSite=Strict -> SameSite=Lax
        // Also attach dsh_lan_auth cookie if client is authenticated
        const sc = resHeaders['set-cookie'];
        if (sc) {
          const list = Array.isArray(sc) ? sc : [sc];
          const rewritten = list.map((c) => c.replace(/;\s*SameSite=Strict/i, '; SameSite=Lax'));
          if (clientAuthed) {
            rewritten.push('dsh_lan_auth=1; Path=/; SameSite=Lax; Max-Age=2592000');
          }
          resHeaders['set-cookie'] = rewritten;
        } else if (hasValidTokenInQuery || clientAuthed) {
          resHeaders['set-cookie'] = ['dsh_lan_auth=1; Path=/; SameSite=Lax; Max-Age=2592000'];
        }

        if (dshRes.statusCode === 401 && mintAuthCookie) {
          mintAuthCookie().catch(() => {});
        }

        res.writeHead(dshRes.statusCode, resHeaders);
        dshRes.pipe(res);
      }
    );

    dshReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`LAN Bridge Error: unable to connect to local DSH at ${dshHost}:${dshPort} (${err.message})`);
      }
    });

    req.pipe(dshReq);
  });

  // Handle WebSocket Upgrade (e.g. terminals, RPC streams)
  server.on('upgrade', (req, socket, head) => {
    const clientIp = req.socket?.remoteAddress;
    const incomingCookie = req.headers.cookie || '';
    const dshHeaders = { ...req.headers };
    dshHeaders.host = `${dshHost}:${dshPort}`;
    if (dshHeaders.origin) {
      dshHeaders.origin = `http://${dshHost}:${dshPort}`;
    }

    const currentAuthCookie = getAuthCookie ? getAuthCookie() : null;
    const clientAuthed = isClientAuthed(clientIp, incomingCookie);
    if (!incomingCookie.includes('dsh-auth-') && (clientAuthed || currentAuthCookie) && currentAuthCookie) {
      dshHeaders.cookie = incomingCookie ? `${incomingCookie}; ${currentAuthCookie}` : currentAuthCookie;
    }

    const proxyReq = http.request({
      hostname: dshHost,
      port: dshPort,
      path: req.url,
      method: req.method,
      headers: dshHeaders,
    });

    proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
      let rawHeaders = `HTTP/1.1 101 Switching Protocols\r\n`;
      for (const [k, v] of Object.entries(proxyRes.headers)) {
        if (Array.isArray(v)) {
          for (const item of v) rawHeaders += `${k}: ${item}\r\n`;
        } else {
          rawHeaders += `${k}: ${v}\r\n`;
        }
      }
      rawHeaders += '\r\n';
      socket.write(rawHeaders);

      if (proxyHead && proxyHead.length) socket.write(proxyHead);
      if (head && head.length) proxySocket.write(head);

      proxySocket.pipe(socket);
      socket.pipe(proxySocket);

      proxySocket.on('error', () => socket.destroy());
      socket.on('error', () => proxySocket.destroy());
    });

    proxyReq.on('error', (err) => {
      log.warn?.(`[lan-bridge] WS upgrade to ${dshHost}:${dshPort} error: ${err.message}`);
      socket.destroy();
    });

    proxyReq.end();
  });

  server.on('error', (err) => {
    isListening = false;
    log.warn?.(`[lan-bridge] Failed to bind 0.0.0.0:${port}: ${err.message}`);
  });

  try {
    server.listen(port, '0.0.0.0', () => {
      isListening = true;
      log.log?.(`[lan-bridge] Listening on 0.0.0.0:${port} -> proxying to ${dshHost}:${dshPort}`);
    });
  } catch (err) {
    log.warn?.(`[lan-bridge] Failed to start listener: ${err.message}`);
  }

  return {
    server,
    port,
    get enabled() { return isListening && server.listening; },
    close() {
      try { server.close(); } catch {}
    },
  };
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
  // 单业务配置管理（门户托管）：宿主显式开启 remoteServices 才接受 relay 下发的
  // 'services:config'；下发项与本机声明走同一 normalizeServices 白名单，且只允许
  // auth=open、不接受任何凭据字段；与本机声明同 id 的下发项一律拒绝（本机为准）。
  const remoteServices = opts.remoteServices === true || process.env.DSH_REMOTE_SERVICES === '1';
  let managedList = [];
  let lastApplied = null;
  function servicesFrame() {
    const pub = ({ id, name, desc, icon, auth, entry, spa, category }) => ({ id, name, desc, icon, auth, entry, spa, category });
    return {
      type: 'services',
      servicesOnly: process.env.DSH_SERVICES_ONLY === '1' || undefined,
      capabilities: remoteServices && process.env.DSH_SERVICES_ONLY !== '1' ? { remoteConfig: 1 } : undefined,
      services: [
        ...svcList.map((s) => ({ ...pub(s), origin: 'local' })),
        ...managedList.map((s) => ({ ...pub(s), origin: 'managed' })),
      ],
      applied: lastApplied || undefined,
    };
  }
  function applyManagedConfig(raw) {
    const results = [];
    const accepted = [];
    const localIds = new Set(svcList.map((s) => s.id));
    for (const item of Array.isArray(raw) ? raw.slice(0, 32) : []) {
      const id = String(item?.id || '');
      if (localIds.has(id)) { results.push({ id, ok: false, error: '与本机声明的服务同名，以本机为准' }); continue; }
      const warn = [];
      const [svc] = normalizeServices([{
        id, name: item?.name, desc: item?.desc, icon: item?.icon, upstream: item?.upstream,
        entry: item?.entry, spa: item?.spa === true, auth: 'open',
      }], { warn: (m) => warn.push(m) });
      if (!svc) { results.push({ id, ok: false, error: (warn[0] || 'invalid').replace(/^\[agent\] /, '') }); continue; }
      svc.category = typeof item?.category === 'string' ? item.category.slice(0, 16) : '';
      accepted.push(svc);
      results.push({ id, ok: true });
    }
    for (const s of managedList) svcMap.delete(s.id);
    managedList = accepted;
    for (const s of managedList) svcMap.set(s.id, s);
    lastApplied = results;
    log.log?.(`[agent] managed services applied: ${results.map((r) => `${r.id}:${r.ok ? 'ok' : 'rejected'}`).join(', ') || '(none)'}`);
  }
  function probeUpstream(ws, msg) {
    const t0 = Date.now();
    const reply = (r) => send(ws, { type: 'services:probe-result', reqId: msg.reqId, ms: Date.now() - t0, ...r });
    const up = parseUpstream(msg.upstream);
    if (!up) { reply({ ok: false, error: '上游地址格式错误' }); return; }
    if (!upstreamAllowed(up.host)) { reply({ ok: false, error: `${up.host} 不在实例白名单内（回环 / 10.144.144.0/24 / AGENT_UPSTREAM_ALLOW）` }); return; }
    const entry = typeof msg.entry === 'string' && msg.entry.startsWith('/') ? msg.entry : '/';
    const req = http.request({ host: up.host, port: up.port, path: entry, method: 'GET', timeout: 5000, headers: { host: `${up.host}:${up.port}` } }, (res) => {
      res.resume();
      reply({ ok: res.statusCode < 500, status: res.statusCode });
    });
    req.on('timeout', () => { req.destroy(new Error('连接超时（5s）')); });
    req.on('error', (e) => reply({ ok: false, error: e.code === 'ECONNREFUSED' ? '连接被拒绝（端口没有服务在监听）' : e.message }));
    req.end();
  }
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

  function getActiveWebToken() {
    if (webToken) return webToken;
    try {
      if (fs.existsSync('/var/log/dsh-web.log')) {
        const content = fs.readFileSync('/var/log/dsh-web.log', 'utf8');
        const matches = [...content.matchAll(/\?token=([A-Za-z0-9_-]+)/g)];
        if (matches.length > 0) {
          return matches[matches.length - 1][1];
        }
      }
    } catch {}
    return null;
  }

  if (webToken) mintAuthCookie();

  // ── LAN Bridge deprecated in favor of secure WebRTC P2P (default disabled) ──
  const lanBridgePort = parseInt(process.env.LAN_BRIDGE_PORT || '3088', 10);
  const lanBridgeEnabled = process.env.LAN_BRIDGE_ENABLED === '1' && process.env.DSH_SERVICES_ONLY !== '1';
  let lanBridge = null;
  if (lanBridgeEnabled) {
    try {
      lanBridge = startLanBridge({
        port: lanBridgePort,
        dshHost,
        dshPort,
        getInstanceId: getEffectiveInstanceId,
        getWebToken: getActiveWebToken,
        getAuthCookie: () => authCookie,
        mintAuthCookie,
        log,
      });
    } catch (e) {
      log.warn?.(`[agent] Failed to initialize LAN bridge: ${e.message}`);
    }
  }

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
        send(ws, {
          type: 'system-info',
          info: collectSystemInfo(dshVersion, {
            port: lanBridgePort,
            enabled: lanBridge ? lanBridge.enabled : false,
          }),
        });
        // 插件工作区：上报本实例声明的服务清单（relay 存实例维度，供 /p 路由校验）
        // DSH_SERVICES_ONLY=1：独立 services agent，relay 不注册主实例（服务旁挂到同机 dsh 实例）
        send(ws, servicesFrame());
        startHeartbeat(ws);
        return;
      }

      if (msg.type === 'heartbeat') return;

      // 直连免密换票请求响应
      if (msg.type === 'lan-ticket:request') {
        const activeToken = getActiveWebToken();
        if (!authCookie && activeToken) {
          mintAuthCookie().catch(() => {});
        }
        send(ws, {
          type: 'lan-ticket:response',
          reqId: msg.reqId,
          ok: true,
          token: activeToken || '',
          bridgePort: lanBridgePort,
          bridgeEnabled: lanBridge ? lanBridge.enabled : false,
        });
        return;
      }

      // WebRTC ICE 配置（relay 现签 TURN 临时凭证）
      if (msg.type === 'webrtc:config') {
        const cb = pendingWebrtcConfig.get(msg.reqId);
        if (cb) { pendingWebrtcConfig.delete(msg.reqId); cb(msg); }
        return;
      }

      // relay 吊销某个 P2P 连接（被顶替 / 登出 / 封禁 / 超配额）
      if (msg.type === 'webrtc:revoke') {
        if (closePeer(msg.clientId)) {
          log.log?.(`[agent-webrtc] revoked client ${msg.clientId}`);
        }
        return;
      }

      // WebRTC P2P 穿透打洞信令交互
      if (msg.type === 'webrtc:signal') {
        handleWebRtcSignalMessage(ws, msg);
        return;
      }

      // 门户托管业务下发（仅宿主开启 remoteServices 时接受）
      if (msg.type === 'services:config') {
        if (!remoteServices) { log.warn?.('[agent] services:config ignored (remoteServices disabled)'); return; }
        applyManagedConfig(msg.services);
        send(ws, servicesFrame());
        return;
      }
      if (msg.type === 'services:probe') {
        if (!remoteServices) { send(ws, { type: 'services:probe-result', reqId: msg.reqId, ok: false, error: 'remoteServices disabled' }); return; }
        probeUpstream(ws, msg);
        return;
      }

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

  // ── WebRTC P2P Hole Punching Engine (werift) ──────────────────────
  let weriftModule = null;
  async function loadWerift() {
    if (weriftModule) return weriftModule;
    try {
      try {
        const resolved = import.meta.resolve ? import.meta.resolve('werift') : null;
        if (resolved) {
          const weriftPkgPath = new URL(resolved).pathname;
          const weriftDir = path.dirname(weriftPkgPath);
          const targets = [
            path.join(weriftDir, 'index.mjs'),
            path.join(weriftDir, 'ice/src/internal/selectAddresses.js'),
          ];
          for (const f of targets) {
            if (fs.existsSync(f)) {
              let c = fs.readFileSync(f, 'utf8');
              if (c.includes('"tun"') || c.includes("'tun'")) {
                c = c.replace(/costlyNetworks\s*=\s*\[[^\]]+\]/g, 'costlyNetworks = ["ipsec"]');
                fs.writeFileSync(f, c);
              }
            }
          }
        }
      } catch (_) {}

      weriftModule = await import('werift');
      return weriftModule;
    } catch (e) {
      log.warn?.(`[agent] werift WebRTC module load failed: ${e.message}`);
      return null;
    }
  }

  const activeRtcPeers = new Map(); // clientId -> { pc, dc, wsStreams }

  // ── ICE 配置 ──────────────────────────────────────────────────────
  // TURN 凭证由 relay 现签（relay 持有 TURN_SECRET，agent 不该有）。缓存到
  // 剩余 10 分钟时刷新；relay 不可达则退化为仅 STUN，P2P 可能失败但不会崩。
  const STUN_ONLY = [
    { urls: 'stun:39.106.35.187:3478' },
    { urls: 'stun:111.206.174.2:3478' },
    { urls: 'stun:111.206.174.3:3478' },
    { urls: 'stun:47.100.127.239:3478' },
    { urls: 'stun:stun.qq.com:3478' },
    { urls: 'stun:stun.miwifi.com:3478' },
    { urls: 'stun:stun.cloudflare.com:3478' },
  ];
  let iceCache = { servers: null, expiresAt: 0 };
  const pendingWebrtcConfig = new Map(); // reqId -> resolve

  function requestWebrtcConfig(ws) {
    const reqId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingWebrtcConfig.delete(reqId);
        resolve(null);
      }, 5000);
      pendingWebrtcConfig.set(reqId, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      send(ws, { type: 'webrtc:config-request', reqId });
    });
  }

  async function getIceServers(ws) {
    const now = Date.now();
    if (iceCache.servers && iceCache.expiresAt - now > 600_000) return iceCache.servers;
    const cfg = await requestWebrtcConfig(ws);
    if (cfg && Array.isArray(cfg.iceServers) && cfg.iceServers.length) {
      const ttlMs = (Number(cfg.ttl) || 3600) * 1000;
      iceCache = { servers: cfg.iceServers, expiresAt: now + ttlMs };
      return iceCache.servers;
    }
    return STUN_ONLY;
  }

  // ICE 候选遥测：认证后 2s 抓一次 stats（给 nomination 留出时间），标注候选
  // 类型（host/srflx/prflx/relay）、传输协议和 RTT，随下一帧 webrtc:peer-state
  // 上报。每个 peer 只上报一次。
  function reportIceStatsSoon(peer) {
    if (!peer || peer.iceStatsSent) return;
    peer.iceStatsSent = true;
    const timer = setTimeout(() => {
      try {
        const statsPromise = peer.pc && peer.pc.getStats ? peer.pc.getStats() : Promise.resolve(null);
        Promise.resolve(statsPromise).then((report) => {
          if (!report) return;
          let pair = null;
          for (const s of report.values()) {
            if (s.type === 'candidate-pair' && (s.nominated || s.state === 'succeeded')) {
              pair = s;
              if (s.nominated) break;
            }
          }
          let localC = null;
          if (pair) localC = report.get(pair.localCandidateId) || null;
          if (peer.ws && peer.ws.readyState === 1) {
            try {
              send(peer.ws, {
                type: 'webrtc:peer-state',
                clientId: peer.clientId,
                state: 'open',
                ice: {
                  candidateType: localC ? localC.candidateType : null,
                  protocol: localC ? localC.protocol : null,
                  rttMs: pair && pair.currentRoundTripTime != null
                    ? Math.round(pair.currentRoundTripTime * 1000)
                    : null,
                },
              });
            } catch {}
          }
        }).catch(() => {});
      } catch {}
    }, 2000);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  // ── P2P 用量统计（每 60s 汇总上报，供 relay 记账与配额）─────────────
  function bump(peer, dir, n) {
    if (!peer || !peer.usage || !n) return;
    if (dir === 'up') peer.usage.up += n;
    else peer.usage.down += n;
  }

  function flushUsage(peer) {
    if (!peer || !peer.usage || !peer.ws || peer.ws.readyState !== 1) return;
    const { up, down } = peer.usage;
    if (!up && !down) return;
    peer.usage.up = 0;
    peer.usage.down = 0;
    try {
      send(peer.ws, {
        type: 'webrtc:usage',
        clientId: peer.clientId,
        bytesUp: up,
        bytesDown: down,
        streams: peer.wsStreams.size,
        windowMs: 60_000,
      });
    } catch {}
  }

  function closePeer(clientId) {
    const peer = activeRtcPeers.get(clientId);
    if (!peer) return false;
    flushUsage(peer);
    try { peer.pc.close(); } catch {}
    if (peer.usage.heartbeat) clearInterval(peer.usage.heartbeat);
    activeRtcPeers.delete(clientId);
    return true;
  }

  async function handleWebRtcSignalMessage(ws, msg) {
    const { reqId, signalType, sdp, candidate, clientId = 'default' } = msg;
    if (signalType === 'offer') {
      const werift = await loadWerift();
      if (!werift || !werift.RTCPeerConnection) {
        send(ws, {
          type: 'webrtc:signal-response',
          reqId,
          ok: false,
          error: '宿主机未安装或加载 werift WebRTC 模块',
        });
        return;
      }

      // 确保本地 Auth Cookie 就绪
      if (!authCookie && webToken) {
        try { await mintAuthCookie(); } catch {}
      }

      try {
        const existing = activeRtcPeers.get(clientId);
        if (existing) closePeer(clientId);

        const iceServers = await getIceServers(ws);
        const pc = new werift.RTCPeerConnection({ iceServers });

        const peer = {
          clientId,
          pc,
          dc: null,
          ws,
          wsStreams: new Map(),
          httpReqs: new Map(),
          nonce: typeof msg.peerNonce === 'string' ? msg.peerNonce : '',
          authed: !msg.peerNonce,
          usage: { up: 0, down: 0, timer: null },
        };
        activeRtcPeers.set(clientId, peer);

        pc.ondatachannel = (event) => {
          const dc = event.channel;
          peer.dc = dc;
          log.log?.(`[agent-webrtc] DataChannel opened (${dc.label}) for client ${clientId}`);

          dc.onmessage = (e) => {
            handleRtcDataChannelMessage(peer, dc, e.data);
          };

          // 首帧必须是 auth。5s 内未认证就直接断开，避免半开连接长期挂着。
          if (!peer.authed) {
            peer.authTimer = setTimeout(() => {
              if (!peer.authed) {
                log.warn?.(`[agent-webrtc] client ${clientId} failed to authenticate, closing`);
                closePeer(clientId);
              }
            }, 5000);
          }

          // 用量每 60s 汇总一次；DC 关闭时再冲一次尾账。
          peer.usage.timer = setInterval(() => flushUsage(peer), 60_000);
          // 30s 心跳：relay 的 P2P lease TTL 是 60s，而 usage 帧只在有字节时
          // 发送——空闲浏览器不发流量时 lease 会过期，另一会话即可绕过单活跃
          // 门卫接管 P2P 所有权。心跳（state 'open'）保持 lease 常新，成本
          // 每 30s 一帧。
          peer.usage.heartbeat = setInterval(() => {
            if (!peer.authed) return;
            if (!peer.ws || peer.ws.readyState !== 1) return;
            try { send(peer.ws, { type: 'webrtc:peer-state', clientId: peer.clientId, state: 'open' }); } catch {}
          }, 30_000);

          dc.onclose = () => {
            log.log?.(`[agent-webrtc] DataChannel closed for client ${clientId}`);
            for (const [, sWs] of peer.wsStreams) {
              try { sWs.close(); } catch {}
            }
            peer.wsStreams.clear();
            for (const [, req] of peer.httpReqs) {
              try { req.destroy(); } catch {}
            }
            peer.httpReqs.clear();
            flushUsage(peer);
            if (peer.usage.timer) clearInterval(peer.usage.timer);
            if (peer.usage.heartbeat) clearInterval(peer.usage.heartbeat);
            if (peer.authTimer) clearTimeout(peer.authTimer);
            activeRtcPeers.delete(clientId);
            if (peer.authed && peer.ws && peer.ws.readyState === 1) {
              try { send(peer.ws, { type: 'webrtc:peer-state', clientId, state: 'closed' }); } catch {}
            }
          };

          dc.onerror = (err) => {
            log.warn?.(`[agent-webrtc] DataChannel error: ${err.message}`);
          };
        };

        await pc.setRemoteDescription({ type: 'offer', sdp });
        const answer = await pc.createAnswer();
        await pc.setLocalDescription(answer);

        // 等待 ICE 候选收集（嵌入至 localDescription 中返回，单次 RTT 快速握手）
        // 2500ms：TURN-only 路径经常超过原来的 1200ms，窗口太短会拿到没有
        // relay candidate 的 answer，握手必然失败。
        await new Promise((resolve) => {
          if (pc.iceGatheringState === 'complete') return resolve();
          const timer = setTimeout(resolve, 2500);
          pc.onicegatheringstatechange = () => {
            if (pc.iceGatheringState === 'complete') {
              clearTimeout(timer);
              resolve();
            }
          };
        });

        send(ws, {
          type: 'webrtc:signal-response',
          reqId,
          ok: true,
          signalType: 'answer',
          sdp: pc.localDescription.sdp,
        });
      } catch (err) {
        log.warn?.(`[agent-webrtc] Offer 协商异常: ${err.message}`);
        send(ws, {
          type: 'webrtc:signal-response',
          reqId,
          ok: false,
          error: err.message,
        });
      }
      return;
    }

    if (signalType === 'candidate') {
      const peer = activeRtcPeers.get(clientId);
      if (peer && peer.pc && candidate) {
        try { await peer.pc.addIceCandidate(candidate); } catch {}
      }
      send(ws, { type: 'webrtc:signal-response', reqId, ok: true });
      return;
    }
  }

  function handleRtcDataChannelMessage(peer, dc, raw) {
    let msg;
    try {
      msg = JSON.parse(typeof raw === 'string' ? raw : raw.toString('utf8'));
    } catch {
      return;
    }

    if (!msg || !msg.type) return;

    // 0. 认证门禁：未认证前只接受 auth，其余消息一律丢弃。
    if (!peer.authed) {
      if (msg.type === 'auth' && peer.nonce && msg.nonce === peer.nonce) {
        peer.authed = true;
        if (peer.authTimer) { clearTimeout(peer.authTimer); peer.authTimer = null; }
        log.log?.(`[agent-webrtc] client ${peer.clientId} authenticated`);
        if (peer.ws && peer.ws.readyState === 1) {
          try { send(peer.ws, { type: 'webrtc:peer-state', clientId: peer.clientId, state: 'open' }); } catch {}
        }
        reportIceStatsSoon(peer);
      }
      return;
    }

    // 1. P2P 测速与探测 (Ping / Pong)
    if (msg.type === 'ping') {
      try {
        dc.send(JSON.stringify({
          type: 'pong',
          reqId: msg.reqId,
          ts: msg.ts,
          agentTs: Date.now(),
          instanceId: getEffectiveInstanceId(),
          hostname: os.hostname(),
        }));
      } catch {}
      return;
    }

    // 2. HTTP 虚拟流转发
    if (msg.type === 'http:request') {
      const { streamId, method = 'GET', url = '/', headers = {}, body } = msg;
      const targetHeaders = { ...headers };
      targetHeaders.host = `${dshHost}:${dshPort}`;
      targetHeaders.origin = `http://${dshHost}:${dshPort}`;
      if (authCookie) targetHeaders.cookie = authCookie;
      delete targetHeaders['content-length'];
      // 压缩后的字节没法塞进构造型 Response 让浏览器解压，直接要明文。
      targetHeaders['accept-encoding'] = 'identity';

      const dshReq = http.request(`http://${dshHost}:${dshPort}${url}`, {
        method,
        headers: targetHeaders,
      }, (dshRes) => {
        const resHeaders = { ...dshRes.headers };
        const sc = resHeaders['set-cookie'];
        if (sc) {
          const list = Array.isArray(sc) ? sc : [sc];
          resHeaders['set-cookie'] = list.map(c => c.replace(/;\s*SameSite=Strict/i, '; SameSite=Lax'));
        }

        try {
          dc.send(JSON.stringify({
            type: 'http:response',
            streamId,
            status: dshRes.statusCode,
            headers: resHeaders,
          }));
        } catch {}

        dshRes.on('data', (chunk) => {
          bump(peer, 'down', chunk.length);
          try {
            dc.send(JSON.stringify({
              type: 'http:chunk',
              streamId,
              data: chunk.toString('base64'),
            }));
          } catch {}
        });

        dshRes.on('end', () => {
          peer.httpReqs.delete(streamId);
          try {
            dc.send(JSON.stringify({ type: 'http:end', streamId }));
          } catch {}
        });
      });

      peer.httpReqs.set(streamId, dshReq);

      dshReq.on('error', (err) => {
        peer.httpReqs.delete(streamId);
        try {
          dc.send(JSON.stringify({
            type: 'http:response',
            streamId,
            status: 502,
            headers: { 'content-type': 'text/plain' },
          }));
          dc.send(JSON.stringify({
            type: 'http:chunk',
            streamId,
            data: Buffer.from(`DSH WebRTC proxy error: ${err.message}`).toString('base64'),
          }));
          dc.send(JSON.stringify({ type: 'http:end', streamId }));
        } catch {}
      });

      if (body) {
        const buf = Buffer.from(body, 'base64');
        bump(peer, 'up', buf.length);
        dshReq.write(buf);
      }
      dshReq.end();
      return;
    }

    // 2b. 浏览器中断 HTTP 流（AbortSignal）
    if (msg.type === 'http:abort') {
      const req = peer.httpReqs.get(msg.streamId);
      if (req) {
        try { req.destroy(); } catch {}
        peer.httpReqs.delete(msg.streamId);
      }
      return;
    }

    // 3. WebSocket 虚拟流转发 (终端 / RPC)
    if (msg.type === 'ws:open') {
      const { streamId, url = '/api/remote.mux' } = msg;
      const wsHeaders = {
        host: `${dshHost}:${dshPort}`,
        origin: `http://${dshHost}:${dshPort}`,
      };
      if (authCookie) wsHeaders.cookie = authCookie;

      const dshWs = new WebSocket(`ws://${dshHost}:${dshPort}${url}`, {
        headers: wsHeaders,
      });

      peer.wsStreams.set(streamId, dshWs);

      dshWs.on('open', () => {
        try {
          dc.send(JSON.stringify({ type: 'ws:opened', streamId }));
        } catch {}
      });

      dshWs.on('message', (data, isBinary) => {
        bump(peer, 'down', isBinary ? data.length : Buffer.byteLength(data, 'utf8'));
        try {
          dc.send(JSON.stringify({
            type: 'ws:message',
            streamId,
            data: isBinary ? data.toString('base64') : data.toString(),
            binary: !!isBinary,
          }));
        } catch {}
      });

      dshWs.on('close', (code, reason) => {
        peer.wsStreams.delete(streamId);
        try {
          dc.send(JSON.stringify({
            type: 'ws:close',
            streamId,
            code,
            reason: reason?.toString(),
          }));
        } catch {}
      });

      dshWs.on('error', (err) => {
        try {
          dc.send(JSON.stringify({
            type: 'ws:error',
            streamId,
            message: err.message,
          }));
        } catch {}
      });
      return;
    }

    if (msg.type === 'ws:message') {
      const { streamId, data, binary } = msg;
      bump(peer, 'up', binary ? Buffer.from(data, 'base64').length : Buffer.byteLength(data, 'utf8'));
      const dshWs = peer.wsStreams.get(streamId);
      if (dshWs && dshWs.readyState === WebSocket.OPEN) {
        if (binary) {
          dshWs.send(Buffer.from(data, 'base64'), { binary: true });
        } else {
          dshWs.send(data);
        }
      }
      return;
    }

    if (msg.type === 'ws:close') {
      const { streamId, code, reason } = msg;
      const dshWs = peer.wsStreams.get(streamId);
      if (dshWs) {
        try { dshWs.close(code, reason); } catch {}
        peer.wsStreams.delete(streamId);
      }
      return;
    }
  }

  // ── Agent 冷启动预热 ─────────────────────────────────────────────
  // werift 首次 dynamic import 可能要 10–20s，否则首个 WebRTC 信令会顶到
  // relay 的 15s 信令超时、浏览器首连永远失败。fire-and-forget：
  // 失败只影响 P2P，不影响中继通道。
  loadWerift().catch((e) => log.warn?.(`[agent] werift prewarm failed: ${e && e.message}`));
  // 预取本机 dsh 的认证 cookie（dsh 重启会轮换 launch token，此处失败无害）
  if (webToken) mintAuthCookie().catch(() => {});

  connect();

  return {
    /** Provide the local dsh web launch token (dsh >= 0.1.2 auth mode). */
    setWebToken,
    stop() {
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (lanBridge) lanBridge.close();
      for (const [, peer] of activeRtcPeers) {
        try { peer.pc.close(); } catch {}
      }
      activeRtcPeers.clear();
    },
  };
}
