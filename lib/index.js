// dsh-remote Plugin for DeepSeek Harness
// Runs alongside dsh and provides remote access via a relay server.
// The agent engine lives in ./core.js, generated at pack time from
// ../../agent/core.js (single source shared with the standalone agent).
// See scripts/prepack.mjs.

import { startAgent } from './core.js';

// Local dsh instance this plugin proxies (dsh web runs on loopback 3080).
const DSH_HOST = '127.0.0.1';
const DSH_PORT = 3080;

// Apply function - called when the plugin is loaded
export function apply(ctx, config) {
  const token = config.token || '';
  const relayUrl = config.relayUrl || process.env.DSH_RELAY_URL || 'wss://relay.example.com/agent';
  const autoConnect = config.autoConnect !== false;
  // Local dsh instance this plugin proxies (config-overridable for tests/dev)
  const dshHost = config.dshHost || process.env.DSH_HOST || DSH_HOST;
  const dshPort = parseInt(config.dshPort || process.env.DSH_PORT || String(DSH_PORT), 10);
  // 插件工作区服务清单（cordis.patch.yml 的 config.services 数组）
  const services = Array.isArray(config.services) ? config.services : [];

  console.log('[dsh-remote] Plugin loaded, token:', token ? '***' : 'none');
  if (services.length) console.log('[dsh-remote] Plugin services:', services.map((s) => s && s.id).filter(Boolean).join(', '));

  if (!token) {
    console.warn('[dsh-remote] No token configured. Please set token in settings.');
    return { setWebToken() {}, stop() {} };
  }

  if (!autoConnect) {
    console.log('[dsh-remote] Auto-connect disabled.');
    return { setWebToken() {}, stop() {} };
  }

  // Start the agent connection (wss enforcement lives in core.js)
  const agent = startAgent({
    token,
    relayUrl,
    dshHost,
    dshPort,
    services,
  });

  // dsh >= 0.1.2 web auth: the web UI is gated behind a per-process one-time
  // launch token (the @Remote gateway era replaced the plain ApiProxy surface
  // and added BrowserAuth on the shared /api FetchHandler). Our agent runs
  // inside the host process, so it asks the connection service for the
  // authenticated URL and mints a browser cookie for all proxied traffic.
  // dsh <= 0.1.1 has no 'connection' service: the guarded inject below never
  // fires and the plugin keeps its 0.1.5 behavior — one build, both hosts.
  try {
    if (ctx && typeof ctx.inject === 'function') {
      ctx.inject(['connection'], (connectionCtx) => {
        try {
          const conn = connectionCtx && connectionCtx.connection;
          if (!conn || typeof conn.authenticatedUrl !== 'function') return;
          const url = conn.authenticatedUrl(`http://${dshHost}:${dshPort}/`);
          const webToken = new URL(url).searchParams.get('token');
          if (webToken) agent.setWebToken(webToken);
        } catch (err) {
          console.warn('[dsh-remote] web launch token acquisition failed:', err && err.message);
        }
      });
    }
  } catch {
    // Non-cordis ctx (smoke tests) or an older host without the service
    // registry shape: legacy mode, no web auth injection.
  }

  return agent;
}
