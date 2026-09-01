// Shared helpers for the dsh-remote MVP wire protocol.
//
// All messages are JSON strings sent over a WebSocket connection.
// Binary payloads are base64-encoded inside JSON.

export function send(ws, obj) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
    return true;
  }
  return false;
}

export function b64(buf) {
  return Buffer.from(buf).toString('base64');
}

export function un64(str) {
  return Buffer.from(str, 'base64');
}

/**
 * Normalize a WebSocket close code before passing it to ws.close().
 * ws throws TypeError on reserved/invalid codes (e.g. 1005 "no status"),
 * which would crash the process if forwarded unchecked.
 * Valid: 1000-1014 except 1004/1005/1006, or 3000-4999.
 */
export function sanitizeCloseCode(code) {
  if (typeof code === 'number') {
    if ((code >= 1000 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006) ||
        (code >= 3000 && code <= 4999)) {
      return code;
    }
  }
  return 1000;
}

// Relay -> Agent
export const HTTP_REQUEST = 'http:request'; // { streamId, method, path, headers }
export const HTTP_BODY = 'http:body';        // { streamId, data }
export const HTTP_END = 'http:end';          // { streamId }
export const WS_OPEN = 'ws:open';            // { streamId, path, headers }
export const WS_FRAME = 'ws:frame';          // { streamId, data, binary }
export const WS_CLOSE = 'ws:close';          // { streamId, code, reason }

// Agent -> Relay
export const HTTP_RESPONSE = 'http:response'; // { streamId, status, headers }
export const HTTP_DATA = 'http:data';         // { streamId, data }
export const HTTP_END_RESPONSE = 'http:end-response'; // { streamId }
export const ERROR = 'error';                 // { streamId?, message }

// Both
export const REGISTER = 'register';    // Agent -> Relay: { token, version }
export const REGISTERED = 'registered'; // Relay -> Agent: { username, sessionId }
export const HEARTBEAT = 'heartbeat';  // { ts }
