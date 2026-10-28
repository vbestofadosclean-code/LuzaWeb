import serverless from 'serverless-http';
import { randomUUID } from 'node:crypto';
import { app, initDb } from '../../server.js';

const proxy = serverless(app, {
  binary: ['image/*', 'audio/*', 'video/*', 'application/pdf', 'application/octet-stream', 'font/*']
});
let initialization;

function normalizeRewritePath(event) {
  // Netlify normally preserves the original URL on an internal rewrite, but some
  // adapters expose the rewritten Function path. Support both forms.
  const prefix = '/.netlify/functions/server';
  if (typeof event?.path !== 'string' || !event.path.startsWith(`${prefix}/`)) return event;
  return { ...event, path: event.path.slice(prefix.length) || '/' };
}

export const handler = async (event, context) => {
  try {
    if (!initialization) {
      const attempt = initDb();
      // Clear the Function-level cache after failure too, otherwise this warm
      // instance would return 503 forever even if the database recovers.
      initialization = attempt.catch(error => {
        initialization = undefined;
        throw error;
      });
    }
    await initialization;
  } catch (error) {
    const requestId = randomUUID();
    const errorCode = String(error?.code || error?.name || 'unknown').slice(0, 48);
    // Keep diagnostics correlated without writing connection strings, provider
    // messages or secret/configuration values into the function log.
    console.error(JSON.stringify({ event: 'function_init_failed', request_id: requestId, error_code: errorCode }));
    return {
      statusCode: 503,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'x-request-id': requestId
      },
      body: JSON.stringify({
        ok: false,
        error: 'O backend está temporariamente indisponível. Tenta novamente mais tarde.',
        code: 'SERVICE_UNAVAILABLE',
        request_id: requestId
      })
    };
  }
  return proxy(normalizeRewritePath(event), context);
};
