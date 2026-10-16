import serverless from 'serverless-http';
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
    if (!initialization) initialization = initDb();
    await initialization;
  } catch (error) {
    console.error('LUZAWEB Netlify function could not initialize:', error?.message || error);
    return {
      statusCode: 503,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store'
      },
      body: JSON.stringify({
        ok: false,
        error: 'O backend do LUZAWEB não está configurado ou não consegue ligar à base de dados. Verifica DATABASE_URL e JWT_SECRET nas variáveis do Netlify.'
      })
    };
  }
  return proxy(normalizeRewritePath(event), context);
};
