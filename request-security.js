const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const HTTP_PROTOCOLS = new Set(['http:', 'https:']);

function readHeader(req, name) {
  if (typeof req?.get === 'function') return req.get(name);
  const value = req?.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function parseRequestOrigin(req) {
  const protocolValue = String(req?.protocol || (req?.socket?.encrypted ? 'https' : 'http')).toLowerCase();
  const protocol = protocolValue.endsWith(':') ? protocolValue : `${protocolValue}:`;
  const host = String(readHeader(req, 'host') || '').trim();
  if (!HTTP_PROTOCOLS.has(protocol) || !host || /[\s,\\]/.test(host)) return null;
  try {
    const parsed = new URL(`${protocol}//${host}`);
    if (!HTTP_PROTOCOLS.has(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/') return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

function originFromHeader(value, { bareOrigin = false } = {}) {
  if (typeof value !== 'string') return null;
  const raw = value.trim();
  if (!raw || raw.toLowerCase() === 'null') return null;
  try {
    const parsed = new URL(raw);
    if (!HTTP_PROTOCOLS.has(parsed.protocol) || parsed.username || parsed.password) return null;
    if (bareOrigin && (parsed.pathname !== '/' || parsed.search || parsed.hash)) return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * Validates browser provenance for state-changing requests authenticated by cookies.
 * The dashboard API is same-origin only. Public project API routes (/v1) are
 * deliberately not covered because they use API keys and are designed for CORS.
 */
export function validateSameOriginMutation(req) {
  const method = String(req?.method || 'GET').toUpperCase();
  if (!MUTATING_METHODS.has(method)) return { ok: true, reason: 'safe_method' };

  const fetchSite = String(readHeader(req, 'sec-fetch-site') || '').trim().toLowerCase();
  if (fetchSite === 'cross-site') return { ok: false, reason: 'fetch_metadata_cross_site' };

  const expectedOrigin = parseRequestOrigin(req);
  if (!expectedOrigin) return { ok: false, reason: 'request_origin_unavailable' };

  const rawOrigin = readHeader(req, 'origin');
  if (rawOrigin !== undefined && rawOrigin !== null) {
    const actualOrigin = originFromHeader(rawOrigin, { bareOrigin: true });
    return actualOrigin === expectedOrigin
      ? { ok: true, reason: 'origin_match' }
      : { ok: false, reason: actualOrigin ? 'origin_mismatch' : 'invalid_origin' };
  }

  // Referer is a fallback for compatible clients/browsers that omit Origin.
  const rawReferer = readHeader(req, 'referer');
  if (rawReferer !== undefined && rawReferer !== null) {
    const refererOrigin = originFromHeader(rawReferer);
    return refererOrigin === expectedOrigin
      ? { ok: true, reason: 'referer_match' }
      : { ok: false, reason: refererOrigin ? 'referer_mismatch' : 'invalid_referer' };
  }

  // Fail closed: cookie-authenticated browser mutations must identify their origin.
  return { ok: false, reason: 'origin_missing' };
}

export function isMutatingMethod(method) {
  return MUTATING_METHODS.has(String(method || '').toUpperCase());
}
