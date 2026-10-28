import { isIP } from 'node:net';

function readHeader(req, name) {
  if (typeof req?.get === 'function') return req.get(name);
  const value = req?.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

export function normalizeClientIp(value) {
  if (typeof value !== 'string') return null;
  let candidate = value.trim();
  // Do not accept comma-separated proxy chains or address:port strings as one IP.
  if (!candidate || candidate.includes(',') || /\s/.test(candidate)) return null;
  if (candidate.startsWith('[') && candidate.endsWith(']')) candidate = candidate.slice(1, -1);
  if (candidate.startsWith('::ffff:') && isIP(candidate) === 6) {
    const mapped = candidate.slice('::ffff:'.length);
    if (isIP(mapped) === 4) return mapped;
  }
  return isIP(candidate) ? candidate.toLowerCase() : null;
}

/**
 * Return an IP suitable for security limits. On Netlify, prefer its edge-provided
 * client-connection header and deliberately ignore X-Forwarded-For if that header
 * is malformed or absent. For self-hosting, req.ip is used only when an operator
 * explicitly configures trusted proxy hops; otherwise the socket peer is used.
 */
export function getRequestClientIp(req, options = {}) {
  const netlify = options.netlify ?? Boolean(process.env.NETLIFY);
  if (netlify) {
    const edgeIp = normalizeClientIp(readHeader(req, 'x-nf-client-connection-ip'));
    if (edgeIp) return edgeIp;
    return normalizeClientIp(req?.socket?.remoteAddress) || 'unknown';
  }

  const hops = Number.parseInt(String(options.trustProxyHops ?? process.env.TRUST_PROXY_HOPS ?? '0'), 10);
  if (Number.isInteger(hops) && hops > 0) {
    const trustedProxyIp = normalizeClientIp(req?.ip);
    if (trustedProxyIp) return trustedProxyIp;
  }
  return normalizeClientIp(req?.socket?.remoteAddress) || normalizeClientIp(req?.ip) || 'unknown';
}
