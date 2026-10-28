const STATUS_CODES = Object.freeze({
  400: 'INVALID_REQUEST',
  401: 'UNAUTHORIZED',
  403: 'FORBIDDEN',
  404: 'NOT_FOUND',
  405: 'METHOD_NOT_ALLOWED',
  408: 'REQUEST_TIMEOUT',
  409: 'CONFLICT',
  413: 'PAYLOAD_TOO_LARGE',
  415: 'UNSUPPORTED_MEDIA_TYPE',
  422: 'UNPROCESSABLE_ENTITY',
  429: 'RATE_LIMITED',
  500: 'INTERNAL_ERROR',
  502: 'BAD_GATEWAY',
  503: 'SERVICE_UNAVAILABLE',
  504: 'GATEWAY_TIMEOUT'
});

const SAFE_CUSTOM_CODES = new Set(['CSRF_ORIGIN_REJECTED', 'INVALID_COLUMNS', 'RATE_LIMITED', 'NOT_FOUND']);

const SAFE_SERVER_MESSAGES = Object.freeze({
  500: 'Ocorreu um erro interno. Tenta novamente mais tarde.',
  502: 'Não foi possível concluir o pedido porque um serviço externo não está disponível.',
  503: 'O serviço está temporariamente indisponível. Tenta novamente mais tarde.',
  504: 'O serviço demorou demasiado tempo a responder. Tenta novamente.'
});

const SAFE_CLIENT_MESSAGES = Object.freeze({
  400: 'Pedido inválido. Verifica os dados enviados.',
  401: 'É necessário iniciar sessão ou autenticar o pedido.',
  403: 'Não tens autorização para executar esta operação.',
  404: 'O recurso pedido não foi encontrado.',
  405: 'Método HTTP não permitido.',
  408: 'O pedido demorou demasiado tempo.',
  409: 'O pedido entra em conflito com o estado atual.',
  413: 'O pedido excede o tamanho permitido.',
  415: 'Formato do pedido não suportado.',
  422: 'Os dados enviados não podem ser processados.',
  429: 'Demasiados pedidos. Tenta novamente mais tarde.'
});

function safeScalar(value, maxLength = 80) {
  if (typeof value !== 'string' || value.length > maxLength) return undefined;
  if (/[\u0000-\u001f\u007f]/.test(value)) return undefined;
  return value;
}

function publicCode(status, requestedCode) {
  // Preserve only stable application-defined symbolic codes for 4xx errors.
  // A database/provider error code must never replace the generic 5xx code.
  if (status < 500 && typeof requestedCode === 'string' && SAFE_CUSTOM_CODES.has(requestedCode)) {
    return requestedCode;
  }
  return STATUS_CODES[status] || (status >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_FAILED');
}

/**
 * Normalize API error responses so internal exceptions and provider messages
 * cannot leak through JSON responses. Keeps only intentionally safe metadata.
 */
export function normalizeApiErrorEnvelope(statusValue, body, requestId) {
  const status = Number.isInteger(Number(statusValue)) && Number(statusValue) >= 400 && Number(statusValue) <= 599
    ? Number(statusValue)
    : 500;
  const source = body && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const normalized = {};

  if (source.ok === false) normalized.ok = false;
  for (const key of ['app', 'status', 'database']) {
    const value = safeScalar(source[key]);
    if (value !== undefined) normalized[key] = value;
  }
  const retrySeconds = Number(source.retry_after_seconds);
  if (Number.isSafeInteger(retrySeconds) && retrySeconds >= 0 && retrySeconds <= 86400) {
    normalized.retry_after_seconds = retrySeconds;
  }

  const safeError = status >= 500
    ? (SAFE_SERVER_MESSAGES[status] || 'Ocorreu um erro interno. Tenta novamente mais tarde.')
    : safeScalar(source.error, 300) || SAFE_CLIENT_MESSAGES[status] || 'Não foi possível concluir o pedido.';

  normalized.error = safeError;
  normalized.code = publicCode(status, source.code);
  normalized.request_id = safeScalar(requestId, 100) || safeScalar(source.request_id, 100) || null;
  return normalized;
}

export { STATUS_CODES as API_ERROR_STATUS_CODES };
