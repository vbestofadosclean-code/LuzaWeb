const base = String(process.env.LOAD_URL || '').trim().replace(/\/$/, '');
if (!base) throw new Error('Define LOAD_URL com o endereço do LuzaWeb, por exemplo https://teu-site.netlify.app.');
const concurrency = Math.max(1, Math.min(100, Number.parseInt(process.env.LOAD_CONCURRENCY || '10', 10) || 10));
const requests = Math.max(1, Math.min(10000, Number.parseInt(process.env.LOAD_REQUESTS || '100', 10) || 100));
const timeoutMs = Math.max(1000, Math.min(30000, Number.parseInt(process.env.LOAD_TIMEOUT_MS || '10000', 10) || 10000));
const parsedBase = new URL(base);
const isLoopbackTarget = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(parsedBase.hostname.toLowerCase());
if (!['http:', 'https:'].includes(parsedBase.protocol)) throw new Error('LOAD_URL deve usar HTTP ou HTTPS.');
if (!isLoopbackTarget && parsedBase.protocol !== 'https:') throw new Error('Para um destino remoto, LOAD_URL tem de usar HTTPS.');
if (!isLoopbackTarget && process.env.LOAD_TEST_CONFIRM !== 'YES') {
  throw new Error('O teste pode gerar tráfego. Para um destino remoto, confirma explicitamente com LOAD_TEST_CONFIRM=YES. Começa com poucos pedidos.');
}
const url = new URL('/api/health/ready', parsedBase).toString();
const results = [];
let next = 0;
async function worker() {
  while (true) {
    const index = next++;
    if (index >= requests) return;
    const started = performance.now();
    let status = 0;
    let error = '';
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'cache-control': 'no-cache' } });
      status = response.status;
      await response.arrayBuffer();
    } catch (caught) { error = String(caught?.name || 'request_failed'); }
    results.push({ duration: performance.now() - started, status, error });
  }
}
await Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker()));
const durations = results.map(item => item.duration).sort((a, b) => a - b);
const percentile = p => durations[Math.min(durations.length - 1, Math.ceil(durations.length * p) - 1)] || 0;
const failed = results.filter(item => item.error || item.status < 200 || item.status >= 400).length;
console.log(JSON.stringify({ target: url, requests, concurrency, failed, success_rate_percent: Number(((requests - failed) / requests * 100).toFixed(2)), latency_ms: { min: Number((durations[0] || 0).toFixed(1)), median: Number((percentile(0.5)).toFixed(1)), p95: Number((percentile(0.95)).toFixed(1)), max: Number((durations.at(-1) || 0).toFixed(1)) }, statuses: results.reduce((out, item) => { const key = item.error ? `error:${item.error}` : String(item.status); out[key] = (out[key] || 0) + 1; return out; }, {}) }, null, 2));
if (failed) process.exitCode = 1;
