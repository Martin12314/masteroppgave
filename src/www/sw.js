// sw.js — apex origin SW: proxy to APP_ORIGIN, sign requests, verify signed responses
let SIG_VERIFY_KEY = null;
let CLIENT_SIGN_KEY = null;

const CLIENT_REQ_KID = 'client-req-1';
const APP_ORIGIN = 'https://app.masteroppgave2026.no';
const METRICS_URL = APP_ORIGIN + '/metrics';

const BOOTSTRAP_PATHS = new Set([
  '/sw.js',
  '/Installer.js',
  '/installer.js',
  '/metrics'
]);
const CONFIG_CACHE = 'sw-config-v1';
const SIG_CACHE_KEY = '/__sig_verify_jwk.json';

// (your existing CLIENT_REQ_PRIVATE_JWK unchanged)
const CLIENT_REQ_PRIVATE_JWK = {
  kty: "RSA",
  kid: "client-req-1",
  use: "sig",
  alg: "PS256",
  key_ops: ["sign"],
  ext: true,

  n: "u31RCl3cGubeBaacyzc00o5jLnBlfNefG1sKCVQdNSSDJdOFJ96oS7oIlL31qEQM1hDCH3MIqZHwHzgTpAXfLZDaJme-GPDT8tJCj8jfbCMVpeGQMbV9N6N7nlQOk8MJEK8TeS8fK3I4M2QiZngbhKDEhNAejiaMvuqWd60RAM1UwsEY_XBNWPFO3Ig9uROrDyfQdu1LCD9tFsBzVBn-O-eFdEVa0wO4LMdQmGgEl6xFfEnNC36TFR7_TZJEuHuBS_rLtUVIy1arPUInN1snPkcBzadklNYpvT1szuMghVJES_-HQKgs_19KdA-4f1nezprTBQYrtMyBfGnCoM8JCQ",
  e: "AQAB",
  d: "GwlCpu6K_1wcVw9EG-_Nj7FVrwwpLlv_hxfVNiwpfBDUUp-SW4H5ndXpR92ur4GEolfPTm6tqJoxWKci-euY177EHnamTH1p6uGUFJzgTv0uMXn565kiweOyv02avocI5x1__uEjKwYxAYQmi8U1HqZ6QDasuU3ozN0SLpbH1WgHIWNGOuMZivcYG5qWAnS7-IGYo69JFLiH6j685qZb4GUmZSzzvB7R5AkgMkihxobur1JLBTY_dUVl1at7cbAF8uJ3GvnUtUXUMql8T0NHHJJegLah2UD4d3hliCxV9XO-JkBV-SNAmVAJh1mQMC41Jt_Jbmt__nAKwqU3448rUw",

  p:  "x0NDaJ0sdsuVwAy7_3E6N2Mb220Hroq0nu2-gr9MPkIhzmPFCLPu8BirRhXq9Nm8RXmDyZqBvgBbMZCJN5Vl99IQSK7iS2G2V4ZWkaKKOVmBb9P373_6PHDCTHNjVhhe1z1MEaYZdYqHTFC6PVEKBJvbiIW9rDqL6id3bxZ5F_c",
  q:  "8N_f3juGJxWmWOZzvfYTfbAz9oVa19rOD_pQ_l9S7gvd4jwXPzK4B7oYDYFlZef8nhevuVBB50i5euZgnKJD_XjEYo-a8ySr5QR_LUUv5DaspZJWy4KuSlX6rC-6TF_7yym_0bgM_zLWwD5rgMuQRfswurucdg1sWOa5WD8Kpv8",
  dp: "Sn6OE-02s07XNE5OdmgpQI2v22--gHVgo030fELySRBGPTe1cNR8Dozac0A8b797EGomZ9d4i8TsUvJbKkmTLnv9FH81IMNt_Pi_IoEmtdwNdPZE6efpcHEjYpt81rITutoytyJmwDfC7zf6-HN0kFaIU1jUmS_mIOsSTpiTOu8",
  dq: "rqAfFGXi5AL2Dg1Ea7sydjR_94DGUyb1rO-0ODWzUZCY06Ls14xVjoSDW4crk62TnqldY-OjY6F9lnPeJrAcym37MdkaZJt5YxbXfGJkTfa1Q3PMKM4cvReIG7yeOzB6wtcJkWj1Qy4AMm8OUNlDRvjMYxQQYiVpHyplxGwvtNE",
  qi: "IAFKq9qRqX3D--euRvDbPMN8WT2PWZxBeXCu8AtvCckjqlUapBBKT00FDRGX74I2RbaPpKLXVSMUNYTkTnM8XpIak_FC3GjjYXKvWo--Y8HjUab6klcX_-yJkxQI1Dvjvn5YHAKY8U8nzwP-QCL-6Z567gm1dRPvOlFEY5TDEY0"
};



/* ----------------- storage for verify key ----------------- */
async function saveSigJwk(jwk) {
  const c = await caches.open(CONFIG_CACHE);
  await c.put(SIG_CACHE_KEY, new Response(JSON.stringify(jwk), {
    headers: { 'Content-Type': 'application/json' }
  }));
}
async function loadSigJwk() {
  const c = await caches.open(CONFIG_CACHE);
  const r = await c.match(SIG_CACHE_KEY);
  if (!r) return null;
  try { return await r.json(); } catch { return null; }
}

/* ----------------- logging ----------------- */
function log(...args) {
  const msg = args.join(' ');
  console.log('[SW]', msg);
  self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    for (const client of clients) {
      client.postMessage({ type: 'SW_LOG', message: msg, ts: new Date().toISOString() });
    }
  });
}
function shortId(){ return Math.random().toString(16).slice(2,8); }
/* ----------------- metrics (NOW REAL) ----------------- */
async function postMetric(eventName, fields = {}) {
  const payload = { event: eventName, at: new Date().toISOString(), sw_scope: self.registration?.scope, ...fields };

  try {
    // Fire-and-forget: no CORS, opaque response (cannot read status)
await fetch(METRICS_URL, {
  method: 'POST',
  mode: 'no-cors',
  credentials: 'omit',
  cache: 'no-store',
  body: JSON.stringify(payload)
});
  } catch (e) {
    console.warn('METRICS POST failed', e);
  }
}

/* ----------------- helpers ----------------- */
function getRunTagFromRequest(req) {
  const v = req.headers.get('X-Run-Tag');
  return v && v.trim() ? v.trim() : null;
}
function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s=''; for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
function parseDigestHeader(cd) { const m = cd?.match(/sha-256=:(.+):/i); return m ? m[1] : null; }
function parseSigHeader(sig) { const m = sig?.match(/sig1=:(.+):/i); return m ? m[1] : null; }

function isProtectedContentType(ct) {
  ct = (ct || '').toLowerCase();
  return ct.includes('text/html') || ct.includes('application/json') || ct.includes('application/javascript') || ct.includes('text/javascript');
}
function utf8Bytes(str){ return new TextEncoder().encode(str).length; }
function approxHeaderBytes(headers) {
  let sum=0;
  for (const [k,v] of headers.entries()) sum += utf8Bytes(`${k}: ${v}\r\n`);
  return sum;
}

/* ----------------- verify response ----------------- */
async function verifyResponseWithTimings(response, bodyText, method, targetUri) {
  if (!SIG_VERIFY_KEY) throw new Error('verification key not installed');

  const cd = response.headers.get('Content-Digest');
  const sig = response.headers.get('Signature');
  const sigInput = response.headers.get('Signature-Input');
  if (!cd || !sig || !sigInput) throw new Error('missing security headers');

  const t0 = performance.now();

  const tDig0 = performance.now();
  const expectedB64 = parseDigestHeader(cd);
  if (!expectedB64) throw new Error('bad Content-Digest format');

  const actualHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bodyText));
  const actualB64 = toB64(new Uint8Array(actualHash));
  if (actualB64 !== expectedB64) throw new Error('digest mismatch');
  const digestMs = performance.now() - tDig0;

  const tSig0 = performance.now();
  const params = sigInput.replace(/^sig1=/, '');

  const base =
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"@status": ${response.status}\n` +
    `content-digest: ${cd}\n` +
    `"@signature-params": ${params}`;

  const sigB64 = parseSigHeader(sig);
  if (!sigB64) throw new Error('bad Signature format');

  const ok = await crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    SIG_VERIFY_KEY,
    b64ToBytes(sigB64),
    new TextEncoder().encode(base)
  );
  if (!ok) throw new Error('signature verification failed');
  const sigMs = performance.now() - tSig0;

  return { digestMs, sigMs, totalMs: performance.now() - t0 };
}

/* ----------------- client signing ----------------- */
async function ensureFixedClientSigningKey() {
  if (CLIENT_SIGN_KEY) return;
  CLIENT_SIGN_KEY = await crypto.subtle.importKey(
    "jwk",
    CLIENT_REQ_PRIVATE_JWK,
    { name: "RSA-PSS", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );
}
function buildSigInput(created) {
  return `("@method" "@target-uri" "content-digest");created=${created};keyid="${CLIENT_REQ_KID}";alg="rsa-pss-sha256"`;
}
async function signRequestHeaders(method, targetUri, bodyBytes, headers) {
  await ensureFixedClientSigningKey();
  const created = Math.floor(Date.now() / 1000);

  const hash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const cd = `sha-256=:${toB64(new Uint8Array(hash))}:`;
  headers.set('Content-Digest', cd);

  const sigInput = buildSigInput(created);

  const base =
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `content-digest: ${cd}\n` +
    `"@signature-params": ${sigInput}`;

  const sig = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    CLIENT_SIGN_KEY,
    new TextEncoder().encode(base)
  );

  headers.set('Signature-Input', `sig1=${sigInput}`);
  headers.set('Signature', `sig1=:${toB64(new Uint8Array(sig))}:`);
}

/* ----------------- lifecycle ----------------- */
// Install
self.addEventListener('install', event => {

  log('SW install');

  // Do NOT wrap skipWaiting in waitUntil
  self.skipWaiting();

});


// Activate
self.addEventListener('activate', event => {

  log('SW activate');

  event.waitUntil((async () => {

    await self.clients.claim();

    let restored = false;

    // restore verify key
    const jwk = await loadSigJwk();

    if (jwk) {

      try {

        SIG_VERIFY_KEY = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name:'RSA-PSS', hash:'SHA-256' },
          false,
          ['verify']
        );

        restored = true;

        log('restored SIG_VERIFY_KEY kid=' + (jwk.kid || '?'));

      } catch (err) {

        SIG_VERIFY_KEY = null;

        log('failed restore key:', err?.message || String(err));

      }

    }

    // send activation metric ONCE
    try {

      await postMetric('sw_activate_event', {
        restored_key: restored
      });

    } catch (e) {

      log('activate metric failed', e);

    }

  })());

});

self.addEventListener('message', async e => {
  if (e.data?.type !== 'SET_SIG_KEY') return;
  try {
    const jwk = e.data.jwk;
    SIG_VERIFY_KEY = await crypto.subtle.importKey('jwk', jwk, { name:'RSA-PSS', hash:'SHA-256' }, false, ['verify']);
    await saveSigJwk(jwk);
    await postMetric('sw_sig_key_installed', { kid: jwk?.kid || '?' });

    e.source?.postMessage?.({ type:'SIG_KEY_INSTALLED', kid: jwk?.kid || '?' });
  } catch (err) {
    SIG_VERIFY_KEY = null;
    await postMetric('sw_sig_key_error', { err: err?.message || String(err) });
    e.source?.postMessage?.({ type:'SIG_KEY_ERROR', message: err?.message || String(err) });
  }
});

/* ----------------- fetch proxy ----------------- */
function shouldBypass(url) {
  if (!url.protocol.startsWith('http')) return true;
  if (url.origin !== self.location.origin) return true;

  if (BOOTSTRAP_PATHS.has(url.pathname)) return true;

  // bypass metrics completely
  if (url.pathname === '/metrics') return true;

  return false;
}
function buildUpstreamUrl(url) { return APP_ORIGIN + url.pathname + url.search; }

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (shouldBypass(url)) return;

  event.respondWith((async () => {
    const isUnsigned = url.pathname.startsWith('/unsigned/');
    const rid = shortId();
    const started = performance.now();
    const runTag = getRunTagFromRequest(event.request);

    // Gate: only block non-bootstrap if we truly have no key yet
    if (!SIG_VERIFY_KEY) {
      if (url.pathname !== '/' && !BOOTSTRAP_PATHS.has(url.pathname)) {
        return Response.redirect('/', 302);
      }
      return fetch(event.request);
    }

    let upstreamUrl = buildUpstreamUrl(url);

    // also push rt= for server-side tagging
    if (runTag) {
      const u = new URL(upstreamUrl);
      u.searchParams.set('rt', runTag);
      upstreamUrl = u.toString();
    }

    const init = {
      method: event.request.method,
      redirect: 'follow',
      credentials: 'omit',
      cache: 'no-store',
    };

    let bodyBytes;
    if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      bodyBytes = await event.request.clone().arrayBuffer();
      init.body = bodyBytes;
    } else {
      bodyBytes = new Uint8Array(0).buffer;
    }

    // ✅ IMPORTANT: forward X-Run-Tag upstream
    const headers = new Headers();
    if (runTag) headers.set('X-Run-Tag', runTag);

    if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      headers.set('Content-Type', event.request.headers.get('Content-Type') || 'application/octet-stream');
    }

    // sign
    const u = new URL(upstreamUrl);
    const targetUri = u.pathname + u.search;
    await signRequestHeaders(event.request.method, targetUri, bodyBytes, headers);
    init.headers = headers;

    const tUp0 = performance.now();
    const res = await fetch(upstreamUrl, init);
    const upstreamMs = performance.now() - tUp0;
    const ct = res.headers.get('Content-Type') || '';

    // unsigned: skip verify
    if (isUnsigned) {
      await postMetric('sw_unsigned_passthrough', { runTag, path:url.pathname, status:res.status, content_type:ct, sw_fetch_upstream_ms: Math.round(upstreamMs) });
      return res;
    }

    if (res.type === 'opaque') return res;
    if (!isProtectedContentType(ct)) return res;

    const text = await res.clone().text();

    const secHeaders = new Headers();
    const uCD = res.headers.get('Content-Digest');
    const uSI = res.headers.get('Signature-Input');
    const uSG = res.headers.get('Signature');
    if (uCD) secHeaders.set('Content-Digest', uCD);
    if (uSI) secHeaders.set('Signature-Input', uSI);
    if (uSG) secHeaders.set('Signature', uSG);
    const respSigHeaderBytes = approxHeaderBytes(secHeaders);

    try {
      const timings = await verifyResponseWithTimings(res, text, event.request.method, targetUri);
      const totalWallMs = performance.now() - started;

      await postMetric('sw_verify_ok', {
        runTag,
        path: url.pathname,
        status: res.status,
        content_type: ct,
        sw_fetch_upstream_ms: Math.round(upstreamMs),
        sw_verify_total_ms: Math.round(timings.totalMs),
        sw_digest_ms: Math.round(timings.digestMs),
        sw_signature_verify_ms: Math.round(timings.sigMs),
        resp_body_bytes: utf8Bytes(text),
        resp_sig_header_bytes: respSigHeaderBytes,
        sw_total_wall_ms: Math.round(totalWallMs)
      });

      const outHeaders = new Headers(res.headers);
      outHeaders.delete('content-length');
      return new Response(text, { status: res.status, statusText: res.statusText, headers: outHeaders });
    } catch (err) {
      await postMetric('sw_verify_block', {
        runTag,
        path: url.pathname,
        status: res.status,
        content_type: ct,
        err: err?.message || String(err),
        sw_fetch_upstream_ms: Math.round(upstreamMs),
        resp_body_bytes: utf8Bytes(text),
        resp_sig_header_bytes: respSigHeaderBytes
      });

      return new Response('Blocked by Service Worker (integrity violation): ' + (err?.message || 'unknown'), {
        status: 498,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }
  })());
});