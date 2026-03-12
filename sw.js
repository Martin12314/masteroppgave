// sw.js
// Purpose:
// - proxy same-origin app requests to APP_ORIGIN
// - sign upstream requests (with X-Client-Key-Id + content-digest + signature)
// - verify signed protected responses
// - DO NOT proxy metrics
// - metrics must be sent directly to APP_ORIGIN from the page

let SIG_VERIFY_KEY = null;
let CLIENT_SIGN_KEY = null;

const SW_BUILD = '2026-03-12-no-metrics-forward-v2';

const CLIENT_REQ_KID = 'client-req-1';
const APP_ORIGIN = 'https://app.masteroppgave2026.no';

const BOOTSTRAP_PATHS = new Set([
  '/sw.js',
  '/Installer.js',
  '/installer.js',
  '/favicon.ico'
]);

const CONFIG_CACHE = 'sw-config-v1';
const SIG_CACHE_KEY = '/__sig_verify_jwk.json';

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
  p: "x0NDaJ0sdsuVwAy7_3E6N2Mb220Hroq0nu2-gr9MPkIhzmPFCLPu8BirRhXq9Nm8RXmDyZqBvgBbMZCJN5Vl99IQSK7iS2G2V4ZWkaKKOVmBb9P373_6PHDCTHNjVhhe1z1MEaYZdYqHTFC6PVEKBJvbiIW9rDqL6id3bxZ5F_c",
  q: "8N_f3juGJxWmWOZzvfYTfbAz9oVa19rOD_pQ_l9S7gvd4jwXPzK4B7oYDYFlZef8nhevuVBB50i5euZgnKJD_XjEYo-a8ySr5QR_LUUv5DaspZJWy4KuSlX6rC-6TF_7yym_0bgM_zLWwD5rgMuQRfswurucdg1sWOa5WD8Kpv8",
  dp: "Sn6OE-02s07XNE5OdmgpQI2v22--gHVgo030fELySRBGPTe1cNR8Dozac0A8b797EGomZ9d4i8TsUvJbKkmTLnv9FH81IMNt_Pi_IoEmtdwNdPZE6efpcHEjYpt81rITutoytyJmwDfC7zf6-HN0kFaIU1jUmS_mIOsSTpiTOu8",
  dq: "rqAfFGXi5AL2Dg1Ea7sydjR_94DGUyb1rO-0ODWzUZCY06Ls14xVjoSDW4crk62TnqldY-OjY6F9lnPeJrAcym37MdkaZJt5YxbXfGJkTfa1Q3PMKM4cvReIG7yeOzB6wtcJkWj1Qy4AMm8OUNlDRvjMYxQQYiVpHyplxGwvtNE",
  qi: "IAFKq9qRqX3D--euRvDbPMN8WT2PWZxBeXCu8AtvCckjqlUapBBKT00FDRGX74I2RbaPpKLXVSMUNYTkTnM8XpIak_FC3GjjYXKvWo--Y8HjUab6klcX_-yJkxQI1Dvjvn5YHAKY8U8nzwP-QCL-6Z567gm1dRPvOlFEY5TDEY0"
};

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

function log(...args) {
  const msg = args.join(' ');
  console.log('[SW]', msg);
  self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    for (const client of clients) {
      client.postMessage({ type: 'SW_LOG', message: msg, ts: new Date().toISOString() });
    }
  });
}

function getRunTagFromRequest(req) {
  const v = req.headers.get('X-Run-Tag');
  return v && v.trim() ? v.trim() : null;
}

function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function parseDigestHeader(cd) {
  const m = cd?.match(/sha-256=:(.+):/i);
  return m ? m[1] : null;
}

function parseSigHeader(sig) {
  const m = sig?.match(/sig1=:(.+):/i);
  return m ? m[1] : null;
}

function isProtectedContentType(ct) {
  ct = (ct || '').toLowerCase();
  return ct.includes('text/html') ||
         ct.includes('application/json') ||
         ct.includes('application/javascript') ||
         ct.includes('text/javascript');
}

async function verifyResponseWithTimings(response, bodyText, method, targetUri) {
  if (!SIG_VERIFY_KEY) throw new Error('verification key not installed');

  const cd = response.headers.get('Content-Digest');
  const sig = response.headers.get('Signature');
  const sigInput = response.headers.get('Signature-Input');

  if (!cd) throw new Error('missing Content-Digest');
  if (!sig) throw new Error('missing Signature');
  if (!sigInput) throw new Error('missing Signature-Input');

  const expectedB64 = parseDigestHeader(cd);
  if (!expectedB64) throw new Error('bad Content-Digest format');

  const actualHash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bodyText));
  const actualB64 = toB64(new Uint8Array(actualHash));
  if (actualB64 !== expectedB64) throw new Error('digest mismatch');

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
  return true;
}

async function ensureFixedClientSigningKey() {
  if (CLIENT_SIGN_KEY) return;
  CLIENT_SIGN_KEY = await crypto.subtle.importKey(
    'jwk',
    CLIENT_REQ_PRIVATE_JWK,
    { name: 'RSA-PSS', hash: { name: 'SHA-256' } },
    false,
    ['sign']
  );
}

// FIX: declares x-client-key-id as the first covered component so the
// server's verifyRequest base-string matches exactly.
function buildSigInput(created) {
  return `("x-client-key-id" "@method" "@target-uri" "content-digest");created=${created};keyid="${CLIENT_REQ_KID}";alg="rsa-pss-sha256"`;
}

// FIX: sets X-Client-Key-Id header on every upstream request and includes
// it as the first line of the signature base string, matching the server's
// verifyRequest which always prepends "x-client-key-id: <id>\n".
async function signRequestHeaders(method, targetUri, bodyBytes, headers) {
  await ensureFixedClientSigningKey();
  const created = Math.floor(Date.now() / 1000);

  const hash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const cd = `sha-256=:${toB64(new Uint8Array(hash))}:`;

  headers.set('Content-Digest', cd);
  // Required by server verifyRequest — must be sent and covered by the signature
  headers.set('X-Client-Key-Id', CLIENT_REQ_KID);

  const sigInput = buildSigInput(created);

  // Base string must match server's verifyRequest construction exactly:
  //   "x-client-key-id: <id>\n"
  //   "\"@method\": \"<lc-method>\"\n"
  //   "\"@target-uri\": \"<path+query>\"\n"
  //   "content-digest: <cd>\n"
  //   "\"@signature-params\": <sigInput>"
  const base =
    `x-client-key-id: ${CLIENT_REQ_KID}\n` +
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

self.addEventListener('install', () => {
  log('SW install build=' + SW_BUILD);
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  log('SW activate build=' + SW_BUILD);

  event.waitUntil((async () => {
    await self.clients.claim();

    const jwk = await loadSigJwk();
    if (jwk) {
      try {
        SIG_VERIFY_KEY = await crypto.subtle.importKey(
          'jwk',
          jwk,
          { name: 'RSA-PSS', hash: 'SHA-256' },
          false,
          ['verify']
        );
        log('restored SIG_VERIFY_KEY kid=' + (jwk.kid || '?'));
      } catch (err) {
        SIG_VERIFY_KEY = null;
        log('failed restore key: ' + (err?.message || String(err)));
      }
    }
  })());
});

self.addEventListener('message', async e => {
  if (e.data?.type === 'PING_SW') {
    e.source?.postMessage?.({
      type: 'PONG_SW',
      sw_build: SW_BUILD,
      script_url: self.registration?.active?.scriptURL || self.location.href
    });
    return;
  }

  if (e.data?.type !== 'SET_SIG_KEY') return;

  try {
    const jwk = e.data.jwk;
    SIG_VERIFY_KEY = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify']
    );

    await saveSigJwk(jwk);

    e.source?.postMessage?.({
      type: 'SIG_KEY_INSTALLED',
      kid: jwk?.kid || '?',
      sw_build: SW_BUILD
    });
  } catch (err) {
    SIG_VERIFY_KEY = null;
    e.source?.postMessage?.({
      type: 'SIG_KEY_ERROR',
      message: err?.message || String(err),
      sw_build: SW_BUILD
    });
  }
});

function shouldBypass(url) {
  if (!url.protocol.startsWith('http')) return true;
  if (url.origin !== self.location.origin) return true;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return true;
  return false;
}

function buildUpstreamUrl(url) {
  return APP_ORIGIN + url.pathname + url.search;
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (shouldBypass(url)) return;

  if (url.pathname === '/metrics' || url.pathname === '/metrics/ingest') {
    event.respondWith(new Response(JSON.stringify({
      ok: false,
      error: 'Metrics are no longer forwarded by the service worker. Send them directly to APP_ORIGIN /metrics/ingest.'
    }), {
      status: 410,
      headers: { 'Content-Type': 'application/json' }
    }));
    return;
  }

  event.respondWith((async () => {
    const isUnsigned = url.pathname.startsWith('/unsigned/');
    const runTag = getRunTagFromRequest(event.request);

    if (!SIG_VERIFY_KEY) {
      if (url.pathname !== '/' && !BOOTSTRAP_PATHS.has(url.pathname)) {
        return Response.redirect('/', 302);
      }
      return fetch(event.request);
    }

    let upstreamUrl = buildUpstreamUrl(url);
    if (runTag) {
      const u0 = new URL(upstreamUrl);
      u0.searchParams.set('rt', runTag);
      upstreamUrl = u0.toString();
    }

    const init = {
      method: event.request.method,
      redirect: 'follow',
      credentials: 'omit',
      cache: 'no-store'
    };

    let bodyBytes;
    let bodyU8;

    if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      bodyBytes = await event.request.clone().arrayBuffer();
      bodyU8 = new Uint8Array(bodyBytes);
      init.body = bodyU8;
    } else {
      bodyBytes = new Uint8Array(0).buffer;
      bodyU8 = new Uint8Array(0);
    }

    const headers = new Headers();

    const runTagHdr = event.request.headers.get('X-Run-Tag');
    if (runTagHdr) headers.set('X-Run-Tag', runTagHdr);

    const contentType = event.request.headers.get('Content-Type');
    if (contentType && event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      headers.set('Content-Type', contentType);
    }

    const u = new URL(upstreamUrl);
    const targetUri = u.pathname + u.search;

    await signRequestHeaders(event.request.method, targetUri, bodyBytes, headers);
    init.headers = headers;

    let res;
    try {
      res = await fetch(upstreamUrl, init);
    } catch (err) {
      return new Response('Upstream fetch failed: ' + (err?.message || String(err)), {
        status: 502,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    const ct = res.headers.get('Content-Type') || '';

    if (isUnsigned) return res;
    if (res.type === 'opaque') return res;
    if (!isProtectedContentType(ct)) return res;

    const text = await res.clone().text();

    await verifyResponseWithTimings(res, text, event.request.method, targetUri);

    const outHeaders = new Headers(res.headers);
    outHeaders.delete('content-length');

    return new Response(text, {
      status: res.status,
      statusText: res.statusText,
      headers: outHeaders
    });
  })());
});
