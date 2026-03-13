// /sw.js
import { CompactEncrypt, importJWK } from 'https://cdn.jsdelivr.net/npm/jose@5/+esm';

let SIG_VERIFY_KEY = null;
let CLIENT_SIGN_KEY = null;
let CLIENT_PUB_JWK = null;
let CLIENT_REQ_KID = null;

const SW_BUILD = '2026-03-13-jwe-register-v5-dynamic-client-key';
const APP_ORIGIN = 'https://app.masteroppgave2026.no';

const BOOTSTRAP_PATHS = new Set([
  '/',
  '/baseline.html',
  '/sw.js',
  '/Installer.js',
  '/installer.js',
  '/favicon.ico',
  '/styles.css',
  '/assets/metrics-client.js',
  '/assets/metrics-debug.html'
]);

const CONFIG_CACHE = 'sw-config-v2';
const SIG_CACHE_KEY = '/__sig_verify_jwk.json';
const CLIENT_REQ_KEYPAIR_CACHE_KEY = '/__client_req_keypair.json';

async function cachePutJson(key, value) {
  const c = await caches.open(CONFIG_CACHE);
  await c.put(
    key,
    new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } })
  );
}

async function cacheGetJson(key) {
  const c = await caches.open(CONFIG_CACHE);
  const r = await c.match(key);
  if (!r) return null;
  try {
    return await r.json();
  } catch {
    return null;
  }
}

async function saveSigJwk(jwk) {
  await cachePutJson(SIG_CACHE_KEY, jwk);
}

async function loadSigJwk() {
  return await cacheGetJson(SIG_CACHE_KEY);
}

function log(...args) {
  const msg = args.join(' ');
  console.log('[SW]', msg);
  self.clients
    .matchAll({ includeUncontrolled: true })
    .then((clients) => {
      for (const client of clients) {
        client.postMessage({ type: 'SW_LOG', message: msg, ts: new Date().toISOString() });
      }
    })
    .catch(() => {});
}

async function respond(event, message) {
  // Why: event.source can be null in some edge cases; clientId is safer; broadcast is last-resort.
  try {
    if (event.source?.postMessage) {
      event.source.postMessage(message);
      return;
    }
  } catch {}

  try {
    if (event.clientId) {
      const c = await self.clients.get(event.clientId);
      if (c?.postMessage) {
        c.postMessage(message);
        return;
      }
    }
  } catch {}

  try {
    const all = await self.clients.matchAll({ includeUncontrolled: true });
    for (const c of all) c.postMessage(message);
  } catch {}
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
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
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
  return (
    ct.includes('text/html') ||
    ct.includes('application/json') ||
    ct.includes('application/javascript') ||
    ct.includes('text/javascript')
  );
}

function shouldBypass(url) {
  if (!url.protocol.startsWith('http')) return true;
  if (url.origin !== self.location.origin) return true;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return true;
  return false;
}

function buildUpstreamUrl(url) {
  return APP_ORIGIN + url.pathname + url.search;
}

function buildSigInput(created) {
  return `("@method" "@target-uri" "content-digest");created=${created};keyid="${CLIENT_REQ_KID}";alg="rsa-pss-sha256"`;
}

async function generateClientSigningKeyMaterial() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

  const kid = 'client-req-' + crypto.randomUUID();

  privateJwk.kid = kid;
  privateJwk.use = 'sig';
  privateJwk.alg = 'PS256';
  privateJwk.key_ops = ['sign'];
  privateJwk.ext = true;

  publicJwk.kid = kid;
  publicJwk.use = 'sig';
  publicJwk.alg = 'PS256';
  publicJwk.key_ops = ['verify'];
  publicJwk.ext = true;

  await cachePutJson(CLIENT_REQ_KEYPAIR_CACHE_KEY, {
    client_key_id: kid,
    created_at_ms: Date.now(),
    private_jwk: privateJwk,
    public_jwk: publicJwk
  });

  CLIENT_REQ_KID = kid;
  CLIENT_PUB_JWK = publicJwk;
  CLIENT_SIGN_KEY = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['sign']
  );

  log('generated client signing key kid=' + kid);
}

async function ensureClientSigningKey() {
  if (CLIENT_SIGN_KEY && CLIENT_REQ_KID && CLIENT_PUB_JWK) return;

  const saved = await cacheGetJson(CLIENT_REQ_KEYPAIR_CACHE_KEY);
  if (saved?.private_jwk && saved?.public_jwk && saved?.client_key_id) {
    CLIENT_REQ_KID = saved.client_key_id;
    CLIENT_PUB_JWK = saved.public_jwk;
    CLIENT_SIGN_KEY = await crypto.subtle.importKey(
      'jwk',
      saved.private_jwk,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['sign']
    );
    log('restored client signing key kid=' + CLIENT_REQ_KID);
    return;
  }

  await generateClientSigningKeyMaterial();
}

async function signRequestHeaders(method, targetUri, bodyBytes, headers) {
  await ensureClientSigningKey();

  const created = Math.floor(Date.now() / 1000);
  const hash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const cd = `sha-256=:${toB64(new Uint8Array(hash))}:`;
  headers.set('Content-Digest', cd);

  const sigInput = buildSigInput(created);

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

  headers.set('X-Client-Key-Id', CLIENT_REQ_KID);
  headers.set('Signature-Input', `sig1=${sigInput}`);
  headers.set('Signature', `sig1=:${toB64(new Uint8Array(sig))}:`);
}

async function encryptEnvelopeAsJwe(envelope, jweJwk) {
  const publicKey = await importJWK(
    {
      kty: 'RSA',
      kid: jweJwk.kid,
      n: jweJwk.n,
      e: jweJwk.e,
      alg: 'RSA-OAEP-256',
      use: 'enc',
      ext: true
    },
    'RSA-OAEP-256'
  );

  return await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(envelope)))
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',
      enc: 'A256GCM',
      kid: jweJwk.kid
    })
    .encrypt(publicKey);
}

async function registerClientKey(jweJwk) {
  await ensureClientSigningKey();

  const now = Math.floor(Date.now() / 1000);

  const payload = {
    client_key_id: CLIENT_REQ_KID,
    created: now,
    expires: now + 86400,
    sw_build: SW_BUILD,
    pub_jwk: {
      kty: CLIENT_PUB_JWK.kty,
      kid: CLIENT_PUB_JWK.kid,
      use: 'sig',
      alg: 'PS256',
      key_ops: ['verify'],
      ext: true,
      n: CLIENT_PUB_JWK.n,
      e: CLIENT_PUB_JWK.e
    }
  };

  const stableJson = JSON.stringify({
    client_key_id: payload.client_key_id,
    created: payload.created,
    expires: payload.expires,
    sw_build: payload.sw_build,
    pub_jwk: payload.pub_jwk
  });

  const proofSig = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    CLIENT_SIGN_KEY,
    new TextEncoder().encode(stableJson)
  );

  const envelope = {
    payload,
    proof_sig_b64: toB64(new Uint8Array(proofSig))
  };

  const ciphertext = await encryptEnvelopeAsJwe(envelope, jweJwk);

  const res = await fetch(APP_ORIGIN + '/req-key/register', {
    method: 'POST',
    mode: 'cors',
    credentials: 'omit',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enc: 'jwe', kid: jweJwk.kid, ciphertext })
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error('registration failed: HTTP ' + res.status + ' ' + txt);
  }

  log('client key registered kid=' + CLIENT_REQ_KID + ' expires=' + payload.expires);
}

async function verifyResponseWithTimings(response, bodyBytes, method, targetUri) {
  if (!SIG_VERIFY_KEY) throw new Error('verification key not installed');

  const cd = response.headers.get('Content-Digest');
  const sig = response.headers.get('Signature');
  const sigInput = response.headers.get('Signature-Input');

  if (!cd) throw new Error('missing Content-Digest');
  if (!sig) throw new Error('missing Signature');
  if (!sigInput) throw new Error('missing Signature-Input');

  const expectedB64 = parseDigestHeader(cd);
  if (!expectedB64) throw new Error('bad Content-Digest format');

  const actualHash = await crypto.subtle.digest('SHA-256', bodyBytes);
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

self.addEventListener('install', (event) => {
  log('SW install build=' + SW_BUILD);
  event.waitUntil(
    (async () => {
      await self.skipWaiting();
      await ensureClientSigningKey();
    })()
  );
});

self.addEventListener('activate', (event) => {
  log('SW activate build=' + SW_BUILD);
  event.waitUntil(
    (async () => {
      await self.clients.claim();
      await ensureClientSigningKey();

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
    })()
  );
});

self.addEventListener('message', (event) => {
  const data = event.data || {};

  if (data.type === 'PING_SW') {
    event.waitUntil(
      respond(event, {
        type: 'PONG_SW',
        sw_build: SW_BUILD,
        script_url: self.registration?.active?.scriptURL || self.location.href,
        client_key_id: CLIENT_REQ_KID
      })
    );
    return;
  }

  if (data.type === 'SET_SIG_KEY') {
    event.waitUntil(
      (async () => {
        try {
          const jwk = data.jwk;

          SIG_VERIFY_KEY = await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'RSA-PSS', hash: 'SHA-256' },
            false,
            ['verify']
          );

          await saveSigJwk(jwk);

          await respond(event, {
            type: 'SIG_KEY_INSTALLED',
            kid: jwk?.kid || '?',
            sw_build: SW_BUILD
          });
        } catch (err) {
          SIG_VERIFY_KEY = null;
          await respond(event, {
            type: 'SIG_KEY_ERROR',
            message: err?.message || String(err),
            sw_build: SW_BUILD
          });
        }
      })()
    );
    return;
  }

  if (data.type === 'REGISTER_CLIENT_KEY') {
    event.waitUntil(
      (async () => {
        try {
          await registerClientKey(data.jweJwk);
          await respond(event, { type: 'REGISTER_OK', client_key_id: CLIENT_REQ_KID });
        } catch (err) {
          await respond(event, { type: 'REGISTER_FAIL', message: err?.message || String(err) });
        }
      })()
    );
    return;
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (shouldBypass(url)) return;

  if (url.pathname === '/metrics' || url.pathname === '/metrics/ingest') {
    event.respondWith(
      new Response(
        JSON.stringify({
          ok: false,
          error:
            'Metrics are no longer forwarded by the service worker. Send them directly to APP_ORIGIN /metrics/ingest.'
        }),
        { status: 410, headers: { 'Content-Type': 'application/json' } }
      )
    );
    return;
  }

  event.respondWith(
    (async () => {
      try {
        const req = event.request;
        const isUnsigned = url.pathname.startsWith('/unsigned/');
        const runTag = getRunTagFromRequest(req);

        if (!SIG_VERIFY_KEY || !CLIENT_SIGN_KEY || !CLIENT_REQ_KID) {
          return Response.redirect('/baseline.html', 302);
        }

        let upstreamUrl = buildUpstreamUrl(url);
        if (runTag) {
          const u0 = new URL(upstreamUrl);
          u0.searchParams.set('rt', runTag);
          upstreamUrl = u0.toString();
        }

        let bodyBytes;
        if (req.method === 'GET' || req.method === 'HEAD') {
          bodyBytes = new Uint8Array(0);
        } else {
          bodyBytes = new Uint8Array(await req.clone().arrayBuffer());
        }

        const headers = new Headers();
        const contentType = req.headers.get('Content-Type');
        if (contentType && req.method !== 'GET' && req.method !== 'HEAD') headers.set('Content-Type', contentType);

        const accept = req.headers.get('Accept');
        if (accept) headers.set('Accept', accept);

        const runTagHdr = req.headers.get('X-Run-Tag');
        if (runTagHdr) headers.set('X-Run-Tag', runTagHdr);

        const reqSeqHdr = req.headers.get('X-Req-Seq');
        if (reqSeqHdr) headers.set('X-Req-Seq', reqSeqHdr);

        const u = new URL(upstreamUrl);
        const targetUri = u.pathname + u.search;

        await signRequestHeaders(req.method, targetUri, bodyBytes, headers);

        const signedReq = new Request(upstreamUrl, {
          method: req.method,
          headers,
          body: req.method === 'GET' || req.method === 'HEAD' ? undefined : bodyBytes,
          redirect: 'follow',
          cache: 'no-store',
          mode: 'cors',
          credentials: 'omit'
        });

        const res = await fetch(signedReq);
        const ct = res.headers.get('Content-Type') || '';

        if (isUnsigned) return res;
        if (res.type === 'opaque') return res;
        if (!isProtectedContentType(ct)) return res;

        const responseBytes = new Uint8Array(await res.clone().arrayBuffer());

        await verifyResponseWithTimings(res, responseBytes, req.method, targetUri);

        const outHeaders = new Headers(res.headers);
        outHeaders.delete('content-length');

        return new Response(responseBytes, {
          status: res.status,
          statusText: res.statusText,
          headers: outHeaders
        });
      } catch (err) {
        return new Response('SW proxy error: ' + (err?.message || String(err)), {
          status: 502,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      }
    })()
  );
});