// sw.js — Service Worker for apex origin
// Enforces integrity using Content-Digest + HTTP Message Signatures
// Also records benchmark metrics to app origin /metrics

let SIG_VERIFY_KEY = null;

const APP_ORIGIN = 'https://app.masteroppgave2026.no';
const METRICS_URL = APP_ORIGIN + '/metrics';

const BOOTSTRAP_PATHS = new Set([
  '/sw.js',
  '/Installer.js',
  '/installer.js',
]);

function log(...args) {
  const msg = args.join(' ');
  console.log('[SW]', msg);

  self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    for (const client of clients) {
      client.postMessage({
        type: 'SW_LOG',
        message: msg,
        ts: new Date().toISOString()
      });
    }
  });
}

function ms3(v) {
  return Number(Number(v).toFixed(3));
}

function shouldBypassSecurity(url) {
  return (
    url.searchParams.get('sw-bypass') === '1' ||
    url.pathname.startsWith('/unsigned/')
  );
}

async function postMetric(eventName, fields = {}) {
  const payload = {
    event: eventName,
    at: new Date().toISOString(),
    source: 'service-worker',
    ...fields
  };

  try {
    await fetch(METRICS_URL, {
      method: 'POST',
      mode: 'no-cors',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.warn('[SW] metric send failed', e);
  }
}

self.addEventListener('install', event => {
  log('install → skipWaiting');
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  log('activate → clients.claim');
  event.waitUntil(self.clients.claim());
});

self.addEventListener('message', async event => {
  if (event.data?.type !== 'SET_SIG_KEY') return;

  try {
    SIG_VERIFY_KEY = await crypto.subtle.importKey(
      'jwk',
      event.data.jwk,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const kid = event.data.jwk?.kid || '?';
    log('signature verification key installed (kid=' + kid + ')');

    if (event.source && typeof event.source.postMessage === 'function') {
      event.source.postMessage({ type: 'SIG_KEY_INSTALLED', kid });
    }
  } catch (e) {
    SIG_VERIFY_KEY = null;
    const msg = e?.message || String(e);
    log('ERROR installing signature key:', msg);

    if (event.source && typeof event.source.postMessage === 'function') {
      event.source.postMessage({ type: 'SIG_KEY_ERROR', message: msg });
    }
  }
});

function b64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bytesToB64(bytes) {
  let bin = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const chunkSize = 0x8000;
  for (let i = 0; i < arr.length; i += chunkSize) {
    bin += String.fromCharCode(...arr.subarray(i, i + chunkSize));
  }
  return btoa(bin);
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
    ct.includes('text/javascript') ||
    ct.includes('text/css') ||
    ct.includes('image/png') ||
    ct.includes('image/jpeg') ||
    ct.includes('image/webp') ||
    ct.includes('image/svg+xml')
  );
}

function getReqHeader(name, headers) {
  try {
    return headers.get(name);
  } catch {
    return null;
  }
}

async function verifyResponse(response, bodyBytes, method, targetUri) {
  if (!SIG_VERIFY_KEY) throw new Error('verification key not installed');

  const cd = response.headers.get('Content-Digest');
  const sig = response.headers.get('Signature');
  const sigInput = response.headers.get('Signature-Input');

  if (!cd || !sig || !sigInput) {
    throw new Error('missing security headers (need Content-Digest + Signature + Signature-Input)');
  }

  const digestStarted = performance.now();

  const expectedB64 = parseDigestHeader(cd);
  if (!expectedB64) throw new Error('bad Content-Digest format');

  const actualHash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const actualB64 = bytesToB64(actualHash);

  if (actualB64 !== expectedB64) {
    throw new Error('digest mismatch');
  }

  const digestMs = performance.now() - digestStarted;

  const sigStarted = performance.now();

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

  const sigMs = performance.now() - sigStarted;

  if (!ok) throw new Error('signature verification failed');

  return {
    digestMs,
    sigMs,
    totalMs: digestMs + sigMs
  };
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (!url.protocol.startsWith('http')) return;
  if (url.origin !== self.location.origin) return;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return;

  event.respondWith((async () => {
    const started = performance.now();

    // Explicit bypass mode for baseline benchmarks
    if (shouldBypassSecurity(url)) {
      const upstreamUrl = APP_ORIGIN + url.pathname + url.search;

      const init = {
        method: event.request.method,
        redirect: 'follow',
        credentials: 'omit',
        headers: new Headers()
      };

      const forwarded = [
        'Content-Type',
        'X-Run-Tag',
        'X-Req-Seq',
        'X-Bench-Kind'
      ];

      for (const h of forwarded) {
        const v = getReqHeader(h, event.request.headers);
        if (v) init.headers.set(h, v);
      }

      if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
        init.body = await event.request.clone().arrayBuffer();
        if (!init.headers.has('Content-Type')) {
          init.headers.set(
            'Content-Type',
            event.request.headers.get('Content-Type') || 'application/octet-stream'
          );
        }
      }

      const bypassStarted = performance.now();
      const res = await fetch(upstreamUrl, init);
      const bypassFetchMs = performance.now() - bypassStarted;

      log('BYPASS', url.pathname, '→', res.status, 'ms=', ms3(bypassFetchMs));

      const runTag =
        event.request.headers.get('X-Run-Tag') ||
        url.searchParams.get('runTag') ||
        '';
      const iterRaw =
        event.request.headers.get('X-Req-Seq') ||
        url.searchParams.get('iter') ||
        '';
      const iter = iterRaw === '' ? null : Number(iterRaw);

      if (runTag) {
        event.waitUntil(postMetric('sw_bypass_fetch', {
          runTag,
          iter,
          bench_kind: event.request.headers.get('X-Bench-Kind') || url.searchParams.get('bench') || '',
          path: url.pathname,
          method: event.request.method,
          http_status: res.status,
          content_type: res.headers.get('Content-Type') || '',
          sw_upstream_fetch_ms: ms3(bypassFetchMs),
          sw_total_ms: ms3(performance.now() - started),
          resp_header_bytes: Number(res.headers.get('X-Metric-Resp-Header-Bytes') || 0),
          resp_body_bytes: Number(res.headers.get('X-Metric-Resp-Body-Bytes') || 0),
          resp_total_bytes: Number(res.headers.get('X-Metric-Resp-Total-Bytes') || 0)
        }));
      }

      return res;
    }

    if (!SIG_VERIFY_KEY) {
      const res = await fetch(event.request);
      log('PASS (no key yet)', url.pathname, '→', res.status);
      return res;
    }

    const upstreamUrl = APP_ORIGIN + url.pathname + url.search;

    const init = {
      method: event.request.method,
      redirect: 'follow',
      credentials: 'omit',
      headers: new Headers()
    };

    const forwarded = [
      'Content-Type',
      'X-Run-Tag',
      'X-Req-Seq',
      'X-Bench-Kind'
    ];

    for (const h of forwarded) {
      const v = getReqHeader(h, event.request.headers);
      if (v) init.headers.set(h, v);
    }

    if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      init.body = await event.request.clone().arrayBuffer();
      if (!init.headers.has('Content-Type')) {
        init.headers.set(
          'Content-Type',
          event.request.headers.get('Content-Type') || 'application/octet-stream'
        );
      }
    }

    let res;
    const upstreamStarted = performance.now();
    try {
      res = await fetch(upstreamUrl, init);
    } catch (e) {
      log('NETWORK ERROR', url.pathname, e?.message || String(e));
      throw e;
    }
    const upstreamFetchMs = performance.now() - upstreamStarted;

    const ct = res.headers.get('Content-Type') || '';
    if (!isProtectedContentType(ct)) {
      log('PASS (unverified type)', url.pathname, 'ct=', ct, '→', res.status);
      return res;
    }

    const bodyBytes = await res.clone().arrayBuffer();

    try {
      const method = event.request.method;
      const targetUri = url.pathname + url.search;

      const vr = await verifyResponse(res, bodyBytes, method, targetUri);

      log(
        'OK',
        url.pathname,
        'ct=',
        ct,
        'status=',
        res.status,
        'upstreamMs=',
        ms3(upstreamFetchMs),
        'verifyMs=',
        ms3(vr.totalMs)
      );

      const runTag =
        event.request.headers.get('X-Run-Tag') ||
        url.searchParams.get('runTag') ||
        '';
      const iterRaw =
        event.request.headers.get('X-Req-Seq') ||
        url.searchParams.get('iter') ||
        '';
      const iter = iterRaw === '' ? null : Number(iterRaw);

      if (runTag) {
        event.waitUntil(postMetric('sw_fetch_verify', {
          runTag,
          iter,
          bench_kind: event.request.headers.get('X-Bench-Kind') || url.searchParams.get('bench') || '',
          path: url.pathname,
          method,
          http_status: res.status,
          content_type: ct,
          sw_upstream_fetch_ms: ms3(upstreamFetchMs),
          sw_digest_verify_ms: ms3(vr.digestMs),
          sw_signature_verify_ms: ms3(vr.sigMs),
          sw_verify_ms: ms3(vr.totalMs),
          sw_total_ms: ms3(performance.now() - started),
          resp_header_bytes: Number(res.headers.get('X-Metric-Resp-Header-Bytes') || 0),
          resp_body_bytes: Number(res.headers.get('X-Metric-Resp-Body-Bytes') || bodyBytes.byteLength),
          resp_total_bytes: Number(res.headers.get('X-Metric-Resp-Total-Bytes') || 0),
          sign_ms: Number(res.headers.get('X-Metric-Sign-Ms') || 0),
          req_header_bytes: Number(res.headers.get('X-Metric-Req-Header-Bytes') || 0),
          req_body_bytes: Number(res.headers.get('X-Metric-Req-Body-Bytes') || 0),
          decrypt_ms: Number(res.headers.get('X-Metric-Decrypt-Ms') || 0)
        }));
      }

      const outHeaders = new Headers(res.headers);
      outHeaders.delete('content-length');

      return new Response(bodyBytes, {
        status: res.status,
        statusText: res.statusText,
        headers: outHeaders
      });
    } catch (e) {
      log('BLOCK', url.pathname, 'reason=', e.message || String(e), 'ct=', ct, 'status=', res.status);

      return new Response(
        'Blocked by Service Worker (integrity violation): ' + (e.message || 'unknown'),
        { status: 498, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }
  })());
});