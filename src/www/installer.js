// Trusted installer: bootstraps trust using DNS TXT pinning

const out = document.getElementById('log');

function log(m) {
  console.log('[INSTALL]', m);
  out.textContent += '\n' + m;
  out.scrollTop = out.scrollHeight;
}

const APP_ORIGIN = 'https://app.masteroppgave2026.no';

// -------------------- DNS pin lookup --------------------

async function fetchDNSPin() {
  console.log('[INSTALL] VERSION = 2026-01-29');
  log('[INSTALL] VERSION = 2026-01-29');

  log('Fetching SIG-PUB pin from DNS TXT (_sigpub.app.masteroppgave2026.no)…');

  const r = await fetch(
    'https://cloudflare-dns.com/dns-query?name=_sigpub.app.masteroppgave2026.no&type=TXT',
    {
      headers: { accept: 'application/dns-json' },
      cache: 'no-store'
    }
  );

  const j = await r.json();
  const raw = j.Answer?.[0]?.data?.replace(/"/g, '');

  if (!raw) throw new Error('DNS pin missing');

  const parts = Object.fromEntries(
    raw.split(';').map(p => p.split('=', 2))
  );

  if (parts.v !== '1') throw new Error('Unsupported DNS pin version');
  if (!parts.kid || !parts.sha256) throw new Error('DNS pin missing kid or sha256');

  log(`DNS pin loaded (kid=${parts.kid})`);
  return { kid: parts.kid, sha256: parts.sha256 };
}

// -------------------- Hash helper --------------------

async function hashJWK(jwk) {
  const canonical = JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e });
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function normalizeB64(s) {
  return s.replace(/=+$/, '');
}

// Wait until SW confirms it imported the key
function waitForSWKeyAck(expectedKid, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      navigator.serviceWorker.removeEventListener('message', onMsg);
      reject(new Error('Timed out waiting for SW key install ack'));
    }, timeoutMs);

    function onMsg(ev) {
      if (ev?.data?.type === 'SIG_KEY_INSTALLED' && ev.data.kid === expectedKid) {
        clearTimeout(t);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        resolve(true);
      }
      if (ev?.data?.type === 'SIG_KEY_ERROR') {
        clearTimeout(t);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        reject(new Error('SW failed to install key: ' + (ev.data.message || 'unknown')));
      }
    }

    navigator.serviceWorker.addEventListener('message', onMsg);
  });
}

// -------------------- Main installer flow --------------------

async function main() {
  log('Installer started');

  // 1) DNS pin
  const pinned = await fetchDNSPin();

  // 2) Fetch signature public key from app origin (requires strict CORS on app.*)
  log('Fetching /sig-pub from app origin…');
  const r = await fetch(APP_ORIGIN + '/sig-pub', {
    cache: 'no-store',
    mode: 'cors'
  });

  if (!r.ok) throw new Error('Failed to fetch /sig-pub (HTTP ' + r.status + ')');

  const jwk = await r.json();
  log(`Got SIG-PUB (kid=${jwk.kid})`);

  const now = Math.floor(Date.now() / 1000);
  if (jwk.created > now + 60) throw new Error('SIG-PUB created in the future');
  if (jwk.expires < now) throw new Error('SIG-PUB expired');
  if (jwk.kid !== pinned.kid) throw new Error(`KID mismatch: DNS=${pinned.kid}, SIG-PUB=${jwk.kid}`);

  // 3) Verify key material
  const localHash = await hashJWK(jwk);
  if (normalizeB64(localHash) !== normalizeB64(pinned.sha256)) {
    throw new Error('MITM detected: SIG-PUB hash mismatch');
  }
  log('SIG-PUB verified against DNS pin');

  // 4) Register Service Worker
  if (!('serviceWorker' in navigator)) throw new Error('ServiceWorker not supported');

  log('Registering Service Worker /sw.js …');
  const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
  await navigator.serviceWorker.ready;
  log('Service Worker ready');

  const active = reg.active || reg.waiting || reg.installing;
  if (!active) throw new Error('No active Service Worker instance');

  // 5) Deliver verified key to SW + wait for ack
  log('Sending verified key to Service Worker');
  const ackPromise = waitForSWKeyAck(jwk.kid, 4000);
  active.postMessage({ type: 'SET_SIG_KEY', jwk });
  await ackPromise;
  log('Service Worker confirmed key installed');

  // 6) Enter protected application (same apex URL; SW will fetch verified bytes from app.*)
  log('Redirecting to /login.html …');
  location.replace('/login.html');
}

main().catch(err => {
  log('FATAL: ' + (err?.message || err));
  console.error(err);
});
