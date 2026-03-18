<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>JWE Field Encrypt (Lab)</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="stylesheet" href="/styles.css">
    <style>
        .status { padding:.5rem .75rem; border-radius:.5rem; display:inline-block; margin:.25rem 0 }
        .ok { background:#e8f7ee; color:#146c2e; border:1px solid #bfe7cc }
        .fail { background:#ffecec; color:#8a1f11; border:1px solid #f5c0bc }
        fieldset { margin:1rem 0 }
        label { display:block; margin:.35rem 0 }
        input, textarea { width:100%; padding:.5rem; box-sizing:border-box }
        pre { white-space:pre-wrap; word-break:break-word }

        .logbox {
          background:#0b1020;
          color:#d0d7ff;
          padding:1rem;
          border-radius:.5rem;
          max-height:260px;
          overflow:auto;
          font-size:.85rem;
        }
        .row { display:flex; gap:.75rem; align-items:center; flex-wrap:wrap }
        .small { font-size:.9rem; color:#555 }
        code { background:#f6f8fa; padding:0 .25rem; border-radius:.25rem; }
    </style>
</head>
<body>

<h1>Pick fields/headers to encrypt (JWE)</h1>

<div id="kxStatus" class="status">Key exchange not run yet…</div>

<p class="small">
    Tamper demo:
    <a href="/index.html">normal</a> ·
    <a href="/index.html?tamper=signature">signature</a> ·
    <a href="/index.html?tamper=digest">digest</a> ·
    <a href="/index.html?tamper=body">body</a> ·
    <a href="/index.html?tamper=all">all</a>
</p>

<fieldset>
    <legend>Body</legend>
    <label>Name <input id="name" placeholder="alice"></label>
    <label>Age <input id="age" type="number" value="30"></label>
    <label>Message <textarea id="msg" rows="3" placeholder="hello"></textarea></label>
    <label><input type="checkbox" id="encName" checked> Encrypt name</label>
    <label><input type="checkbox" id="encMsg" checked> Encrypt message</label>
</fieldset>

<fieldset>
    <legend>Headers</legend>
    <label>X-Custom <input id="xhdr" placeholder="secret-header"></label>
    <label><input type="checkbox" id="encHdr"> Encrypt X-Custom header</label>
</fieldset>

<div class="row">
    <button id="sendBtn" disabled>Send</button>
    <label class="small"><input type="checkbox" id="verbose"> verbose logs (show full JWE strings)</label>
</div>

<h3>Security + app log</h3>
<pre id="security-log" class="logbox">Waiting for Service Worker…</pre>

<h2>Response from Host</h2>
<pre id="out"></pre>

<script type="module">
    import { CompactEncrypt, importJWK } from 'https://cdn.jsdelivr.net/npm/jose@5.3.0/+esm';

    const secLog = document.getElementById('security-log');
    const verbose = document.getElementById('verbose');
    const sendBtn = document.getElementById('sendBtn');

    function appendLog(line) {
      secLog.textContent += line + '\n';
      secLog.scrollTop = secLog.scrollHeight;
    }

    function nowTs() {
      return new Date().toISOString();
    }

    function pageLog(...args) {
      appendLog(`[${nowTs()}] [PAGE] ${args.join(' ')}`);
    }

    navigator.serviceWorker?.addEventListener('message', e => {
      if (e.data?.type === 'SW_LOG') {
        appendLog(`[${e.data.ts}] [SW] ${e.data.message}`);
      }
    });

    window.addEventListener('error', (e) => {
      pageLog('ERROR', e.message);
    });

    const kxStatus = document.getElementById('kxStatus');
    function badge(ok, text) {
      kxStatus.textContent = text;
      kxStatus.className = 'status ' + (ok ? 'ok' : 'fail');
    }

    let jweKey = null;
    let kid = null;
    let reqSignOK = false;

    async function swActive() {
      const reg = await navigator.serviceWorker.ready;
      return navigator.serviceWorker.controller || reg.active || reg.waiting || reg.installing;
    }

    function waitForSWMessage(types, timeoutMs = 6000) {
      const wanted = new Set(Array.isArray(types) ? types : [types]);

      return new Promise((resolve, reject) => {
        const t = setTimeout(() => {
          navigator.serviceWorker.removeEventListener('message', onMsg);
          reject(new Error('Timed out waiting for SW message: ' + Array.from(wanted).join(',')));
        }, timeoutMs);

        function onMsg(ev) {
          const type = ev?.data?.type;
          if (!wanted.has(type)) return;
          clearTimeout(t);
          navigator.serviceWorker.removeEventListener('message', onMsg);
          resolve(ev.data);
        }

        navigator.serviceWorker.addEventListener('message', onMsg);
      });
    }

    async function getReqSignStatus() {
      const active = await swActive();
      if (!active) throw new Error('No active Service Worker instance');

      const p = waitForSWMessage('REQ_SIGN_STATUS', 4000);
      active.postMessage({ type: 'GET_REQ_SIGN_STATUS' });
      return await p;
    }

    async function initKey() {
      pageLog('Fetching JWE public key from /key-exchange (expect SW to verify)');
      const tamper = new URLSearchParams(location.search).get('tamper');
      const q = tamper ? `?tamper=${encodeURIComponent(tamper)}` : '';
      pageLog('tamper=', tamper || 'none', 'fetch=', '/key-exchange' + q);

      const r = await fetch('/key-exchange' + q, { cache:'no-store' });

      pageLog('key-exchange HTTP', r.status, r.statusText);
      if (!r.ok) {
        badge(false, 'Key exchange failed: HTTP ' + r.status);
        throw new Error('key-exchange failed: ' + r.status);
      }

      const jwk = await r.json();
      kid = jwk.kid || '(no-kid)';
      pageLog('Received JWK kid=', kid);

      jweKey = await importJWK(
        { kty:'RSA', n:jwk.n, e:jwk.e, alg:'RSA-OAEP-256' },
        'RSA-OAEP-256'
      );

      const rs = await getReqSignStatus();
      reqSignOK = !!rs.ready;
      pageLog('Request-sign status from SW: ready=', String(reqSignOK), 'kid=', rs.kid || '(none)');

      if (!reqSignOK) {
        badge(false, 'Request-signing not ready in Service Worker');
        sendBtn.disabled = true;
        return;
      }

      badge(true, 'Key exchange OK (JWE key imported)');
      sendBtn.disabled = false;
      pageLog('JWE public key imported');
    }

    async function enc(plaintext) {
      const e = new CompactEncrypt(new TextEncoder().encode(plaintext));
      e.setProtectedHeader({ alg:'RSA-OAEP-256', enc:'A256GCM', kid });
      return await e.encrypt(jweKey);
    }

    function maybeShort(s) {
      if (verbose.checked) return s;
      if (!s) return s;
      if (s.length <= 80) return s;
      return s.slice(0, 40) + ' … ' + s.slice(-28) + ` (len=${s.length})`;
    }

    initKey().catch(err => {
      badge(false, 'Key exchange error: ' + err.message);
      pageLog('Key exchange error:', err.message);
      console.error(err);
    });

    document.getElementById('sendBtn').addEventListener('click', async () => {
      if (!jweKey) {
        pageLog('Cannot send: JWE key not ready yet');
        alert('Key not ready yet. Check log.');
        return;
      }
      if (!reqSignOK) {
        pageLog('Cannot send: request-signing not ready yet');
        alert('Request-signing not ready yet. Check log.');
        return;
      }

      const name = document.getElementById('name').value || '';
      const age  = Number(document.getElementById('age').value || 0);
      const msg  = document.getElementById('msg').value || '';

      const encName = document.getElementById('encName').checked;
      const encMsg  = document.getElementById('encMsg').checked;

      const xhdrVal = document.getElementById('xhdr').value || '';
      const encHdr  = document.getElementById('encHdr').checked;

      pageLog('Preparing request → /api/echo');
      pageLog('Selections:',
        `encName=${encName}`,
        `encMsg=${encMsg}`,
        `xhdr=${xhdrVal ? 'set' : 'empty'}`,
        `encHdr=${encHdr}`
      );

      const body = {
        name: encName ? ("JWE: " + await enc(name)) : name,
        age,
        message: encMsg ? ("JWE: " + await enc(msg)) : msg
      };

      const headers = { 'Content-Type': 'application/json' };
      if (xhdrVal) {
        if (encHdr) headers['X-Enc-X-Custom'] = await enc(xhdrVal);
        else headers['X-Custom'] = xhdrVal;
      }

      pageLog('Request body preview:',
        `name=${encName ? 'JWE ' + maybeShort(body.name) : JSON.stringify(body.name)}`,
        `age=${body.age}`,
        `message=${encMsg ? 'JWE ' + maybeShort(body.message) : JSON.stringify(body.message)}`
      );
      if (headers['X-Custom']) pageLog('Header X-Custom:', JSON.stringify(headers['X-Custom']));
      if (headers['X-Enc-X-Custom']) pageLog('Header X-Enc-X-Custom:', 'JWE ' + maybeShort(headers['X-Enc-X-Custom']));

      pageLog('Sending…');
      const t0 = performance.now();

      let r;
      try {
        r = await fetch('/api/echo', {
          method: 'POST',
          headers,
          body: JSON.stringify(body)
        });
      } catch (e) {
        pageLog('NETWORK ERROR sending /api/echo:', e.message);
        throw e;
      }

      pageLog('Response HTTP', r.status, r.statusText, `(${Math.round(performance.now()-t0)}ms)`);
      const text = await r.text();
      document.getElementById('out').textContent = text;
    });
</script>

</body>
</html>