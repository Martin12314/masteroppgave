// /installer.js (MessageChannel RPC, no global listener leaks)
const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/', type: 'module' });
const METRICS_URL = 'https://app.masteroppgave2026.no/metrics';

function log(...a) {
  console.log('[INSTALLER]', ...a);
}

async function postMetric(eventName, fields = {}) {
  const payload = { event: eventName, at: new Date().toISOString(), page: location.href, ...fields };
  log('METRIC SEND', eventName, payload);
  try {
    await fetch(METRICS_URL, { method: 'POST', mode: 'no-cors', body: JSON.stringify(payload) });
    log('METRIC SENT', eventName);
  } catch (e) {
    log('METRIC ERROR', eventName, e);
  }
}

async function fetchSigPubJwkFromApp() {
  const r = await fetch('https://app.masteroppgave2026.no/sig-pub', {
    cache: 'no-store',
    mode: 'cors',
    credentials: 'omit'
  });
  if (!r.ok) throw new Error('sig-pub HTTP ' + r.status);
  return await r.json();
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForController(timeoutMs = 2500) {
  const start = performance.now();
  while (!navigator.serviceWorker.controller) {
    if (performance.now() - start > timeoutMs) return false;
    await sleep(50);
  }
  return true;
}

function swRpc(type, payload, timeoutMs) {
  const target = navigator.serviceWorker.controller || reg.active;
  if (!target) return Promise.reject(new Error('No active SW to message'));

  return new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    const to = setTimeout(() => reject(new Error(type + ' timeout')), timeoutMs);

    ch.port1.onmessage = (e) => {
      clearTimeout(to);
      const data = e.data || {};
      if (data.ok) resolve(data);
      else reject(new Error(data.message || 'SW RPC failed'));
    };

    target.postMessage({ type, ...payload }, [ch.port2]);
  });
}

async function install() {
  const t0 = performance.now();

  if (!('serviceWorker' in navigator)) {
    await postMetric('sw_install_unsupported', {});
    return;
  }

  const swInstallStart = performance.now();
  await navigator.serviceWorker.ready;
  const swInstallMs = performance.now() - swInstallStart;

  await postMetric('sw_install_complete', { sw_install_total_ms: Math.round(swInstallMs) });

  let controlled = await waitForController(2000);

  if (!controlled && !sessionStorage.getItem('__sw_reloaded_once')) {
    sessionStorage.setItem('__sw_reloaded_once', '1');
    await postMetric('sw_force_reload', { note: 'No controller yet; reloading once to get control.' });
    location.reload();
    return;
  }

  controlled = await waitForController(2000);
  await postMetric('sw_controlled', { controlled });

  const jwk = await fetchSigPubJwkFromApp();

  const tKey0 = performance.now();
  const keyResp = await swRpc('SET_SIG_KEY', { jwk }, 8000);
  await postMetric('sw_key_install', {
    sw_key_install_ms: Math.round(performance.now() - tKey0),
    kid: keyResp.kid || jwk?.kid
  });

  const kxResp = await fetch('https://app.masteroppgave2026.no/key-exchange', {
    cache: 'no-store',
    mode: 'cors',
    credentials: 'omit'
  });
  if (!kxResp.ok) throw new Error('key-exchange HTTP ' + kxResp.status);
  const jweJwk = await kxResp.json();

  const tReg0 = performance.now();
  const regResp = await swRpc('REGISTER_CLIENT_KEY', { jweJwk }, 25000);

  await postMetric('sw_client_key_registered', {
    sw_reg_ms: Math.round(performance.now() - tReg0),
    client_key_id: regResp.client_key_id || null
  });

  await postMetric('sw_bootstrap_total', {
    sw_bootstrap_total_ms: Math.round(performance.now() - t0)
  });

  location.replace('/login.html');
}

install().catch(async (e) => {
  await postMetric('sw_bootstrap_error', { err: e?.message || String(e) });
  console.error(e);
});