// installer.js (fixed bootstrap: controller gating + timeout + one reload)

const METRICS_URL = 'https://app.masteroppgave2026.no/metrics';

function log(...a){
  console.log('[INSTALLER]',...a);
}

async function postMetric(eventName, fields = {}) {

  const payload = {
    event:eventName,
    at:new Date().toISOString(),
    page:location.href,
    ...fields
  };

  log('METRIC SEND', eventName, payload);

  try {

    await fetch(METRICS_URL,{
      method:'POST',
      mode:'no-cors',
      body:JSON.stringify(payload)
    });

    log('METRIC SENT', eventName);

  } catch(e){

    log('METRIC ERROR',eventName,e);
  }
}

async function fetchSigPubJwkFromApp() {
  const r = await fetch('https://app.masteroppgave2026.no/sig-pub', {
    cache: 'no-store',
    mode: 'cors',
    credentials: 'omit',
  });
  if (!r.ok) throw new Error('sig-pub HTTP ' + r.status);
  return await r.json();
}

function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

async function waitForController(timeoutMs = 2500) {
  const start = performance.now();
  while (!navigator.serviceWorker.controller) {
    if (performance.now() - start > timeoutMs) return false;
    await sleep(50);
  }
  return true;
}

async function install() {

  // Already installed? Skip installer completely
  if (navigator.serviceWorker.controller) {
    location.replace('/');
    return;
  }

  const t0 = performance.now();

  if (!('serviceWorker' in navigator)) {
    await postMetric('sw_install_unsupported', {});
    return;
  }

  // 1) Register
    const swInstallStart = performance.now();

    const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });

    await navigator.serviceWorker.ready;

    const swInstallMs = performance.now() - swInstallStart;

    await postMetric('sw_install_complete', {
      sw_install_total_ms: Math.round(swInstallMs)
    });

  // 2) Ensure the page is controlled (or reload once)
  let controlled = await waitForController(2000);

  if (!controlled && !sessionStorage.getItem('__sw_reloaded_once')) {
    sessionStorage.setItem('__sw_reloaded_once', '1');
    await postMetric('sw_force_reload', { note: 'No controller yet; reloading once to get control.' });
    location.reload();
    return; // stop here; next load should be controlled
  }

  controlled = await waitForController(2000);
  await postMetric('sw_controlled', { controlled });

  // 3) Fetch JWK
  const jwk = await fetchSigPubJwkFromApp();

  // 4) Send key to SW + wait ACK
  const controller = navigator.serviceWorker.controller;
  const target = controller || reg.active;
  if (!target) throw new Error('No active SW to message');

  const ack = new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('SIG_KEY_INSTALLED timeout')), 5000);
    navigator.serviceWorker.addEventListener('message', function onMsg(e) {
      if (e.data?.type === 'SIG_KEY_INSTALLED') {
        clearTimeout(to);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        resolve(e.data);
      }
      if (e.data?.type === 'SIG_KEY_ERROR') {
        clearTimeout(to);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        reject(new Error(e.data.message || 'SIG_KEY_ERROR'));
      }
    });
  });

  const tKey0 = performance.now();
  target.postMessage({ type: 'SET_SIG_KEY', jwk });
  await ack;
  await postMetric('sw_key_install', { sw_key_install_ms: Math.round(performance.now() - tKey0), kid: jwk?.kid });

  // 5) Fetch JWE public key and register the SW's client signing key with the server
  const kxResp = await fetch('https://app.masteroppgave2026.no/key-exchange', {
    cache: 'no-store',
    mode: 'cors',
    credentials: 'omit'
  });
  if (!kxResp.ok) throw new Error('key-exchange HTTP ' + kxResp.status);
  const jweJwk = await kxResp.json();

  const regAck = new Promise((resolve, reject) => {
    const to = setTimeout(() => reject(new Error('REGISTER_CLIENT_KEY timeout')), 10000);
    navigator.serviceWorker.addEventListener('message', function onMsg(e) {
      if (e.data?.type === 'REGISTER_OK') {
        clearTimeout(to);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        resolve(e.data);
      }
      if (e.data?.type === 'REGISTER_FAIL') {
        clearTimeout(to);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        reject(new Error(e.data.message || 'REGISTER_FAIL'));
      }
    });
  });

  const tReg0 = performance.now();
  target.postMessage({ type: 'REGISTER_CLIENT_KEY', jweJwk });
  await regAck;
  await postMetric('sw_client_key_registered', {
    sw_reg_ms: Math.round(performance.now() - tReg0),
    client_key_id: 'client-req-1'
  });

  await postMetric('sw_bootstrap_total', { sw_bootstrap_total_ms: Math.round(performance.now() - t0) });
  location.replace('/');
}

install().catch(async (e) => {
  await postMetric('sw_bootstrap_error', { err: e?.message || String(e) });
  console.error(e);
});