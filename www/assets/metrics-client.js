export function createMetricsClient({
  endpoint,
  storageKey = 'metrics-queue-v1',
  debugEnabled = () => false,
  onLog = () => {}
} = {}) {
  if (!endpoint) throw new Error('metrics endpoint is required');

  let memoryQueue = [];

  function log(...args) {
    if (!debugEnabled()) return;
    const line = `[METRICS] ${args.join(' ')}`;
    console.log(line);
    try { onLog(line); } catch {}
  }

  function metricId() {
    return crypto.randomUUID
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function readQueue() {
    try {
      const raw = localStorage.getItem(storageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return memoryQueue.slice();
    }
  }

  function writeQueue(items) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(items));
      memoryQueue = items.slice();
    } catch {
      memoryQueue = items.slice();
    }
  }

  function enqueue(item) {
    const q = readQueue();
    q.push(item);
    writeQueue(q);
    log('queued', item.event, 'metric_id=' + item.metric_id, 'size=' + q.length);
  }

  function dequeueMany(maxItems = 50) {
    const q = readQueue();
    if (!q.length) return [];
    const items = q.slice(0, maxItems);
    const rest = q.slice(maxItems);
    writeQueue(rest);
    return items;
  }

  function requeueFront(items) {
    if (!items?.length) return;
    const q = readQueue();
    writeQueue([...items, ...q]);
    log('requeued', String(items.length), 'items');
  }

  function track(eventName, fields = {}) {
    const item = {
      metric_id: metricId(),
      event: eventName,
      at: nowIso(),
      page_url: location.href,
      origin: location.origin,
      user_agent: navigator.userAgent,
      ...fields
    };
    enqueue(item);
    return item.metric_id;
  }

  async function flush({ keepalive = false, maxItems = 50 } = {}) {
    const items = dequeueMany(maxItems);
    if (!items.length) {
      log('flush skipped; queue empty');
      return { ok: true, sent: 0 };
    }

    const runTag = items.find(x => x.runTag)?.runTag || null;

    const payload = {
      metric_mode: 'batch',
      batch_id: metricId(),
      batch_kind: 'browser_metrics',
      batch_started_at: items[0]?.at || nowIso(),
      batch_flushed_at: nowIso(),
      page_url: location.href,
      origin: location.origin,
      user_agent: navigator.userAgent,
      runTag,
      metrics: items
    };

    log('flush sending', String(items.length), 'items to', endpoint);

    try {
      const body = JSON.stringify(payload);

      const res = await fetch(endpoint, {
        method: 'POST',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        keepalive,
        headers: {
          'Content-Type': 'application/json'
        },
        body
      });

      const txt = await res.text();

      if (!res.ok) {
        log('flush failed http=' + res.status, txt);
        requeueFront(items);
        return { ok: false, sent: 0, status: res.status, body: txt };
      }

      log('flush ok http=' + res.status, txt);
      return { ok: true, sent: items.length, status: res.status, body: txt };
    } catch (err) {
      log('flush exception', String(err));
      requeueFront(items);
      return { ok: false, sent: 0, error: String(err) };
    }
  }

  async function flushAll({ keepalive = false, batchSize = 50 } = {}) {
    let total = 0;
    for (;;) {
      const q = readQueue();
      if (!q.length) break;

      const res = await flush({ keepalive, maxItems: batchSize });
      if (!res.ok) return { ok: false, sent: total };
      total += res.sent;

      if (res.sent === 0) break;
    }
    return { ok: true, sent: total };
  }

  window.addEventListener('pagehide', () => {
    flush({ keepalive: true, maxItems: 50 }).catch(() => {});
  });

  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      flush({ keepalive: true, maxItems: 50 }).catch(() => {});
    }
  });

  return {
    track,
    flush,
    flushAll,
    readQueue
  };
}
