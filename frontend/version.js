/* Never reload automatically: browser-only payloads may be part of an investigation. */
(() => {
  const loaded = document.querySelector('meta[name="frontend-version"]')?.content || 'unknown';
  const badge = document.createElement('button');
  badge.id = 'frontend-version';
  badge.type = 'button';
  badge.textContent = `UI ${loaded}`;
  badge.title = `Loaded frontend: ${loaded}. Click to check for updates.`;
  document.querySelector('header h1').after(badge);
  let latest = loaded, checking = false;
  async function check() {
    if (checking || loaded === 'development') return;
    checking = true;
    try {
      const response = await fetch(new URL('frontend-version.json', location.href), {cache: 'no-store'});
      if (!response.ok) throw new Error('version unavailable');
      const data = await response.json();
      if (!/^[a-f0-9]{12}$/.test(data.version)) throw new Error('invalid version');
      latest = data.version;
      badge.classList.toggle('update-available', latest !== loaded);
      badge.textContent = latest === loaded ? `UI ${loaded}` : `UI ${loaded} · Update available`;
      badge.title = latest === loaded ? `Frontend ${loaded} is current.`
        : `Loaded: ${loaded}\nAvailable: ${latest}\nClick to reload. In-memory payloads will be lost.`;
    } catch (_) {
      badge.title = `Loaded frontend: ${loaded}. Update check unavailable.`;
    } finally { checking = false; }
  }
  badge.onclick = () => {
    if (latest !== loaded) {
      if (confirm('Load the new frontend? Follow tabs and saved drafts remain, but in-memory payloads will be lost.')) {
        const url = new URL(location.href);
        url.searchParams.set('ui', latest);
        location.assign(url.href);
      }
    } else check();
  };
  document.addEventListener('visibilitychange', () => { if (!document.hidden) check(); });
  setInterval(() => { if (!document.hidden) check(); }, 30000);
  check();
})();
