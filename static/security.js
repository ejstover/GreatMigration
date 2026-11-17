/* Same-origin CSRF protection shared by all application fetch workflows. */
(() => {
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, options = {}) => {
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    const method = String(options.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (url.origin === location.origin && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      const headers = new Headers(options.headers || (input instanceof Request ? input.headers : undefined));
      headers.set('X-CSRF-Token', document.querySelector('meta[name="csrf-token"]')?.content || '');
      options = { ...options, headers };
    }
    return originalFetch(input, options);
  };
  window.secureLogout = async () => {
    const response = await fetch('/logout', { method: 'POST' });
    if (response.ok) location.assign('/login');
  };
})();
