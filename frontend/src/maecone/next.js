// Where to go after signing in, when something sent the browser here with
// `?next=`: the one place that decides it.
//
// This is the open-redirect surface. A sign-in page that follows `next`
// anywhere is a phishing page with Core's name on it, so the rule is narrow:
//
//   * a path on this origin — only /oauth/authorize, as before;
//   * an absolute URL — only if its origin (scheme, host and port) is exactly
//     the origin of a live application's base_url. That is how an app's gate
//     sends someone here (OPEN-DECISIONS #19) and gets them back.
//
// Anything else — another host, a look-alike host, a different port, a
// protocol-relative `//host`, a backslash, credentials in the URL, any scheme
// but http(s) — is refused, and the caller goes to the launcher instead.
//
// Pure: no window, no React. `next.test.js` runs it under `node --test`, and
// the backend suite runs that file (test_next_allowlist.py).

/** scheme://host[:port] of a base_url, or null. */
function originOf(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.origin : null
  } catch {
    return null
  }
}

/**
 * The URL to send the browser to, or null to go to the launcher.
 *
 * @param raw   the `next` parameter, as given
 * @param apps  the catalogue from /api/auth/me: [{status, base_url}, ...]
 * @param here  this page's origin, e.g. "http://auth.maec.local:8000"
 */
export function safeNext(raw, apps, here) {
  if (typeof raw !== 'string' || raw === '') return null
  // Backslashes and control characters are how a URL parser is talked into
  // reading a host the eye does not see. Nothing legitimate needs them.
  // eslint-disable-next-line no-control-regex
  if (/[\\\u0000-\u001f\u007f]/.test(raw)) return null

  if (raw.startsWith('/')) {
    if (raw.startsWith('//')) return null                 // protocol-relative: a host
    let url
    try {
      url = new URL(raw, here)
    } catch {
      return null
    }
    if (url.origin !== here || url.pathname !== '/oauth/authorize') return null
    return url.pathname + url.search
  }

  if (!/^https?:\/\//i.test(raw)) return null             // javascript:, data:, ...
  let url
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.username || url.password) return null           // http://app@evil.example
  const allowed = new Set(
    (apps || [])
      .filter((app) => app && app.status === 'live' && app.base_url)
      .map((app) => originOf(app.base_url))
      .filter(Boolean),
  )
  return allowed.has(url.origin) ? url.href : null
}
