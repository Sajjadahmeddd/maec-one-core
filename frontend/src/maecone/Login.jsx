// The MAEC One sign-in card.
//
// The page around it — the pitch, the module tiles, the footer — is
// MaecOne.jsx, shared with the launcher. Here the tiles are presentational:
// nothing should look clickable before we know who you are.
//
// Credentials are per person, checked against the identity database. The
// tiles are drawn from the same catalogue the launcher uses, so both screens
// always describe the same products — but before sign-in the server sends no
// entitlements, so none of them can be opened.

import { useEffect, useState } from 'react'
import { auth } from './api'
import MaecOne, { BADGES, ICONS, Svg } from './MaecOne.jsx'

const REMEMBER_KEY = 'maec.signin.email'

/** The address is remembered per browser; the session itself is not. */
function readRemembered() {
  try {
    return localStorage.getItem(REMEMBER_KEY) || ''
  } catch {
    return ''            // private windows and blocked site data
  }
}

function writeRemembered(value) {
  try {
    if (value) localStorage.setItem(REMEMBER_KEY, value)
    else localStorage.removeItem(REMEMBER_KEY)
  } catch {
    /* nothing to do — remembering is a convenience, not a requirement */
  }
}

function Eye({ off }) {
  return (
    <Svg width="18" height="18">
      <path d="M2 12s3.5-6.5 10-6.5S22 12 22 12s-3.5 6.5-10 6.5S2 12 2 12Z" />
      <circle cx="12" cy="12" r="2.8" />
      {off && <line x1="3.5" y1="20.5" x2="20.5" y2="3.5" />}
    </Svg>
  )
}

export default function Login({ apps = [], onSignedIn }) {
  const remembered = readRemembered()
  const [email, setEmail] = useState(remembered)
  const [password, setPassword] = useState('')
  const [remember, setRemember] = useState(!!remembered)
  const [reveal, setReveal] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [hint, setHint] = useState(false)

  // the address field starts filled when it was remembered, so send focus
  // to the password instead of making the user tab past it
  useEffect(() => {
    const target = remembered ? 'maec-password' : 'maec-email'
    document.getElementById(target)?.focus()
  }, [remembered])

  // A password manager fills the fields straight into the DOM without React's
  // onChange ever running, so state stayed empty and Sign in stayed disabled
  // over two visibly filled boxes — no way in for anyone with saved
  // credentials. Read back what the browser actually put there. The timings
  // cover autofill that lands before, during and just after first paint.
  useEffect(() => {
    const adopt = () => {
      const filled = (id) => document.getElementById(id)?.value || ''
      setEmail((current) => current || filled('maec-email'))
      setPassword((current) => current || filled('maec-password'))
    }
    const timers = [0, 120, 400, 900].map((ms) => setTimeout(adopt, ms))
    return () => timers.forEach(clearTimeout)
  }, [])

  const submit = async (event) => {
    event.preventDefault()
    if (!email.trim() || !password || busy) return
    setBusy(true)
    setError('')
    try {
      const who = await auth.login(email, password)
      writeRemembered(remember ? email.trim() : '')
      onSignedIn(who)
    } catch (err) {
      setError(err.message)
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  const card = (
    <form className="signin-card" onSubmit={submit}>
      <div className="signin-mark"><img src="/maec-logo.png" alt="" /></div>

      <h2 className="signin-welcome">Welcome Back</h2>
      <p className="signin-sub">Sign in to your account</p>

      <label className="signin-label" htmlFor="maec-email">Email address</label>
      <div className="signin-field">
        <span className="signin-adornment"><ICONS.mail width="18" height="18" /></span>
        <input
          id="maec-email"
          type="email"
          value={email}
          autoComplete="username"
          placeholder="you@mirageaec.com"
          onChange={(e) => { setEmail(e.target.value); setError('') }}
        />
      </div>

      <label className="signin-label" htmlFor="maec-password">Password</label>
      <div className="signin-field">
        <span className="signin-adornment"><ICONS.lock width="18" height="18" /></span>
        <input
          id="maec-password"
          type={reveal ? 'text' : 'password'}
          value={password}
          autoComplete="current-password"
          placeholder="••••••••••"
          onChange={(e) => { setPassword(e.target.value); setError('') }}
        />
        <button
          type="button"
          className="signin-reveal"
          aria-label={reveal ? 'Hide password' : 'Show password'}
          title={reveal ? 'Hide password' : 'Show password'}
          onClick={() => setReveal((r) => !r)}
        >
          <Eye off={reveal} />
        </button>
      </div>

      <div className="signin-row">
        <label className="signin-remember">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
          />
          <span>Remember me</span>
        </label>
        <button type="button" className="signin-forgot" onClick={() => setHint((h) => !h)}>
          Forgot your password?
        </button>
      </div>

      {error && <p className="signin-error">{error}</p>}
      {hint && (
        <p className="signin-hint">
          Your account is your own. Ask a MAEC One administrator to reset the
          password — for security, we cannot tell you whether an address is
          registered.
        </p>
      )}

      <button
        type="submit"
        className="signin-submit"
        disabled={!email.trim() || !password || busy}
      >
        {busy ? 'Signing in…' : 'Sign in'}
      </button>

      <ul className="signin-badges">
        {BADGES.map(([name, sub]) => (
          <li key={name}>
            <ICONS.badge width="18" height="18" />
            <span><strong>{name}</strong>{sub}</span>
          </li>
        ))}
      </ul>
    </form>
  )

  // no onPick: the tiles say what exists but stay inert — nothing should
  // look clickable before we know who you are
  return <MaecOne panel={card} apps={apps} />
}
