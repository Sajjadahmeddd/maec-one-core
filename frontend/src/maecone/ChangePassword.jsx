// The way out of an administrator-set password.
//
// Shown whenever `must_change_password` is set, over everything else — there
// is nowhere else to go, because the server refuses every other call with
// "Password change required." This screen is not the enforcement; it is the
// only door the enforcement leaves open.

import { useState } from 'react'
import MaecOne, { BADGES, ICONS } from './MaecOne.jsx'
import { auth } from './api'

export default function ChangePassword({ session, onChanged, onSignOut }) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const submit = async (event) => {
    event.preventDefault()
    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }
    setBusy(true)
    setError('')
    try {
      onChanged(await auth.changePassword(current, next))
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  const card = (
    <form className="signin-card" onSubmit={submit}>
      <div className="signin-mark"><img src="/maec-logo.png" alt="" /></div>

      <h2 className="signin-welcome">Choose your password</h2>
      <p className="signin-sub">{session?.email}</p>

      <p className="launch-lede">
        Your password was set by an administrator, so they know it. Choose one
        of your own to continue — nothing else will open until you do.
      </p>

      <label className="signin-label" htmlFor="maec-current">Current password</label>
      <div className="signin-field">
        <span className="signin-adornment"><ICONS.lock width="18" height="18" /></span>
        <input id="maec-current" type="password" value={current}
               autoComplete="current-password" required
               onChange={(e) => { setCurrent(e.target.value); setError('') }} />
      </div>

      <label className="signin-label" htmlFor="maec-new">New password</label>
      <div className="signin-field">
        <span className="signin-adornment"><ICONS.lock width="18" height="18" /></span>
        <input id="maec-new" type="password" value={next}
               autoComplete="new-password" required
               onChange={(e) => { setNext(e.target.value); setError('') }} />
      </div>

      <label className="signin-label" htmlFor="maec-confirm">Confirm new password</label>
      <div className="signin-field">
        <span className="signin-adornment"><ICONS.lock width="18" height="18" /></span>
        <input id="maec-confirm" type="password" value={confirm}
               autoComplete="new-password" required
               onChange={(e) => { setConfirm(e.target.value); setError('') }} />
      </div>

      <p className="signin-hint">
        At least 8 characters, with an uppercase letter, a lowercase letter,
        a digit and a symbol.
      </p>

      {error && <p className="signin-error">{error}</p>}

      <button type="submit" className="signin-submit"
              disabled={!current || !next || !confirm || busy}>
        {busy ? 'Saving…' : 'Set password and continue'}
      </button>

      <button type="button" className="launch-signout" onClick={onSignOut}>
        Sign out instead
      </button>

      <ul className="signin-badges">
        {BADGES.map(([label, sub]) => (
          <li key={label}>
            <ICONS.badge width="18" height="18" />
            <span><strong>{label}</strong>{sub}</span>
          </li>
        ))}
      </ul>
    </form>
  )

  return <MaecOne panel={card} apps={session?.apps || []} />
}
