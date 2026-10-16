// MAEC One Core — the whole application.
//
// Four things live here and nothing else: the sign-in screen, the launcher,
// the password change (forced, or chosen at /change-password), and the
// Global Admin panel. There is no page state machine and no product tabs;
// those belong to Engineering Tools, which is a separate deployment.
//
// Signing in lands on the launcher — for everyone, a Global Admin included —
// unless a `next` that safeNext() follows sent them here. Every route
// below is a convenience — the API refuses what this person may not do
// regardless of what the browser renders.

import { useEffect, useMemo, useState } from 'react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'

import ChangePassword from './maecone/ChangePassword.jsx'
import Launcher from './maecone/Launcher.jsx'
import Login from './maecone/Login.jsx'
import AdminShell from './maecone/admin/AdminShell.jsx'
import { SESSION_EXPIRED, auth as authApi } from './maecone/api'
import { CHANGE_PASSWORD, HOME, backFrom, landing, safeNext, signInFirst } from './maecone/next.js'

/** Is this `next`, as safeNext() returned it, that page? */
const isChangePage = (target) => target?.split('?')[0] === CHANGE_PASSWORD

/**
 * The `next` this page was opened with, as given. Two things send a browser
 * here with one: an app's gate, with the page the person asked for in that app
 * (OPEN-DECISIONS #19), and Core's authorize endpoint. Whether it is followed
 * is decided by safeNext() — a live app's exact origin, or /oauth/authorize on
 * this one — once the catalogue of apps has arrived. Anything else goes to the
 * launcher, so the parameter cannot be used to send someone elsewhere.
 */
function rawNext() {
  try {
    return new URLSearchParams(window.location.search).get('next')
  } catch {
    return null
  }
}

export default function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const { pathname } = location

  // read once: the address bar changes as soon as the client router navigates.
  // Set again only when /change-password sends someone to sign in first.
  const [asked, setAsked] = useState(rawNext)

  // "Password changed", on the launcher, after a voluntary change
  const [notice, setNotice] = useState('')
  useEffect(() => { if (pathname !== '/') setNotice('') }, [pathname])

  // null while we ask the server; then the payload from GET /api/auth/me
  const [session, setSession] = useState(null)

  // Where `next` may take us — judged against the live apps' addresses, which
  // come with the session. null: no next, or one that is refused.
  const next = useMemo(
    () => (asked && session ? safeNext(asked, session.apps, window.location.origin) : null),
    [asked, session],
  )

  // Signed in, with no password change outstanding: go back where they were.
  // The change-password page is this app's own, so no page load is needed.
  useEffect(() => {
    if (!next || !session?.authenticated || session.must_change_password) return
    if (isChangePage(next)) {
      setAsked(null)
      navigate(next, { replace: true })
    } else {
      window.location.assign(next)
    }
  }, [next, session, navigate])

  // /change-password, not signed in: sign in first, then back to it.
  useEffect(() => {
    const there = session && !session.authenticated ? signInFirst(pathname) : null
    if (there) {
      setAsked(pathname)
      navigate(there, { replace: true })
    }
  }, [session, pathname, navigate])

  /** After sign-in or a password change: back where they were, when the
   *  `next` they came with is followed — the effect above takes them — and
   *  otherwise the launcher, whatever their role. */
  const land = (who) => {
    setSession(who)
    if (landing(asked, who.apps, window.location.origin) !== HOME) return
    navigate(HOME, { replace: true })
  }

  /** After the required change. Someone who came for /change-password has just
   *  done exactly that, so it is not shown again: the launcher, as before. */
  const changedRequired = (who) => {
    if (asked && isChangePage(safeNext(asked, who.apps, window.location.origin))) {
      setAsked(null)
      setSession(who)
      navigate(HOME, { replace: true })
      return
    }
    land(who)
  }

  /** After a voluntary change: the launcher, saying so. */
  const changedVoluntarily = (who) => {
    setSession(who)
    navigate(HOME, { replace: true })
    setNotice('Password changed')
  }

  useEffect(() => {
    authApi.me()
      .then(setSession)
      .catch(() => setSession({ authenticated: false, apps: [] }))
  }, [])

  // A lapsed session anywhere drops straight back to the sign-in screen
  useEffect(() => {
    const expired = () => {
      setSession({ authenticated: false, apps: [] })
      navigate('/', { replace: true })
    }
    window.addEventListener(SESSION_EXPIRED, expired)
    return () => window.removeEventListener(SESSION_EXPIRED, expired)
  }, [navigate])

  const signOut = async () => {
    try { await authApi.logout() } catch { /* the cookie goes either way */ }
    setSession({ authenticated: false, apps: [] })
    navigate('/', { replace: true })
  }

  if (session === null) {
    return (
      <div className="signin" style={{ display: 'grid', placeItems: 'center' }}>
        <span className="muted">Loading…</span>
      </div>
    )
  }

  // An administrator set this password and therefore knows it. The server
  // refuses every call but /api/auth/* until it is replaced, so there is
  // nowhere else to send them.
  if (session.must_change_password) {
    return <ChangePassword session={session} onChanged={changedRequired} onSignOut={signOut} />
  }

  if (!session.authenticated) {
    return <Login apps={session.apps} onSignedIn={land} />
  }

  // The effect above is taking the browser back to the application that sent
  // it here. There is nothing to show in the meantime.
  if (next) {
    return (
      <div className="signin" style={{ display: 'grid', placeItems: 'center' }}>
        <span className="muted">Signing you in…</span>
      </div>
    )
  }

  return (
    <Routes>
      {/* The launcher is Core's home, for everyone: every application, and
          what this person can do with each. Core hosts none of them; a tile
          opens its base_url (launcher.js). */}
      <Route path={HOME} element={
        <Launcher
          session={session}
          notice={notice}
          onAdmin={() => navigate('/admin')}
          onChangePassword={() => navigate(CHANGE_PASSWORD)}
          onSignOut={signOut}
        />
      } />

      {/* Anyone signed in may change their own password. The server asks for
          the current one, whatever this page shows. */}
      <Route path={CHANGE_PASSWORD} element={
        <ChangePassword
          voluntary
          session={session}
          onChanged={changedVoluntarily}
          onCancel={() => navigate(backFrom(location.state))}
        />
      } />

      {/* Global Admins only, from the launcher's card or by its address.
          Convenience only: require_global_admin refuses /api/admin/* to
          anyone else, whatever this renders. */}
      <Route path="/admin/*" element={
        session.is_global_admin
          ? <AdminShell session={session} onSignOut={signOut} />
          : <Navigate to={HOME} replace />
      } />

      {/* Anything else, a refused `next` included, is the launcher. */}
      <Route path="*" element={<Navigate to={HOME} replace />} />
    </Routes>
  )
}
