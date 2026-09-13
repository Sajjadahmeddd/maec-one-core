// MAEC One Core — the whole application.
//
// Four things live here and nothing else: the sign-in screen, the launcher,
// the forced password change, and the Global Admin panel. There is no page
// state machine and no product tabs; those belong to Engineering Tools,
// which is a separate deployment.
//
// Where you land after signing in is decided by the server. Every route
// below is a convenience — the API refuses what this person may not do
// regardless of what the browser renders.

import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'

import ChangePassword from './maecone/ChangePassword.jsx'
import Launcher from './maecone/Launcher.jsx'
import Login from './maecone/Login.jsx'
import AdminShell from './maecone/admin/AdminShell.jsx'
import { SESSION_EXPIRED, auth as authApi } from './maecone/api'
import { INTERNAL } from './maecone/MaecOne.jsx'

/** A Global Admin lands in the panel; everyone else on the launcher. */
const homeFor = (session) => (session?.is_global_admin ? '/admin' : '/')

/**
 * Where to go once signed in, when Core's authorize endpoint sent the browser
 * here first. The guard redirects an unsigned or must-change-password visitor
 * to `/?next=<the authorize URL>`; after sign-in (and any password change) we
 * go back there, and the server re-checks everything.
 *
 * Only ever back to /oauth/authorize on this origin. Anything else in `next`
 * is dropped, so the parameter cannot be used to send someone elsewhere.
 */
function authorizeReturn() {
  try {
    const raw = new URLSearchParams(window.location.search).get('next')
    if (!raw) return null
    const url = new URL(raw, window.location.origin)
    if (url.origin !== window.location.origin || url.pathname !== '/oauth/authorize') return null
    return url.pathname + url.search
  } catch {
    return null
  }
}

export default function App() {
  const navigate = useNavigate()

  // read once: the address bar changes as soon as the client router navigates
  const [next] = useState(authorizeReturn)

  // null while we ask the server; then the payload from GET /api/auth/me
  const [session, setSession] = useState(null)

  // Signed in, with no password change outstanding: finish the handoff.
  useEffect(() => {
    if (next && session?.authenticated && !session.must_change_password) {
      window.location.assign(next)
    }
  }, [next, session])

  /** After sign-in or a password change: back to authorize, or home. */
  const land = (who) => {
    setSession(who)
    if (!next) navigate(homeFor(who), { replace: true })
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
    return <ChangePassword session={session} onChanged={land} onSignOut={signOut} />
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
      {/* The launcher is Core's home: the products this person may open. */}
      <Route path="/" element={
        <Launcher
          session={session}
          onOpen={(app) => {
            // Core does not host any product. A tile opens by URL, from
            // applications.base_url — which is empty until each service is
            // deployed and its row updated. See EXTRACTION-LOG.md.
            if (app?.base_url) window.location.assign(app.base_url)
          }}
          onAdmin={() => navigate('/admin')}
          onSignOut={signOut}
        />
      } />

      {/* Convenience only: require_global_admin refuses /api/admin/* to
          anyone else, so a non-admin who types this gets an empty shell and
          403s from every call it makes. */}
      <Route path="/admin/*" element={
        session.is_global_admin
          ? <AdminShell session={session} onSignOut={signOut} />
          : <Navigate to="/" replace />
      } />

      <Route path="*" element={<Navigate to={homeFor(session)} replace />} />
    </Routes>
  )
}

// Re-exported so a future product link can ask which application this
// deployment is. Core is not a product, so it is none of them.
export { INTERNAL }
