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

export default function App() {
  const navigate = useNavigate()

  // null while we ask the server; then the payload from GET /api/auth/me
  const [session, setSession] = useState(null)

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
    return (
      <ChangePassword
        session={session}
        onChanged={(who) => { setSession(who); navigate(homeFor(who), { replace: true }) }}
        onSignOut={signOut}
      />
    )
  }

  if (!session.authenticated) {
    return <Login apps={session.apps} onSignedIn={(who) => {
      setSession(who)
      navigate(homeFor(who), { replace: true })
    }} />
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
