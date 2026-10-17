// The Global Admin shell: the header, the tab bar, and the screen under it.
//
// Laid out as the designs in frontend/Global admin GUI/ have it: the MAEC
// wordmark with the version, the person's address and avatar on the right,
// and the sections as a boxed tab bar on the page. The way back to the
// launcher, Change password and Sign out are in the menu the avatar opens;
// the wordmark goes to the launcher too.
//
// Reaching this at all is a convenience, not a control. `require_global_admin`
// on the server refuses /api/admin/* to anyone else, whatever the browser
// believes, and the guard refuses the whole prefix a second time.

import { useEffect, useRef, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'

import ApplicationsScreen from './ApplicationsScreen.jsx'
import AuditScreen from './AuditScreen.jsx'
import OnboardingScreen from './OnboardingScreen.jsx'
import RolesScreen from './RolesScreen.jsx'
import ToolsScreen from './ToolsScreen.jsx'
import UsersScreen from './UsersScreen.jsx'
import { CHANGE_PASSWORD, HOME } from '../next.js'

// "v1.0": major.minor of the version that was built (vite.config.js)
// eslint-disable-next-line no-undef
const VERSION = `v${String(__APP_VERSION__).split('.').slice(0, 2).join('.')}`

// The sections, in the order the designs and the brief give them.
// Provisioning (directory groups -> roles) has no tab: its API and data are
// unchanged, and nothing here deletes them.
const TABS = [
  { path: 'users', label: 'Users', element: <UsersScreen /> },
  { path: 'roles', label: 'User & Role Access', element: <RolesScreen /> },
  { path: 'tools', label: 'Tool-Level Settings', element: <ToolsScreen /> },
  { path: 'audit', label: 'Audit Logs & Security', element: <AuditScreen /> },
  { path: 'onboarding', label: 'User Onboarding & Import', element: <OnboardingScreen /> },
  { path: 'applications', label: 'Applications', element: <ApplicationsScreen /> },
]

/** The avatar's letter: the first of the address. */
const initial = (email = '') => (email.trim()[0] || '?').toUpperCase()

function AccountMenu({ email, onLauncher, onChangePassword, onSignOut }) {
  const [open, setOpen] = useState(false)
  const box = useRef(null)

  // closes on a click anywhere else, and on Escape
  useEffect(() => {
    if (!open) return undefined
    const away = (event) => { if (!box.current?.contains(event.target)) setOpen(false) }
    const escape = (event) => { if (event.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', away)
    document.addEventListener('keydown', escape)
    return () => {
      document.removeEventListener('mousedown', away)
      document.removeEventListener('keydown', escape)
    }
  }, [open])

  const pick = (action) => () => { setOpen(false); action() }

  return (
    <div className="maec-who" ref={box}>
      <button type="button" className="maec-who-button" aria-haspopup="menu"
              aria-expanded={open} aria-label={`Account menu for ${email}`}
              onClick={() => setOpen((o) => !o)}>
        <span className="maec-who-email">{email}</span>
        <span className="maec-avatar" aria-hidden="true">{initial(email)}</span>
      </button>
      {open && (
        <ul className="maec-menu" role="menu">
          <li role="none"><button type="button" role="menuitem" onClick={pick(onLauncher)}>Launcher</button></li>
          <li role="none"><button type="button" role="menuitem" onClick={pick(onChangePassword)}>Change password</button></li>
          <li role="none"><button type="button" role="menuitem" onClick={pick(onSignOut)}>Sign out</button></li>
        </ul>
      )}
    </div>
  )
}

export default function AdminShell({ session, onSignOut }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()

  return (
    <div className="maec-admin">
      <header className="maec-admin-header">
        <button type="button" className="maec-wordmark" onClick={() => navigate(HOME)}
                title="Back to the launcher">
          <img src="/maec-logo.png" alt="MAEC" />
          <span className="maec-version">{VERSION}</span>
        </button>

        <span className="maec-spacer" />

        <AccountMenu
          email={session?.email || ''}
          onLauncher={() => navigate(HOME)}
          // the voluntary change; its Back returns to this screen
          onChangePassword={() => navigate(CHANGE_PASSWORD, { state: { from: pathname } })}
          onSignOut={onSignOut}
        />
      </header>

      <main className="maec-body">
        <nav className="maec-tabs" aria-label="Global Admin sections">
          {TABS.map(({ path, label }) => (
            <NavLink key={path} to={`/admin/${path}`}
                     className={({ isActive }) => `maec-tab${isActive ? ' active' : ''}`}>
              {label}
            </NavLink>
          ))}
        </nav>

        <Routes>
          <Route index element={<Navigate to="users" replace />} />
          {TABS.map(({ path, element }) => <Route key={path} path={path} element={element} />)}
          <Route path="*" element={<Navigate to="/admin/users" replace />} />
        </Routes>
      </main>
    </div>
  )
}
