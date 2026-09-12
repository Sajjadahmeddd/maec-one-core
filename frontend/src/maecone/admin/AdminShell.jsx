// The Global Admin shell — layout only.
//
// The five screens are the next build. What is here is the frame they will
// hang in: the header, the tab strip, and a placeholder per tab, all built
// on the tokens in ../theme.css so those screens inherit a settled look
// rather than inventing one.
//
// Reaching this at all is a convenience, not a control. `require_global_admin`
// on the server refuses /api/admin/* to anyone else, whatever the browser
// believes, and the guard refuses the whole prefix a second time.

import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'

import AuditScreen from './AuditScreen.jsx'
import OnboardingScreen from './OnboardingScreen.jsx'
import ProvisioningScreen from './ProvisioningScreen.jsx'
import RolesScreen from './RolesScreen.jsx'
import UsersScreen from './UsersScreen.jsx'
import ToolsScreen from './ToolsScreen.jsx'

// The other products, as top-level pills. Only Global Admin is built; the
// rest are named so the shell reads as part of one platform rather than a
// tool on its own, and they light up as those services arrive.
const SECTIONS = [
  { key: 'admin', label: 'Global Admin', to: '/admin', ready: true },
  { key: 'engineering', label: 'Engineering Tools', to: '/hapext', ready: true },
  { key: 'projects', label: 'Project Management', to: null, ready: false },
  { key: 'finance', label: 'Finance & HR', to: null, ready: false },
]

const TABS = [
  { path: 'users', label: 'Users & Access',
    lede: 'Create people, assign roles and application seats, manage status.' },
  { path: 'roles', label: 'Roles & Permissions',
    lede: 'Who holds which role, at which scope, and what that lets them do.' },
  { path: 'tools', label: 'Tool Access',
    lede: 'Per-organisation rules that narrow what a role may do with a module.' },
  { path: 'provisioning', label: 'Provisioning',
    lede: 'Directory groups mapped to roles, and what a new joiner gets by default.' },
  { path: 'audit', label: 'Audit Log',
    lede: 'Every sign-in, grant and refusal — who, when, from where.' },
  { path: 'onboarding', label: 'Onboarding',
    lede: 'Bulk import of people, with a validation report before anything is written.' },
]

// Which tabs have a real screen behind them. The rest render a placeholder
// rather than a fabricated one.
// every tab now has a screen behind it
const BUILT = new Set(
  ['users', 'roles', 'tools', 'audit', 'onboarding', 'provisioning'])


function initials(email = '') {
  const local = email.split('@')[0] || ''
  const parts = local.split(/[._-]+/).filter(Boolean)
  const letters = parts.length > 1
    ? parts[0][0] + parts[1][0]
    : local.slice(0, 2)
  return (letters || '?').toUpperCase()
}

function Placeholder({ label, lede }) {
  return (
    <div className="maec-card maec-placeholder">
      <h1 className="maec-h1">{label}</h1>
      <p className="maec-lede">{lede}</p>
      <span className="maec-soon">Coming in the next build</span>
    </div>
  )
}

export default function AdminShell({ session, onSignOut }) {
  const navigate = useNavigate()

  return (
    <div className="maec-admin">
      <header className="maec-admin-header">
        <button className="maec-wordmark" onClick={() => navigate('/home')}
                title="Back to MAEC One">
          <img src="/maec-logo.png" alt="MAEC" />
          <span>ONE</span>
        </button>

        <nav>
          <ul className="maec-nav">
            {SECTIONS.map(({ key, label, to, ready }) => (
              <li key={key}>
                <button
                  type="button"
                  className={`maec-pill${key === 'admin' ? ' active' : ''}`}
                  disabled={!ready}
                  title={ready ? `Go to ${label}` : 'Coming soon'}
                  onClick={() => to && navigate(to)}
                >
                  {label}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <span className="maec-spacer" />

        <div className="maec-who">
          <span className="maec-who-email">{session?.email}</span>
          <span className="maec-avatar" aria-hidden="true">{initials(session?.email)}</span>
          <button type="button" className="maec-btn secondary" onClick={onSignOut}>
            Sign out
          </button>
        </div>
      </header>

      <nav className="maec-tabs">
        {TABS.map(({ path, label }) => (
          <NavLink
            key={path}
            to={`/admin/${path}`}
            className={({ isActive }) => `maec-tab${isActive ? ' active' : ''}`}
          >
            {label}
          </NavLink>
        ))}
      </nav>

      <main className="maec-body">
        <Routes>
          <Route index element={<Navigate to="users" replace />} />
          <Route path="users" element={<UsersScreen />} />
          <Route path="roles" element={<RolesScreen />} />
          <Route path="audit" element={<AuditScreen />} />
          <Route path="onboarding" element={<OnboardingScreen />} />
          <Route path="provisioning" element={<ProvisioningScreen />} />
          <Route path="tools" element={<ToolsScreen />} />
          {/* the remaining three arrive in the next build */}
          {TABS.filter((t) => !BUILT.has(t.path)).map(({ path, label, lede }) => (
            <Route key={path} path={path}
                   element={<Placeholder label={label} lede={lede} />} />
          ))}
          <Route path="*" element={<Navigate to="/admin/users" replace />} />
        </Routes>
      </main>
    </div>
  )
}
