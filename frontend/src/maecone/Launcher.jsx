// The MAEC One launcher — where you land once signed in.
//
// Same frame as the sign-in screen, so the page you just filled in does not
// jump around underneath you: the tiles stay exactly where they were and only
// the right-hand panel changes. What changes is that the tiles are now
// controls — for the products this person actually holds a seat on.
//
// The list comes from GET /api/auth/me, not from a constant in this file. A
// product appears openable only when the organisation subscribes to it and
// this person has been given a seat, and the API refuses the same request on
// its own account, so a tile is a convenience rather than the gate.

import MaecOne, { BADGES, ICONS, INTERNAL, PRESENTATION, isOpenable } from './MaecOne.jsx'

export default function Launcher({ session, onOpen, onAdmin, onSignOut }) {
  const apps = session?.apps || []
  const open = apps.filter(isOpenable)
  const rest = apps.length - open.length

  // The product this deployment is opens in place; a separately hosted one is
  // a full navigation to wherever it lives.
  const pick = (app) => {
    if (!isOpenable(app)) return
    if (app.key === INTERNAL) onOpen(app)
    else window.location.assign(app.base_url)
  }

  const panel = (
    <div className="signin-card launch-card">
      <div className="signin-mark"><img src="/maec-logo.png" alt="" /></div>

      <p className="launch-status">
        <ICONS.shieldCheck width="15" height="15" />
        Signed in
      </p>

      <h2 className="signin-welcome">Welcome back</h2>
      <p className="launch-name">{session?.display_name || 'MAEC'}</p>
      {session?.email && <p className="signin-sub">{session.email}</p>}

      <p className="launch-lede">
        Your MAEC One workspace is ready. Choose an application on the left
        to get started.
      </p>

      {session?.is_global_admin && (
        <button type="button" className="launch-open launch-admin" onClick={onAdmin}>
          <span className="module-icon tone-blue">
            <ICONS.shieldCheck width="22" height="22" />
          </span>
          <span className="launch-open-text">
            <strong>Global Admin</strong>
            Roles, tool access, provisioning and the audit log
          </span>
          <ICONS.arrow width="16" height="16" />
        </button>
      )}

      <ul className="launch-list">
        {open.map((app) => {
          const { icon, tone } = PRESENTATION[app.key] || { icon: 'tools', tone: 'blue' }
          const Icon = ICONS[icon]
          return (
            <li key={app.key}>
              <button type="button" className="launch-open" onClick={() => pick(app)}>
                <span className={`module-icon tone-${tone}`}>
                  <Icon width="22" height="22" />
                </span>
                <span className="launch-open-text">
                  <strong>{app.name}</strong>
                  {app.description}
                </span>
                <ICONS.arrow width="16" height="16" />
              </button>
            </li>
          )
        })}
      </ul>

      {session?.organization_suspended ? (
        <p className="launch-soon">
          Your organisation&apos;s access to MAEC One is suspended, so no
          application can be opened. Your administrator can tell you more.
        </p>
      ) : open.length === 0 && (
        <p className="launch-soon">
          You do not have a seat on any application yet. Ask your
          administrator to assign one.
        </p>
      )}

      {rest > 0 && open.length > 0 && (
        <p className="launch-soon">
          {rest} more {rest === 1 ? 'application is' : 'applications are'} on
          the way, or waiting on access. You will see them light up here.
        </p>
      )}

      <button type="button" className="launch-signout" onClick={onSignOut}>
        Sign out
      </button>

      <ul className="signin-badges">
        {BADGES.map(([label, sub]) => (
          <li key={label}>
            <ICONS.badge width="18" height="18" />
            <span><strong>{label}</strong>{sub}</span>
          </li>
        ))}
      </ul>
    </div>
  )

  return <MaecOne panel={panel} apps={apps} onPick={pick} />
}
