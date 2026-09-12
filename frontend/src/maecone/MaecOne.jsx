// The MAEC One frame — the platform pitch and its eight module tiles on the
// left, whatever the caller supplies on the right.
//
// Two screens sit in it: the sign-in card before you are known, and the
// launcher afterwards. Keeping the frame here is what stops those two
// drifting apart, since between them the only thing that changes is the
// right-hand panel and whether the tiles do anything when clicked.

export const Svg = (props) => (
  <svg
    viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}
  />
)

export const ICONS = {
  tools: (p) => (
    <Svg {...p}><path d="M12 2.6 20.5 7v10L12 21.4 3.5 17V7Z" /><path d="M12 12.2 20.5 7M12 12.2 3.5 7m8.5 5.2v9.2" /></Svg>
  ),
  project: (p) => (
    <Svg {...p}><path d="M6 3h9l4 4v14H6Z" /><path d="M9 11h7M9 15h7M9 7h3" /></Svg>
  ),
  finance: (p) => (
    <Svg {...p}><path d="M6 3h9l4 4v14H6Z" /><path d="M12 9.5v7M13.8 11.3a1.8 1.8 0 0 0-3.6.4c0 2 3.6 1 3.6 3a1.8 1.8 0 0 1-3.6.4" /></Svg>
  ),
  people: (p) => (
    <Svg {...p}><circle cx="9" cy="8" r="3.1" /><path d="M3.5 20a5.5 5.5 0 0 1 11 0" /><path d="M16 5.6a3.1 3.1 0 0 1 0 5.9M17.5 14.6A5.5 5.5 0 0 1 20.5 20" /></Svg>
  ),
  clock: (p) => (
    <Svg {...p}><circle cx="12" cy="12" r="8.6" /><path d="M12 7v5.3l3.4 2" /></Svg>
  ),
  card: (p) => (
    <Svg {...p}><rect x="2.6" y="5.4" width="18.8" height="13.2" rx="2.4" /><path d="M2.6 10h18.8" /><path d="M6.6 14.6h3.2" /></Svg>
  ),
  calendar: (p) => (
    <Svg {...p}><rect x="3.4" y="5" width="17.2" height="15.6" rx="2.4" /><path d="M3.4 10h17.2M8.4 3v4M15.6 3v4" /><path d="M8 14h.01M12 14h.01M16 14h.01" /></Svg>
  ),
  kpa: (p) => (
    <Svg {...p}><path d="M12 2.7 20 6v6.2c0 4.4-3.3 7.6-8 9.1-4.7-1.5-8-4.7-8-9.1V6Z" /><path d="m12 8.4 1.3 2.7 2.9.4-2.1 2.1.5 2.9-2.6-1.4-2.6 1.4.5-2.9-2.1-2.1 2.9-.4Z" /></Svg>
  ),
  shieldCheck: (p) => (
    <Svg {...p}><path d="M12 2.7 20 6v6.2c0 4.4-3.3 7.6-8 9.1-4.7-1.5-8-4.7-8-9.1V6Z" /><path d="m8.8 12 2.2 2.2 4.2-4.4" /></Svg>
  ),
  bolt: (p) => (
    <Svg {...p}><path d="M13.4 2.4 5.2 13.2h5.6l-1.4 8.4 8.4-11.1h-5.8Z" /></Svg>
  ),
  target: (p) => (
    <Svg {...p}><circle cx="12" cy="12" r="8.6" /><circle cx="12" cy="12" r="3.4" /><path d="M12 1.8v3.4M12 18.8v3.4M1.8 12h3.4M18.8 12h3.4" /></Svg>
  ),
  cloud: (p) => (
    <Svg {...p}><path d="M7.2 18.6a4.3 4.3 0 0 1-.5-8.6 5.6 5.6 0 0 1 10.8-1.2 3.9 3.9 0 0 1 .3 7.7Z" /></Svg>
  ),
  mail: (p) => (
    <Svg {...p}><rect x="2.8" y="5" width="18.4" height="14" rx="2.4" /><path d="m3.4 7.3 8.6 6 8.6-6" /></Svg>
  ),
  lock: (p) => (
    <Svg {...p}><rect x="4.4" y="10.4" width="15.2" height="10.4" rx="2.4" /><path d="M8.2 10.4V7.6a3.8 3.8 0 0 1 7.6 0v2.8" /></Svg>
  ),
  badge: (p) => (
    <Svg {...p}><path d="M12 2.7 20 6v6.2c0 4.4-3.3 7.6-8 9.1-4.7-1.5-8-4.7-8-9.1V6Z" /><circle cx="12" cy="11.6" r="2.6" /><path d="M10 14v4l2-1.2 2 1.2v-4" /></Svg>
  ),
  arrow: (p) => (
    <Svg {...p}><path d="M4.5 12h15M13.5 6l6 6-6 6" /></Svg>
  ),
}

// The products, and how each one looks.
//
// The LIST is no longer here. It comes from GET /api/auth/me, computed from
// the organisation's subscriptions and this person's seats, because whether a
// tile can be opened is an entitlement question and entitlements are not the
// browser's to decide. What stays here is presentation — the icon and colour
// a product wears — keyed by the same `key` the server sends.
export const PRESENTATION = {
  engineering: { icon: 'tools', tone: 'blue' },
  projects: { icon: 'project', tone: 'green' },
  finance: { icon: 'finance', tone: 'orange' },
  people: { icon: 'people', tone: 'violet' },
  timesheet: { icon: 'clock', tone: 'teal' },
  expenses: { icon: 'card', tone: 'amber' },
  attendance: { icon: 'calendar', tone: 'rose' },
  kpa: { icon: 'kpa', tone: 'blue' },
}

// The product this deployment actually is: picking it opens in place rather
// than navigating away.
export const INTERNAL = 'engineering'

/**
 * Can this person open this product right now? Three things must hold: the
 * service exists, they hold a seat, and there is somewhere to send them.
 * The server decides the middle one. A `true` here only shows a tile — the
 * API refuses the same request independently.
 */
export const isOpenable = (app) => (
  !!app && app.status === 'live' && !!app.entitled
  && (app.key === INTERNAL || !!app.base_url)
)

const look = (key) => PRESENTATION[key] || { icon: 'tools', tone: 'blue' }

const CAPABILITIES = [
  ['shieldCheck', 'Secure Access'],
  ['bolt', 'Smart Automation'],
  ['target', 'Accurate Results'],
  ['cloud', 'Seamless Integration'],
]

// Statements we can stand behind. The previous three claimed ISO 27001 and
// SOC 2 Type II, which Mirage AEC does not hold — and a compliance claim on
// a sign-in page is exactly what a client's procurement team checks.
export const BADGES = [
  ['Encrypted', 'in transit'],
  ['Role-based', 'access'],
  ['Every sign-in', 'audited'],
]

/**
 * @param panel  the right-hand column: the sign-in card, or the welcome panel
 * @param apps   the catalogue from GET /api/auth/me. Before sign-in it comes
 *               without an `entitled` field, so nothing is openable — which
 *               is right: nothing should look clickable before you are known.
 * @param onPick called with an app when an openable tile is clicked. Omit it
 *               and the tiles are presentational.
 */
export default function MaecOne({ panel, apps = [], onPick }) {
  return (
    <div className="signin">
      <div className="signin-body">
        <section className="signin-pitch">
          <div className="maec-lockup">
            <img src="/maec-logo.png" alt="MAEC" />
            <div className="maec-one"><span>ONE</span></div>
          </div>

          <h1 className="signin-headline">
            One Platform.<br />
            Everything <span>Connected.</span>
          </h1>
          <p className="signin-standfirst">
            Engineering, Projects, People &amp; Business —<br />
            all in one secure platform.
          </p>

          <ul className="module-grid">
            {apps.map((app) => {
              const { key, name, description } = app
              const { icon, tone } = look(key)
              const Icon = ICONS[icon]
              const built = app.status === 'live'
              const live = !!onPick && isOpenable(app)
              // One face for both screens — including the state line, which is
              // why the two columns are the same height rather than merely
              // close. Only the wording changes with what you can do here.
              const face = (
                <>
                  <span className={`module-icon tone-${tone}`}><Icon width="27" height="27" /></span>
                  <h2>{name}</h2>
                  <p>{description}</p>
                  <span className="module-state">
                    {live
                      ? <>Open <ICONS.arrow width="13" height="13" /></>
                      : built
                        ? (onPick && !app.entitled ? 'No access' : 'Available')
                        : 'Coming soon'}
                  </span>
                </>
              )
              return (
                <li key={key}>
                  {onPick ? (
                    <button
                      type="button"
                      className={`module-tile${live ? ' live' : ''}`}
                      disabled={!live}
                      title={
                        live ? `Open ${name}`
                          : built ? `You do not have access to ${name}`
                            : `${name} is not built yet`
                      }
                      onClick={() => onPick(app)}
                    >
                      {face}
                    </button>
                  ) : (
                    <div className={`module-tile${built ? ' built' : ''}`}>{face}</div>
                  )}
                </li>
              )
            })}
          </ul>

          <ul className="capability-strip">
            {CAPABILITIES.map(([icon, label]) => {
              const Icon = ICONS[icon]
              return <li key={label}><Icon width="17" height="17" />{label}</li>
            })}
          </ul>
        </section>

        <section className="signin-panel">{panel}</section>
      </div>

      <footer className="signin-footer">
        <span>© {new Date().getFullYear()} MAEC. All rights reserved.</span>
        <span className="signin-footer-mid">Privacy Policy<i /> Terms of Use</span>
        <span>Need help? <a href="mailto:support@mirageaec.com">support@mirageaec.com</a></span>
      </footer>
    </div>
  )
}
