// Audit Logs & Security.
//
// Laid out as the design (frontend/Global admin GUI/Audit Logs & security.png):
// four numbers and the security posture, the recent activity in words, and
// the security controls along the bottom. One slim row of filters and the
// export sit above the table; the design shows the most recent page, and the
// filters only narrow it.
//
// Read-only, because the table is. Every number is a query result: a
// near-empty log on the first day is the correct answer, and the screen says
// so rather than showing a plausible figure. The posture and the controls are
// read from the running configuration (GET /api/admin/audit/controls) — the
// design's sample claims (MFA, SCIM, an IP allowlist) are not shown, because
// Core does not have them.

import { useCallback, useEffect, useState } from 'react'
import { admin } from '../api'
import {
  actionLabel, posture, resultBadge, shortWhen, sourceLabel, targetLabel,
} from './present.js'

// Actions grouped for the filter, from the prefixes audit() actually writes.
const ACTION_GROUPS = [
  ['', 'Any activity'],
  ['login.', 'Sign-in'],
  ['user.', 'People'],
  ['role.', 'Roles'],
  ['license.', 'Seats'],
  ['tool_rule.', 'Tool rules'],
  ['import.', 'Imports'],
  ['admin.', 'Refused admin access'],
  ['gate.', 'Refused application access'],
  ['oauth.', 'Application sign-in (OIDC)'],
]

const WINDOWS = [[null, 'All time'], [1, 'Last 24 hours'], [7, 'Last 7 days'],
                 [30, 'Last 30 days'], [90, 'Last 90 days']]

function full(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function Stat({ value, label }) {
  return (
    <div className="maec-stat">
      <span className="maec-stat-value">{value}</span>
      <span className="maec-stat-label">{label}</span>
    </div>
  )
}

export default function AuditScreen() {
  const [data, setData] = useState(null)
  const [stats, setStats] = useState(null)
  const [controls, setControls] = useState(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  // platform: events that belong to no organisation — failed sign-ins for
  // unknown addresses, refused client credentials. Global Admin only.
  const [filters, setFilters] = useState({
    q: '', action: '', result: '', days: 30, platform: false,
  })
  const [page, setPage] = useState(1)

  const load = useCallback(() => (
    // a short page, as the design's "recent" list; the pager goes further
    admin.audit({ ...filters, page, page_size: 10 })
      .then(setData)
      .catch((e) => setError(e.message))
  ), [filters, page])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    admin.auditStats().then(setStats).catch(() => {})
    admin.auditControls().then(setControls).catch(() => {})
  }, [])

  const change = (patch) => { setFilters((f) => ({ ...f, ...patch })); setPage(1) }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  const state = controls ? posture(controls.controls) : null
  const opened = open && data.events.find((x) => x.id === open)

  return (
    <div className="maec-card">
      <h1 className="maec-h1">Audit Logs &amp; Security</h1>
      <p className="maec-lede">
        Review administrative activity, permission changes, authentication events, and security controls.
      </p>

      <div className="maec-stats audit">
        <Stat value={stats ? stats.events.toLocaleString() : '…'}
              label={`Events (${stats?.window_days ?? 30} days)`} />
        <Stat value={stats ? stats.role_changes.toLocaleString() : '…'} label="Role changes" />
        <Stat value={stats ? stats.security_alerts.toLocaleString() : '…'} label="Security alerts" />
        <Stat value={stats ? stats.admin_actions.toLocaleString() : '…'} label="Admin actions logged" />
        <div className="maec-stat maec-posture">
          <div className="maec-posture-head">
            Security posture
            {state && <span className={`maec-chip ${state.tone}`}>{state.label}</span>}
            {state && <span className="maec-faint">{state.count}</span>}
          </div>
          <span className="maec-posture-line">{state ? state.line : '…'}</span>
        </div>
      </div>

      {data.scoped && (
        <p className="maec-note" style={{ marginTop: 16 }}>
          You are seeing events for the applications you lead. A Global Admin
          sees the whole organisation.
        </p>
      )}

      <h2 className="maec-section">Recent Audit Activity</h2>

      <div className="maec-toolbar maec-filters">
        {data.can_see_platform && (
          <select className="maec-select" value={filters.platform ? 'platform' : 'org'}
                  aria-label="Whose events"
                  onChange={(e) => change({ platform: e.target.value === 'platform' })}>
            <option value="org">This organisation</option>
            <option value="platform">Platform events</option>
          </select>
        )}
        <input className="maec-search" placeholder="Search actor or target..."
               aria-label="Search actor or target"
               value={filters.q} onChange={(e) => change({ q: e.target.value })} />
        <select className="maec-select" value={filters.action} aria-label="Activity"
                onChange={(e) => change({ action: e.target.value })}>
          {ACTION_GROUPS.map(([value, label]) => <option key={label} value={value}>{label}</option>)}
        </select>
        <select className="maec-select" value={filters.result} aria-label="Result"
                onChange={(e) => change({ result: e.target.value })}>
          <option value="">Any result</option>
          {data.results.map((r) => <option key={r} value={r}>{resultBadge(r).label}</option>)}
        </select>
        <select className="maec-select" value={filters.days ?? ''} aria-label="Period"
                onChange={(e) => change({ days: e.target.value ? Number(e.target.value) : null })}>
          {WINDOWS.map(([value, label]) => <option key={label} value={value ?? ''}>{label}</option>)}
        </select>
        <button type="button" className="maec-btn secondary" onClick={() => admin.exportAudit(filters)}>
          Export CSV
        </button>
      </div>

      {data.platform && (
        <p className="maec-note">
          Platform events belong to no organisation: sign-in attempts for
          addresses with no account, applications that failed to prove who
          they are, and clients registered from the command line. The numbers
          above still count this organisation&apos;s events.
        </p>
      )}

      {error && <p className="maec-error">{error}</p>}

      <div className="maec-table-wrap">
        <table className="maec-table">
          <thead>
            <tr>
              <th>Timestamp</th><th>Actor</th><th>Action</th>
              <th>Target</th><th>Source</th><th>Result</th>
            </tr>
          </thead>
          <tbody>
            {data.events.map((e) => {
              const result = resultBadge(e.result)
              return (
                <tr key={e.id} className={`maec-opens${open === e.id ? ' maec-open' : ''}`}
                    onClick={() => setOpen(open === e.id ? null : e.id)}>
                  <td title={full(e.created_at)} style={{ whiteSpace: 'nowrap' }}>{shortWhen(e.created_at)}</td>
                  {/* the sentinel means the event genuinely had nobody to
                      name — a sign-in attempt with no address supplied */}
                  <td>{e.anonymous ? 'unknown' : e.actor_email}</td>
                  <td>
                    <button type="button" className="maec-linkish" title={e.action}
                            aria-expanded={open === e.id}
                            onClick={(ev) => { ev.stopPropagation(); setOpen(open === e.id ? null : e.id) }}>
                      {actionLabel(e.action)}
                    </button>
                  </td>
                  <td>{targetLabel(e)}</td>
                  <td>{sourceLabel(e.source)}</td>
                  <td><span className={`maec-chip ${result.tone}`}>{result.label}</span></td>
                </tr>
              )
            })}
            {data.total === 0 && (
              <tr><td colSpan={6}>
                <p className="maec-lede">
                  No activity matches these filters. On a new installation
                  that is expected — the log fills as the platform is used.
                </p>
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {opened && (
        <div className="maec-detail">
          <h3 className="maec-h3" style={{ marginTop: 0 }}>
            {actionLabel(opened.action)} <span className="maec-faint">({opened.action})</span>
          </h3>
          <dl className="maec-facts">
            <dt>When</dt><dd>{full(opened.created_at)}</dd>
            <dt>Actor</dt><dd>{opened.anonymous ? '— (no address supplied)' : opened.actor_email}</dd>
            <dt>Target</dt><dd>{opened.target_label || '—'}{opened.target_type
              ? <span className="maec-faint"> ({opened.target_type}: {opened.target_id || '—'})</span> : null}</dd>
            <dt>From</dt><dd>{opened.ip || '—'}</dd>
            <dt>Application</dt><dd>{opened.application_name || '—'}</dd>
            <dt>User agent</dt><dd className="maec-faint">{opened.user_agent || '—'}</dd>
          </dl>
          {(opened.before || opened.after) && (
            <div className="maec-diff">
              {opened.before && (
                <div><h4 className="maec-h4">Before</h4><pre>{JSON.stringify(opened.before, null, 2)}</pre></div>
              )}
              {opened.after && (
                <div><h4 className="maec-h4">After</h4><pre>{JSON.stringify(opened.after, null, 2)}</pre></div>
              )}
            </div>
          )}
        </div>
      )}

      {data.pages > 1 && (
        <div className="maec-pager">
          <button type="button" className="maec-btn secondary" disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}>Previous</button>
          <span className="maec-lede">Page {data.page} of {data.pages} — {data.total} events</span>
          <button type="button" className="maec-btn secondary" disabled={page >= data.pages}
                  onClick={() => setPage((p) => p + 1)}>Next</button>
        </div>
      )}

      {controls && (
        <p className="maec-controls-strip">
          <strong>Security controls:</strong>
          {controls.controls.map((c, i) => (
            <span key={c.key} title={`${c.on ? 'On' : 'Off'} — enforced in ${c.where}${c.note ? ` (${c.note})` : ''}`}
                  className={c.on ? undefined : 'off'}>
              {i > 0 && ' • '}{c.label}{c.on ? '' : ' (off)'}
            </span>
          ))}
        </p>
      )}
    </div>
  )
}
