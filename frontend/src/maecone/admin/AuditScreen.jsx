// Screen 004 — Audit Logs & Security.
//
// Read-only, because the table is. Every number on this page is a query
// result: a near-empty log on the first day is the correct answer, and the
// screen says so rather than showing a plausible figure.
//
// The controls strip at the bottom reports what is actually switched on,
// read from the running configuration, and names where each is enforced —
// so a claim here can be checked against the code rather than believed.

import { useCallback, useEffect, useState } from 'react'
import { admin } from '../api'

const RESULT_TONE = { success: 'granted', warning: 'warn', blocked: 'denied' }

// Actions grouped for the filter, from the prefixes audit() actually writes.
const ACTION_GROUPS = [
  ['', 'Any activity'],
  ['login.', 'Sign-in'],
  ['user.', 'People'],
  ['role.', 'Roles'],
  ['license.', 'Seats'],
  ['tool_rule.', 'Tool rules'],
  ['admin.', 'Refused admin access'],
  ['app.', 'Refused product access'],
]

const WINDOWS = [[null, 'All time'], [1, 'Last 24 hours'], [7, 'Last 7 days'],
                 [30, 'Last 30 days'], [90, 'Last 90 days']]

function when(iso) {
  if (!iso) return '—'
  const at = new Date(iso)
  return at.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function Card({ label, value, hint }) {
  return (
    <div className="maec-stat">
      <span className="maec-stat-value">{value}</span>
      <span className="maec-stat-label">{label}</span>
      {hint && <span className="maec-stat-hint">{hint}</span>}
    </div>
  )
}

export default function AuditScreen() {
  const [data, setData] = useState(null)
  const [stats, setStats] = useState(null)
  const [controls, setControls] = useState(null)
  const [error, setError] = useState('')
  const [open, setOpen] = useState(null)

  const [filters, setFilters] = useState({ q: '', action: '', result: '', days: 30 })
  const [page, setPage] = useState(1)

  const load = useCallback(() => {
    const params = { ...filters, page, page_size: 50 }
    return admin.audit(params)
      .then(setData)
      .catch((e) => setError(e.message))
  }, [filters, page])

  useEffect(() => { load() }, [load])
  useEffect(() => {
    admin.auditStats().then(setStats).catch(() => {})
    admin.auditControls().then(setControls).catch(() => {})
  }, [])

  const change = (patch) => { setFilters((f) => ({ ...f, ...patch })); setPage(1) }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  const empty = data.total === 0

  return (
    <div className="maec-stack">
      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h1 className="maec-h1">Audit Logs &amp; Security</h1>
            <p className="maec-lede">
              Review administrative activity, permission changes, authentication
              events, and security controls.
            </p>
          </div>
          <button type="button" className="maec-btn secondary"
                  onClick={() => admin.exportAudit(filters)}>
            Export CSV
          </button>
        </div>

        {data.scoped && (
          <p className="maec-note">
            You are seeing events for the applications you lead. A Global Admin
            sees the whole organisation.
          </p>
        )}

        {stats && (
          <div className="maec-stats">
            <Card label={`Events (${stats.window_days} days)`} value={stats.events} />
            <Card label="Role &amp; access changes" value={stats.role_changes} />
            <Card label="Security alerts" value={stats.security_alerts}
                  hint="warnings and refusals" />
            <Card label="Sign-ins" value={stats.sign_ins}
                  hint={`${stats.failed_sign_ins} failed`} />
            <Card label="Admin actions logged" value={stats.admin_actions} />
          </div>
        )}
      </div>

      <div className="maec-card">
        <div className="maec-toolbar">
          <input className="maec-search" placeholder="Search actor or target…"
                 value={filters.q} onChange={(e) => change({ q: e.target.value })} />
          <select className="maec-select" value={filters.action}
                  onChange={(e) => change({ action: e.target.value })}>
            {ACTION_GROUPS.map(([value, label]) => (
              <option key={label} value={value}>{label}</option>
            ))}
          </select>
          <select className="maec-select" value={filters.result}
                  onChange={(e) => change({ result: e.target.value })}>
            <option value="">Any result</option>
            {data.results.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
          <select className="maec-select" value={filters.days ?? ''}
                  onChange={(e) => change({
                    days: e.target.value ? Number(e.target.value) : null,
                  })}>
            {WINDOWS.map(([value, label]) => (
              <option key={label} value={value ?? ''}>{label}</option>
            ))}
          </select>
        </div>

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
              {data.events.map((e) => (
                <tr key={e.id}>
                  <td className="maec-mono">{when(e.created_at)}</td>
                  {/* the sentinel means the event genuinely had nobody to
                      name — a sign-in attempt with no address supplied */}
                  <td>{e.anonymous
                    ? <span className="maec-faint" title="No address was supplied">—</span>
                    : e.actor_email}</td>
                  <td>
                    <button type="button" className="maec-linkish"
                            onClick={() => setOpen(open === e.id ? null : e.id)}>
                      {e.action}
                    </button>
                  </td>
                  <td>
                    {e.target_type
                      ? <span className="maec-faint">{e.target_type}: {e.target_id || '—'}</span>
                      : '—'}
                  </td>
                  <td>{e.source || '—'}</td>
                  <td>
                    <span className={`maec-chip ${RESULT_TONE[e.result] || 'inactive'}`}>
                      {e.result}
                    </span>
                  </td>
                </tr>
              ))}
              {empty && (
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

        {data.pages > 1 && (
          <div className="maec-pager">
            <button type="button" className="maec-btn secondary" disabled={page <= 1}
                    onClick={() => setPage((p) => p - 1)}>Previous</button>
            <span className="maec-lede">
              Page {data.page} of {data.pages} — {data.total} events
            </span>
            <button type="button" className="maec-btn secondary"
                    disabled={page >= data.pages}
                    onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        )}

        {open && (() => {
          const e = data.events.find((x) => x.id === open)
          if (!e) return null
          return (
            <div className="maec-detail">
              <h3 className="maec-h3">{e.action}</h3>
              <dl className="maec-facts">
                <dt>When</dt><dd>{when(e.created_at)}</dd>
                <dt>Actor</dt><dd>{e.anonymous ? '— (no address supplied)' : e.actor_email}</dd>
                <dt>From</dt><dd>{e.ip || '—'}</dd>
                <dt>Application</dt><dd>{e.application || '—'}</dd>
                <dt>User agent</dt><dd className="maec-faint">{e.user_agent || '—'}</dd>
              </dl>
              {(e.before || e.after) && (
                <div className="maec-diff">
                  {e.before && (
                    <div>
                      <h4 className="maec-h4">Before</h4>
                      <pre>{JSON.stringify(e.before, null, 2)}</pre>
                    </div>
                  )}
                  {e.after && (
                    <div>
                      <h4 className="maec-h4">After</h4>
                      <pre>{JSON.stringify(e.after, null, 2)}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })()}
      </div>

      {controls && (
        <div className="maec-card">
          <h2 className="maec-h2">Active security controls</h2>
          <p className="maec-lede">
            Read from the running configuration, not written into this page.
            Each names where it is enforced.
          </p>
          <ul className="maec-controls">
            {controls.controls.map((c) => (
              <li key={c.key}>
                <span className={`maec-chip ${c.on ? 'granted' : 'inactive'}`}>
                  {c.on ? 'On' : 'Off'}
                </span>
                <span>
                  {c.label}
                  <span className="maec-faint"> — {c.where}</span>
                  {c.note && <span className="maec-faint"> ({c.note})</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
