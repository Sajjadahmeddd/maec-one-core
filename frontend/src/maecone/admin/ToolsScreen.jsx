// Tool-Level Settings — each app's features, and who may use them, here.
//
// Laid out as the design (frontend/Global admin GUI/Tool level settings.png):
// one row per feature, one column per role, and Status. The features are the
// apps' own: each app reports them when it starts (OPEN-DECISIONS #23), and
// they are grouped here under that app's monitoring line — when it last
// reported, its version, how many are new and how many it has stopped
// reporting. Every cell is a dropdown in the grid itself, shown as its pill:
//
//   Full Access  the role may use the feature. Where the role's own rules
//                say what it may do inside, they still apply.
//   No Access    the role may not use it at all.
//   Status       Active, or Inactive: switched off for everyone here.
//
// A feature the app no longer reports can be removed, after a confirmation;
// its key is then retired for good.

import { Fragment, useEffect, useMemo, useState } from 'react'
import { admin } from '../api'
import { accessBadge, monitorLine, roleOrder, toolLabel, toolStatus } from './present.js'

function PillSelect({ value, options, tone, label, busy, onChange }) {
  return (
    <select className={`maec-pill-select ${tone}`} value={value} aria-label={label}
            disabled={busy} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
    </select>
  )
}

export default function ToolsScreen() {
  const [data, setData] = useState(null)
  const [roles, setRoles] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState('')
  const [query, setQuery] = useState('')
  const [confirming, setConfirming] = useState('')    // the feature asked about

  const load = () => Promise.all([admin.toolRules(), admin.roles()])
    .then(([tools, all]) => { setData(tools); setRoles(all) })
    .catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  // the role columns, in the same order as User & Role Access
  const columns = useMemo(() => {
    if (!data || !roles) return []
    const known = new Set(data.roles.map((r) => r.id))
    return roleOrder(roles.roles).filter((r) => known.has(r.id))
  }, [data, roles])

  // the rows, grouped under their application
  const groups = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    const shown = data.modules.filter((m) => !needle
      || toolLabel(m).toLowerCase().includes(needle)
      || m.module_key.toLowerCase().includes(needle))
    return (data.applications || [])
      .map((a) => ({ app: a, rows: shown.filter((m) => m.application_key === a.key) }))
      .filter((g) => g.rows.length)
  }, [data, query])

  const save = async (key, work, done) => {
    setBusy(key); setError(''); setNote('')
    try {
      const result = await work()
      setNote(done(result))
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const people = (n) => (n === 1 ? '1 person re-resolves' : `${n} people re-resolve`)

  const setCell = (m, role, level) => save(
    `${m.application_key}:${m.module_key}:${role.id}`,
    () => admin.putToolRules([{
      application_key: m.application_key, module_key: m.module_key,
      role_id: role.id, access_level: level,
    }]),
    (r) => `${toolLabel(m)}: ${role.name} now ${accessBadge(level).label}. ${people(r.users_affected)} on their next request.`)

  const setStatus = (m, status) => save(
    `${m.application_key}:${m.module_key}:status`,
    () => admin.putToolStatus(m.application_key, m.module_key, status),
    (r) => `${toolLabel(m)} is now ${toolStatus(status).label}. ${people(r.users_affected)} on their next request.`)

  const remove = (m) => save(
    `${m.application_key}:${m.module_key}:remove`,
    () => admin.removeFeature(m.application_key, m.module_key),
    () => { setConfirming(''); return `${toolLabel(m)} was removed. Its key, ${m.module_key}, is retired and can't be reused.` })

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data || !roles) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  const width = columns.length + 2

  return (
    <div className="maec-card">
      <h1 className="maec-h1">Tool-Level Settings</h1>
      <p className="maec-lede">
        Configure tool-specific permissions, feature visibility, and action controls by role.
      </p>

      <div className="maec-toolbar" style={{ marginTop: 22 }}>
        <input
          className="maec-search"
          style={{ flex: '0 1 236px' }}
          placeholder="Search tools or permissions..."
          aria-label="Search tools or permissions"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>

      {error && <p className="maec-error">{error}</p>}
      {note && <p className="maec-note">{note}</p>}

      <div className="maec-table-wrap">
        <table className="maec-table maec-matrix">
          <thead>
            <tr>
              <th>Tool / Module</th>
              {columns.map((r) => <th key={r.id}>{r.name}</th>)}
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {groups.map(({ app, rows }) => {
              const line = monitorLine(app)
              return (
                <Fragment key={app.key}>
                  <tr className="maec-app-row">
                    <td colSpan={width}>
                      <strong>{app.name}</strong>
                      <span className={`maec-monitor${line.stale ? ' stale' : ''}`}
                            title={line.stale ? 'This app has not reported its features for over 24 hours' : undefined}>
                        {line.text}
                      </span>
                    </td>
                  </tr>
                  {rows.map((m) => {
                    const tool = `${m.application_key}:${m.module_key}`
                    const off = m.status === 'inactive'
                    const quiet = !!m.not_reported_since
                    return (
                      <tr key={tool} className={[off && 'maec-row-off', quiet && 'maec-row-quiet']
                        .filter(Boolean).join(' ') || undefined}>
                        <td title={`Key: ${m.module_key}`}>
                          {toolLabel(m)}
                          {m.is_new && <span className="maec-chip scoped maec-badge">New</span>}
                          {off && <div className="maec-sub">Switched off for everyone</div>}
                          {quiet && (
                            <div className="maec-sub">
                              No longer reported by the app{' '}
                              {confirming === tool ? (
                                <>
                                  · Remove for good?{' '}
                                  <button type="button" className="maec-linkish maec-danger"
                                          disabled={busy === `${tool}:remove`}
                                          onClick={() => remove(m)}>Yes, remove</button>{' '}
                                  <button type="button" className="maec-linkish"
                                          onClick={() => setConfirming('')}>Cancel</button>
                                </>
                              ) : (
                                <button type="button" className="maec-linkish maec-danger"
                                        onClick={() => setConfirming(tool)}>Remove</button>
                              )}
                            </div>
                          )}
                        </td>
                        {columns.map((role) => {
                          const cell = data.cells[tool]?.[role.id] || { access_level: 'no_access' }
                          return (
                            <td key={role.id}>
                              <PillSelect
                                value={cell.access_level}
                                options={data.levels}
                                tone={accessBadge(cell.access_level).tone}
                                label={`${toolLabel(m)}, ${role.name}`}
                                busy={busy === `${tool}:${role.id}`}
                                onChange={(level) => setCell(m, role, level)}
                              />
                            </td>
                          )
                        })}
                        <td>
                          <PillSelect
                            value={m.status}
                            options={data.statuses}
                            tone={toolStatus(m.status).tone}
                            label={`${toolLabel(m)}, status`}
                            busy={busy === `${tool}:status`}
                            onChange={(status) => setStatus(m, status)}
                          />
                        </td>
                      </tr>
                    )
                  })}
                </Fragment>
              )
            })}
            {groups.length === 0 && (
              <tr><td colSpan={width}>
                <p className="maec-lede">
                  {query ? `No tool matches “${query}”.` : 'No app has reported its features yet.'}
                </p>
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="maec-faint" style={{ fontSize: 11, marginTop: 14 }}>
        Features appear here automatically when an app reports them. New features
        start switched off for everyone except Global Admin. Switching a role to
        No Access hides the feature in the app and blocks it, from the
        person&apos;s next click. To give one person a different role in one
        app, use User &amp; Role Access with that app as the scope.
      </p>
    </div>
  )
}
