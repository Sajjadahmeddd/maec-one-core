// Tool-Level Settings — who may open each tool, here.
//
// Laid out as the design (frontend/Global admin GUI/Tool level settings.png):
// one row per tool, one column per role, and Status. Every cell is a dropdown
// in the grid itself, shown as its pill:
//
//   Full Access  the role may open the tool; what they may do in it is still
//                the role's (User & Role Access) — an engineer with Full
//                Access to HAPExt still may not configure it.
//   No Access    the role may not open it at all.
//   Status       Active, or Inactive: switched off for everyone here.
//
// Two levels only, by decision (OPEN-DECISIONS #22). Each change is saved as
// it is made; a refusal — Full Access for a role that allows nothing in the
// tool — is shown and the cell stays as it was.

import { useEffect, useMemo, useState } from 'react'
import { admin } from '../api'
import { accessBadge, roleOrder, toolLabel, toolStatus } from './present.js'

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

  const modules = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    if (!needle) return data.modules
    return data.modules.filter((m) =>
      toolLabel(m).toLowerCase().includes(needle)
      || m.module_key.toLowerCase().includes(needle))
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

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data || !roles) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

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
            {modules.map((m) => {
              const tool = `${m.application_key}:${m.module_key}`
              const off = m.status === 'inactive'
              return (
                <tr key={tool} className={off ? 'maec-row-off' : undefined}>
                  <td>
                    {toolLabel(m)}
                    {off && <div className="maec-sub">Switched off for everyone</div>}
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
            {modules.length === 0 && (
              <tr><td colSpan={columns.length + 2}>
                <p className="maec-lede">No tool matches “{query}”.</p>
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="maec-faint" style={{ fontSize: 11, marginTop: 14 }}>
        Full Access lets a role open the tool; what they can do inside it is set
        by their role on User &amp; Role Access. No Access and Inactive take the
        tool away.
      </p>
    </div>
  )
}
