// Screen 002 — Tool-Level Settings.
//
// A matrix of module × role. Each cell narrows what that role may do with
// that module, for this organisation only.
//
// The screen says out loud what the two restrictive levels actually mean,
// because they are not the same and the difference is invisible otherwise:
// Hidden removes a tool from the navigation and nothing more, while No Access
// makes the API refuse. An administrator picking between them is choosing
// between tidiness and a security boundary, and should be told so.

import { useEffect, useMemo, useState } from 'react'
import { admin } from '../api'

export default function ToolsScreen() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [note, setNote] = useState('')
  const [query, setQuery] = useState('')

  const load = () => admin.toolRules().then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const levels = data?.levels || []
  const byKey = useMemo(
    () => Object.fromEntries(levels.map((l) => [l.key, l])), [levels])

  const modules = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    if (!needle) return data.modules
    return data.modules.filter((m) =>
      m.module_key.toLowerCase().includes(needle)
      || m.application_name.toLowerCase().includes(needle))
  }, [data, query])

  const set = async (module, role, level) => {
    const cell = `${module.module_key}:${role.id}`
    setBusy(cell)
    setError('')
    setNote('')
    try {
      const result = await admin.putToolRules([{
        application_key: module.application_key,
        module_key: module.module_key,
        role_id: role.id,
        access_level: level || null,
        status: 'active',
      }])
      setNote(result.users_affected === 1
        ? '1 person re-resolves on their next request.'
        : `${result.users_affected} people re-resolve on their next request.`)
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  return (
    <div className="maec-stack">
      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h1 className="maec-h1">Tool-Level Settings</h1>
            <p className="maec-lede">
              Configure tool-specific permissions, feature visibility, and
              action controls by role.
            </p>
          </div>
        </div>

        <div className="maec-toolbar">
          <input
            className="maec-search"
            placeholder="Search tools…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        {error && <p className="maec-error">{error}</p>}
        {note && <p className="maec-note">{note}</p>}

        <div className="maec-table-wrap">
          <table className="maec-table">
            <thead>
              <tr>
                <th>Tool</th>
                {data.roles.map((r) => <th key={r.id}>{r.name}</th>)}
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {modules.map((m) => {
                const cellKey = `${m.application_key}:${m.module_key}`
                const row = data.rules[cellKey] || {}
                const controlled = Object.values(row).some((v) => v.status === 'controlled')
                return (
                  <tr key={cellKey}>
                    <td>
                      <strong>{m.module_key}</strong>
                      <div className="maec-sub">{m.application_name}</div>
                    </td>
                    {data.roles.map((role) => {
                      const rule = row[role.id]
                      const level = rule?.access_level || ''
                      const tone = byKey[level]?.tone || 'granted'
                      const cell = `${m.module_key}:${role.id}`
                      return (
                        <td key={role.id}>
                          <select
                            className={`maec-select tone-${tone}`}
                            value={level}
                            disabled={busy === cell}
                            onChange={(e) => set(m, role, e.target.value)}
                          >
                            <option value="">No rule (role applies)</option>
                            {levels.map((l) => (
                              <option key={l.key} value={l.key}>{l.label}</option>
                            ))}
                          </select>
                          {rule?.blocks_api && (
                            <span className="maec-chip denied">API refuses</span>
                          )}
                          {rule?.hides_from_nav && !rule.blocks_api && (
                            <span className="maec-chip inactive">Nav only</span>
                          )}
                        </td>
                      )
                    })}
                    <td>
                      <span className={`maec-chip ${controlled ? 'warn' : 'granted'}`}>
                        {controlled ? 'Controlled' : 'Active'}
                      </span>
                    </td>
                  </tr>
                )
              })}
              {modules.length === 0 && (
                <tr><td colSpan={data.roles.length + 2}>
                  <p className="maec-lede">No tool matches “{query}”.</p>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="maec-card">
        <h2 className="maec-h2">What the levels mean</h2>
        <ul className="maec-legend">
          {levels.map((l) => (
            <li key={l.key}>
              <span className={`maec-chip ${l.tone}`}>{l.label}</span>
              <span>{l.note || 'Narrows the role to this level for this tool.'}</span>
            </li>
          ))}
        </ul>
        <p className="maec-lede">
          A tool rule can only take access away. If a role is not granted
          something, no rule here will turn it on — the change is refused
          rather than saved as a rule that quietly does nothing.
        </p>
      </div>
    </div>
  )
}
