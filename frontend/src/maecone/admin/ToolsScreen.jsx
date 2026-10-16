// Tool-Level Settings — what each role can do with each tool, here.
//
// Laid out as the design (frontend/Global admin GUI/Tool level settings.png):
// one row per tool, one column per role, and in each cell the access that
// role actually has — what the role grants (User & Role Access), narrowed by
// this organisation's tool rule if there is one. Status is the application's:
// Active once it is live, In-Active until then.
//
// A rule is set with "+ Add Tool Rule", or by clicking a cell, which opens the
// same form for that tool and role. The form says what the two restrictive
// levels mean, because they are not the same and the difference is invisible
// otherwise: Hidden removes a tool from the navigation and nothing more, while
// No Access makes the API refuse. An administrator picking between them is
// choosing between tidiness and a security boundary, and should be told so.

import { useEffect, useMemo, useState } from 'react'
import { admin } from '../api'
import { effectiveAccess, roleOrder, toolLabel, toolStatus } from './present.js'

const NO_RULE = ''

function RuleForm({ data, columns, draft, setDraft, busy, onSave, onCancel }) {
  const level = data.levels.find((l) => l.key === draft.level)
  const ready = draft.tool && draft.role
  return (
    <form className="maec-form" onSubmit={(e) => { e.preventDefault(); if (ready) onSave() }}>
      <div className="maec-form-grid">
        <label>
          Tool / Module
          <select className="maec-select" value={draft.tool}
                  onChange={(e) => setDraft({ ...draft, tool: e.target.value })}>
            <option value="">Choose a tool…</option>
            {data.modules.map((m) => {
              const key = `${m.application_key}:${m.module_key}`
              return <option key={key} value={key}>{toolLabel(m)}</option>
            })}
          </select>
        </label>
        <label>
          Role
          <select className="maec-select" value={draft.role}
                  onChange={(e) => setDraft({ ...draft, role: e.target.value })}>
            <option value="">Choose a role…</option>
            {columns.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </label>
        <label>
          Access
          <select className="maec-select" value={draft.level}
                  onChange={(e) => setDraft({ ...draft, level: e.target.value })}>
            <option value={NO_RULE}>As the role grants (no rule)</option>
            {data.levels.map((l) => <option key={l.key} value={l.key}>{l.label}</option>)}
          </select>
        </label>
      </div>
      <p className="maec-lede" style={{ marginBottom: 12 }}>
        {level?.note
          || (draft.level
            ? 'Narrows the role to this level for this tool, in this organisation.'
            : 'No rule: the role decides. ')}
        {' '}A rule can only take access away — it never grants what the role does not.
      </p>
      <div className="maec-form-actions">
        <button type="submit" className="maec-btn primary" disabled={!ready || busy}>
          {busy ? 'Saving…' : 'Save rule'}
        </button>
        <button type="button" className="maec-btn secondary" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  )
}

export default function ToolsScreen() {
  const [data, setData] = useState(null)
  const [roles, setRoles] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState('')
  const [query, setQuery] = useState('')
  const [draft, setDraft] = useState(null)      // the open rule form, or null

  const load = () => Promise.all([admin.toolRules(), admin.roles()])
    .then(([tools, all]) => { setData(tools); setRoles(all) })
    .catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  // the role columns, in the same order as User & Role Access
  const columns = useMemo(() => (roles ? roleOrder(roles.roles) : []), [roles])
  const summaryOf = useMemo(
    () => Object.fromEntries((roles?.roles || []).map((r) => [r.id, r.summary])), [roles])

  const modules = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    if (!needle) return data.modules
    return data.modules.filter((m) =>
      toolLabel(m).toLowerCase().includes(needle)
      || m.module_key.toLowerCase().includes(needle)
      || columns.some((r) => r.name.toLowerCase().includes(needle)))
  }, [data, query, columns])

  const openRule = (module, role) => {
    const tool = module ? `${module.application_key}:${module.module_key}` : ''
    const level = module && role ? (data.rules[tool]?.[role.id]?.access_level || NO_RULE) : NO_RULE
    setDraft({ tool, role: role?.id || '', level })
    setNote('')
  }

  const save = async () => {
    const [application_key, module_key] = draft.tool.split(':')
    setBusy(true); setError(''); setNote('')
    try {
      const result = await admin.putToolRules([{
        application_key, module_key, role_id: draft.role,
        access_level: draft.level || null, status: 'active',
      }])
      setNote(result.users_affected === 1
        ? 'Saved. 1 person re-resolves on their next request.'
        : `Saved. ${result.users_affected} people re-resolve on their next request.`)
      setDraft(null)
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data || !roles) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  return (
    <div className="maec-card">
      <h1 className="maec-h1">Tool-Level Settings</h1>
      <p className="maec-lede">
        Configure tool-specific permissions, feature visibility, and action controls by role.
      </p>

      <div className="maec-toolbar split" style={{ marginTop: 22 }}>
        <input
          className="maec-search"
          placeholder="Search tools or permissions..."
          aria-label="Search tools or permissions"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button type="button" className="maec-btn primary"
                onClick={() => (draft ? setDraft(null) : openRule(null, null))}>
          + Add Tool Rule
        </button>
      </div>

      {draft && (
        <RuleForm data={data} columns={columns} draft={draft} setDraft={setDraft}
                  busy={busy} onSave={save} onCancel={() => setDraft(null)} />
      )}

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
              const status = toolStatus(m.application_status)
              return (
                <tr key={tool}>
                  <td>{toolLabel(m)}</td>
                  {columns.map((role) => {
                    const rule = data.rules[tool]?.[role.id]
                    const access = effectiveAccess(summaryOf[role.id]?.[tool], rule?.access_level)
                    const why = rule
                      ? `Tool rule: ${data.levels.find((l) => l.key === rule.access_level)?.label || rule.access_level}`
                      : 'As the role grants. Click to set a rule.'
                    return (
                      <td key={role.id}>
                        <button type="button" className="maec-chip-button" title={why}
                                aria-label={`${toolLabel(m)}, ${role.name}: ${access.label}. ${why}`}
                                onClick={() => openRule(m, role)}>
                          <span className={`maec-chip ${access.tone}${access.ruled ? ' ruled' : ''}`}>
                            {access.label}
                          </span>
                        </button>
                      </td>
                    )
                  })}
                  <td><span className={`maec-chip ${status.tone}`}>{status.label}</span></td>
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
    </div>
  )
}
