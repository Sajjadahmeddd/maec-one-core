// User & Role Access — the roles, and what each may do.
//
// Laid out as the design (frontend/Global admin GUI/User & Role access.png):
// a search, "+ Add Custom Role", and the roles as one list, from the everyday
// role up to Global Admin and then the organisation's own. What each role may
// do with each tool is on Tool-Level Settings; here a role opens to its
// permission editor. It does not edit people — roles are handed out on
// Users. Keeping the two apart is what stops this becoming a per-user grid
// nobody can hold in their head.
//
// Everything is drawn from the server: the roles, the modules and the actions
// all come from GET /api/admin/roles, which reads the seeded permissions
// registry.

import { Fragment, useEffect, useMemo, useState } from 'react'
import { admin } from '../api'
import { roleOrder, toolLabel } from './present.js'

const TITLE = { view: 'View', convert: 'Convert', export: 'Export', configure: 'Configure', use: 'Use' }

/** "<app>:<feature>" -> "<App> – <name>", from the names the apps reported. */
function moduleLabel(qualified, labels) {
  return labels[qualified] || qualified
}

function RoleDetail({ role, data, apps, busy, onToggle, onDelete }) {
  return (
    <div className="maec-detail">
      <h3 className="maec-h3" style={{ marginTop: 0 }}>{role.name}</h3>
      <p className="maec-lede">{role.description || 'No description.'}</p>
      <ul className="maec-chips" style={{ margin: '10px 0 12px' }}>
        <li>
          {role.is_system
            ? <span className="maec-chip inactive">System role</span>
            : <span className="maec-chip scoped">Custom role</span>}
          <span className="maec-chip neutral">
            {role.user_count} {role.user_count === 1 ? 'person' : 'people'}
          </span>
        </li>
      </ul>
      <p className="maec-lede" style={{ marginBottom: 12 }}>
        {role.is_system
          ? 'System roles are shared by every organisation and are read-only. '
            + 'Use + Add Custom Role to copy it, then edit the copy.'
          : 'Each switch writes one allow or deny. You cannot grant a permission you do not hold yourself.'}
      </p>
      <div className="maec-table-wrap">
        <table className="maec-table">
          <thead>
            <tr>
              <th>Tool / Module</th>
              {data.actions.map((a) => <th key={a}>{TITLE[a] || a}</th>)}
            </tr>
          </thead>
          <tbody>
            {data.modules.map((m) => (
              <tr key={m}>
                <td>{moduleLabel(m, apps)}</td>
                {data.actions.map((a) => {
                  // a module only has some actions: no switch for the rest
                  if (!(data.module_actions?.[m] || []).includes(a)) {
                    return <td key={a}><span className="maec-faint">—</span></td>
                  }
                  const key = `${m}:${a}`
                  const effect = role.permissions[key]
                  return (
                    <td key={a}>
                      <label className="maec-switch-wrap">
                        <input
                          type="checkbox"
                          className="maec-toggle"
                          aria-label={`${role.name}: ${moduleLabel(m, apps)} ${TITLE[a] || a}`}
                          checked={effect === 'allow'}
                          disabled={role.is_system || busy === role.id}
                          onChange={(e) => onToggle(role, key, e.target.checked ? 'allow' : 'deny')}
                        />
                        <span className={`maec-chip ${
                          effect === 'allow' ? 'granted' : effect === 'deny' ? 'denied' : 'inactive'}`}>
                          {effect === 'allow' ? 'Allow' : effect === 'deny' ? 'Deny' : 'Not set'}
                        </span>
                      </label>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!role.is_system && (
        <div className="maec-form-actions" style={{ marginTop: 14 }}>
          <button type="button" className="maec-btn secondary"
                  disabled={busy === role.id} onClick={() => onDelete(role)}>
            Delete role
          </button>
        </div>
      )}
    </div>
  )
}

export default function RolesScreen() {
  const [data, setData] = useState(null)
  const [apps, setApps] = useState({})
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(null)      // role id whose detail is open
  const [adding, setAdding] = useState(false)
  const [newName, setNewName] = useState('')
  const [cloneFrom, setCloneFrom] = useState('')

  const load = () => admin.roles().then(setData).catch((e) => setError(e.message))
  useEffect(() => {
    load()
    // each feature's label, from the names its app reported
    admin.toolRules()
      .then((t) => setApps(Object.fromEntries(
        t.modules.map((m) => [`${m.application_key}:${m.module_key}`, toolLabel(m)]))))
      .catch(() => {})
  }, [])

  const roles = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    const all = roleOrder(data.roles)
    if (!needle) return all
    return all.filter((r) =>
      r.name.toLowerCase().includes(needle)
      || (r.description || '').toLowerCase().includes(needle)
      || Object.keys(r.permissions).some((k) => k.includes(needle)))
  }, [data, query])

  const run = async (id, work) => {
    setBusy(id)
    setError('')
    try {
      await work()
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const toggle = (role, key, next) =>
    run(role.id, () => admin.patchRole(role.id, { changes: [{ key, effect: next }] }))

  const remove = (role) => run(role.id, async () => {
    await admin.deleteRole(role.id)
    setOpen(null)
  })

  const create = (event) => {
    event.preventDefault()
    if (!newName.trim()) return
    run('new', async () => {
      await admin.createRole(newName.trim(), cloneFrom)
      setNewName(''); setCloneFrom(''); setAdding(false)
    })
  }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  return (
    <div className="maec-card">
      <h1 className="maec-h1">Granular RBAC &amp; Tab-Level Access Control</h1>
      <p className="maec-lede">
        Configure precise user permissions, tab visibility, and action rights across modules.
      </p>

      <div className="maec-toolbar split" style={{ marginTop: 22 }}>
        <input
          className="maec-search"
          placeholder="Search roles or permissions..."
          aria-label="Search roles or permissions"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button type="button" className="maec-btn primary" onClick={() => setAdding((a) => !a)}>
          + Add Custom Role
        </button>
      </div>

      {adding && (
        <form className="maec-inline-form" onSubmit={create}>
          <input
            className="maec-search" placeholder="New role name, e.g. IT Admin"
            aria-label="New role name"
            value={newName} onChange={(e) => setNewName(e.target.value)}
          />
          <select className="maec-select" value={cloneFrom} aria-label="Start from"
                  onChange={(e) => setCloneFrom(e.target.value)}>
            <option value="">Start empty</option>
            {roleOrder(data.roles).map((r) => (
              <option key={r.id} value={r.id}>Copy from {r.name}</option>
            ))}
          </select>
          <button type="submit" className="maec-btn primary" disabled={busy === 'new' || !newName.trim()}>
            {busy === 'new' ? 'Creating…' : 'Create'}
          </button>
          <button type="button" className="maec-btn secondary" onClick={() => setAdding(false)}>
            Cancel
          </button>
        </form>
      )}

      {error && <p className="maec-error">{error}</p>}

      <div className="maec-table-wrap">
        <table className="maec-table">
          <thead>
            <tr><th>Role &amp; Persona</th></tr>
          </thead>
          <tbody>
            {roles.map((role) => (
              <Fragment key={role.id}>
                <tr className={`maec-opens${open === role.id ? ' maec-open' : ''}`}
                    onClick={() => setOpen(open === role.id ? null : role.id)}>
                  <td>
                    <button type="button" className="maec-linkish"
                            aria-expanded={open === role.id}
                            onClick={(e) => { e.stopPropagation(); setOpen(open === role.id ? null : role.id) }}>
                      {role.name}
                    </button>
                  </td>
                </tr>
                {open === role.id && (
                  <tr>
                    <td className="maec-subrow">
                      <RoleDetail role={role} data={data} apps={apps} busy={busy}
                                  onToggle={toggle} onDelete={remove} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {roles.length === 0 && (
              <tr><td><p className="maec-lede">No role matches “{query}”.</p></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
