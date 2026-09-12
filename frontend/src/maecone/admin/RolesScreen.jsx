// Screen 001 — User & Role Access.
//
// A permission-scheme editor: which role may do what. It does not edit
// people — roles are handed out in User Management. Keeping the two apart is
// what stops this becoming a per-user grid nobody can hold in their head.
//
// Everything here is drawn from the server: the modules, the actions and the
// roles all come from GET /api/admin/roles, which reads the seeded
// permissions registry. Add a module to the registry and this screen grows a
// column without being edited.

import { useEffect, useMemo, useState } from 'react'
import { admin } from '../api'

const BADGE = {
  full: { label: 'Full Access', tone: 'granted' },
  partial: { label: 'Partial', tone: 'scoped' },
  view: { label: 'View Only', tone: 'scoped' },
  none: { label: 'No Access', tone: 'inactive' },
}

const TITLE = { view: 'View', convert: 'Convert', export: 'Export', configure: 'Configure' }

export default function RolesScreen() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(null)      // role id whose detail is expanded
  const [adding, setAdding] = useState(false)
  const [newName, setNewName] = useState('')
  const [cloneFrom, setCloneFrom] = useState('')

  const load = () => admin.roles().then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const roles = useMemo(() => {
    if (!data) return []
    const needle = query.trim().toLowerCase()
    if (!needle) return data.roles
    return data.roles.filter((r) =>
      r.name.toLowerCase().includes(needle)
      || (r.description || '').toLowerCase().includes(needle)
      || Object.keys(r.permissions).some((k) => k.includes(needle)))
  }, [data, query])

  const toggle = async (role, key, next) => {
    setBusy(role.id)
    setError('')
    try {
      await admin.patchRole(role.id, { changes: [{ key, effect: next }] })
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const create = async (event) => {
    event.preventDefault()
    if (!newName.trim()) return
    setBusy('new')
    setError('')
    try {
      await admin.createRole(newName.trim(), cloneFrom)
      setNewName(''); setCloneFrom(''); setAdding(false)
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const remove = async (role) => {
    setBusy(role.id)
    setError('')
    try {
      await admin.deleteRole(role.id)
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
            <h1 className="maec-h1">Granular RBAC &amp; Tab-Level Access Control</h1>
            <p className="maec-lede">
              Configure precise user permissions, tab visibility, and action
              rights across modules.
            </p>
          </div>
          <button type="button" className="maec-btn primary"
                  onClick={() => setAdding((a) => !a)}>
            + Add Custom Role
          </button>
        </div>

        <div className="maec-toolbar">
          <input
            className="maec-search"
            placeholder="Search roles and permissions…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        {adding && (
          <form className="maec-inline-form" onSubmit={create}>
            <input
              className="maec-search" placeholder="New role name"
              value={newName} onChange={(e) => setNewName(e.target.value)}
            />
            <select className="maec-select" value={cloneFrom}
                    onChange={(e) => setCloneFrom(e.target.value)}>
              <option value="">Start empty</option>
              {data.roles.map((r) => (
                <option key={r.id} value={r.id}>Copy from {r.name}</option>
              ))}
            </select>
            <button type="submit" className="maec-btn primary" disabled={busy === 'new'}>
              {busy === 'new' ? 'Creating…' : 'Create'}
            </button>
            <button type="button" className="maec-btn secondary"
                    onClick={() => setAdding(false)}>Cancel</button>
          </form>
        )}

        {error && <p className="maec-error">{error}</p>}

        <div className="maec-table-wrap">
          <table className="maec-table">
            <thead>
              <tr>
                <th>Role &amp; Persona</th>
                {data.modules.map((m) => <th key={m}>{m}</th>)}
                <th>Users</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {roles.map((role) => {
                const badge = (m) => BADGE[role.summary[m]] || BADGE.none
                return (
                  <tr key={role.id}>
                    <td>
                      <button type="button" className="maec-linkish"
                              onClick={() => setOpen(open === role.id ? null : role.id)}>
                        <strong>{role.name}</strong>
                      </button>
                      <div className="maec-sub">{role.description}</div>
                      {role.is_system
                        ? <span className="maec-chip inactive">System role</span>
                        : <span className="maec-chip scoped">Custom</span>}
                    </td>
                    {data.modules.map((m) => (
                      <td key={m}>
                        <span className={`maec-chip ${badge(m).tone}`}>{badge(m).label}</span>
                      </td>
                    ))}
                    <td>{role.user_count}</td>
                    <td>
                      {!role.is_system && (
                        <button type="button" className="maec-btn secondary"
                                disabled={busy === role.id}
                                onClick={() => remove(role)}>Delete</button>
                      )}
                    </td>
                  </tr>
                )
              })}
              {roles.length === 0 && (
                <tr><td colSpan={data.modules.length + 3}>
                  <p className="maec-lede">No role matches “{query}”.</p>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {open && (() => {
        const role = data.roles.find((r) => r.id === open)
        if (!role) return null
        return (
          <div className="maec-card">
            <h2 className="maec-h2">{role.name} — permissions</h2>
            <p className="maec-lede">
              {role.is_system
                ? 'System roles are shared by every organisation and are read-only here. Clone it to make an editable copy.'
                : 'Each switch writes one allow or deny row. You cannot grant a permission you do not hold yourself.'}
            </p>
            <div className="maec-table-wrap">
              <table className="maec-table">
                <thead>
                  <tr>
                    <th>Module</th>
                    {data.actions.map((a) => <th key={a}>{TITLE[a] || a}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {data.modules.map((m) => (
                    <tr key={m}>
                      <td><strong>{m}</strong></td>
                      {data.actions.map((a) => {
                        const key = `engineering:${m}:${a}`
                        const effect = role.permissions[key]
                        return (
                          <td key={a}>
                            <label className="maec-switch-wrap">
                              <input
                                type="checkbox"
                                className="maec-toggle"
                                checked={effect === 'allow'}
                                disabled={role.is_system || busy === role.id}
                                onChange={(e) =>
                                  toggle(role, key, e.target.checked ? 'allow' : 'deny')}
                              />
                              <span className={`maec-chip ${
                                effect === 'allow' ? 'granted'
                                  : effect === 'deny' ? 'denied' : 'inactive'}`}>
                                {effect === 'allow' ? 'Allow'
                                  : effect === 'deny' ? 'Deny' : 'Not set'}
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
          </div>
        )
      })()}
    </div>
  )
}
