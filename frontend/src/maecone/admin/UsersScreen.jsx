// User Management — create people, give them roles and seats.
//
// Everything the form offers comes from the server: the roles that exist, the
// applications this organisation actually subscribes to, the seats left on
// each, and the password rules. Nothing is a constant here, because all of it
// is a database read and a stale copy in the browser would offer choices the
// API then refuses.

import { useCallback, useEffect, useMemo, useState } from 'react'
import { admin } from '../api'

const STATUS_TONE = { active: 'granted', invited: 'scoped', suspended: 'denied' }
const PAGE_SIZE = 25

function when(iso) {
  if (!iso) return 'never'
  const then = new Date(iso)
  const days = Math.floor((Date.now() - then.getTime()) / 86400000)
  if (days === 0) return 'today'
  if (days === 1) return 'yesterday'
  if (days < 30) return `${days} days ago`
  return then.toLocaleDateString()
}

export default function UsersScreen() {
  const [data, setData] = useState(null)
  const [options, setOptions] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState('')
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const [adding, setAdding] = useState(false)
  const [open, setOpen] = useState(null)
  const [form, setForm] = useState({
    email: '', display_name: '', department: '', password: '',
  })

  const load = useCallback(() => (
    admin.users({ q: query, status, page, page_size: PAGE_SIZE })
      .then(setData)
      .catch((e) => setError(e.message))
  ), [query, status, page])

  useEffect(() => { load() }, [load])
  useEffect(() => { admin.userOptions().then(setOptions).catch(() => {}) }, [])

  const run = async (label, work) => {
    setBusy(label)
    setError('')
    setNote('')
    try {
      await work()
      await load()
      const fresh = await admin.userOptions().catch(() => null)
      if (fresh) setOptions(fresh)
      return true
    } catch (e) {
      setError(e.message)
      return false
    } finally {
      setBusy('')
    }
  }

  const create = async (event) => {
    event.preventDefault()
    const ok = await run('new', () => admin.createUser(form))
    if (ok) {
      setNote(`${form.email} created. They must change this password at first sign-in.`)
      setForm({ email: '', display_name: '', department: '', password: '' })
      setAdding(false)
    }
  }

  const rules = options?.password_rules
  const seatsFor = (key) => options?.applications?.find((a) => a.key === key)

  const detail = useMemo(
    () => (data?.users || []).find((u) => u.id === open) || null, [data, open])

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  return (
    <div className="maec-stack">
      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h1 className="maec-h1">Users &amp; Access</h1>
            <p className="maec-lede">
              Create users, assign roles and application seats, manage account status.
            </p>
          </div>
          <button type="button" className="maec-btn primary"
                  onClick={() => setAdding((a) => !a)}>
            + Add User
          </button>
        </div>

        <div className="maec-toolbar">
          <input
            className="maec-search"
            placeholder="Search name, email or department…"
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(1) }}
          />
          <select className="maec-select" value={status}
                  onChange={(e) => { setStatus(e.target.value); setPage(1) }}>
            <option value="">Any status</option>
            {(options?.statuses || []).map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        {adding && (
          <form className="maec-form" onSubmit={create}>
            <div className="maec-form-grid">
              <label>Name
                <input className="maec-search" required value={form.display_name}
                       onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
              </label>
              <label>Email
                <input className="maec-search" type="email" required value={form.email}
                       onChange={(e) => setForm({ ...form, email: e.target.value })} />
              </label>
              <label>Department
                <input className="maec-search" value={form.department}
                       onChange={(e) => setForm({ ...form, department: e.target.value })} />
              </label>
              <label>Initial password
                <input className="maec-search" type="text" required value={form.password}
                       onChange={(e) => setForm({ ...form, password: e.target.value })} />
              </label>
            </div>
            {rules && (
              <p className="maec-lede">
                At least {rules.min_length} characters, with {rules.needs.join(', ')}.
                They will be required to change it at first sign-in, so it is safe
                to read this one out.
              </p>
            )}
            <div className="maec-form-actions">
              <button type="submit" className="maec-btn primary" disabled={busy === 'new'}>
                {busy === 'new' ? 'Creating…' : 'Create user'}
              </button>
              <button type="button" className="maec-btn secondary"
                      onClick={() => setAdding(false)}>Cancel</button>
            </div>
          </form>
        )}

        {error && <p className="maec-error">{error}</p>}
        {note && <p className="maec-note">{note}</p>}

        <div className="maec-table-wrap">
          <table className="maec-table">
            <thead>
              <tr>
                <th>Name</th><th>Email</th><th>Department</th>
                <th>Roles</th><th>Seats</th><th>Status</th><th>Last active</th>
              </tr>
            </thead>
            <tbody>
              {data.users.map((u) => (
                <tr key={u.id}>
                  <td>
                    <button type="button" className="maec-linkish"
                            onClick={() => setOpen(open === u.id ? null : u.id)}>
                      <strong>{u.display_name}</strong>
                    </button>
                    {u.is_global_admin && (
                      <span className="maec-chip scoped">Global Admin</span>
                    )}
                  </td>
                  <td>{u.email}</td>
                  <td>{u.department || '—'}</td>
                  <td>{u.roles.length ? u.roles.map((r) => r.name).join(', ') : '—'}</td>
                  <td>{u.licenses.length ? u.licenses.map((l) => l.application_name).join(', ') : '—'}</td>
                  <td>
                    <span className={`maec-chip ${STATUS_TONE[u.status] || 'inactive'}`}>
                      {u.status}
                    </span>
                    {u.must_change_password && (
                      <span className="maec-chip warn">Must change password</span>
                    )}
                  </td>
                  <td>{when(u.last_login_at)}</td>
                </tr>
              ))}
              {data.users.length === 0 && (
                <tr><td colSpan={7}><p className="maec-lede">
                  No user matches that search.
                </p></td></tr>
              )}
            </tbody>
          </table>
        </div>

        {data.pages > 1 && (
          <div className="maec-pager">
            <button type="button" className="maec-btn secondary" disabled={page <= 1}
                    onClick={() => setPage((p) => p - 1)}>Previous</button>
            <span className="maec-lede">Page {data.page} of {data.pages} — {data.total} people</span>
            <button type="button" className="maec-btn secondary" disabled={page >= data.pages}
                    onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        )}
      </div>

      {detail && options && (
        <UserDetail
          user={detail} options={options} busy={busy} seatsFor={seatsFor}
          run={run} setNote={setNote}
        />
      )}
    </div>
  )
}


function UserDetail({ user, options, busy, seatsFor, run, setNote }) {
  const [grant, setGrant] = useState({
    role_id: '', scope_type: 'application', scope_id: 'engineering',
  })
  const [newPassword, setNewPassword] = useState('')

  const held = new Set(user.licenses.map((l) => l.application_key))

  return (
    <div className="maec-card">
      <h2 className="maec-h2">{user.display_name}</h2>
      <p className="maec-lede">{user.email}</p>

      <h3 className="maec-h3">Roles</h3>
      <ul className="maec-chips">
        {user.roles.map((r) => (
          <li key={r.grant_id}>
            <span className="maec-chip granted">
              {r.name} · {r.scope_type}{r.scope_id ? ` / ${r.scope_id}` : ''}
            </span>
            <button type="button" className="maec-btn secondary"
                    disabled={busy === `revoke-${r.grant_id}`}
                    onClick={() => run(`revoke-${r.grant_id}`,
                                       () => admin.revokeRole(user.id, r.grant_id))}>
              Revoke
            </button>
          </li>
        ))}
        {user.roles.length === 0 && <li><span className="maec-lede">No roles yet.</span></li>}
      </ul>

      <div className="maec-inline-form">
        <select className="maec-select" value={grant.role_id}
                onChange={(e) => setGrant({ ...grant, role_id: e.target.value })}>
          <option value="">Choose a role…</option>
          {options.roles.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
        <select className="maec-select" value={grant.scope_type}
                onChange={(e) => setGrant({
                  ...grant,
                  scope_type: e.target.value,
                  scope_id: e.target.value === 'platform' ? '' : grant.scope_id,
                })}>
          {options.scope_types.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        {grant.scope_type !== 'platform' && (
          <input className="maec-search" placeholder="scope id (e.g. engineering, P-2291)"
                 value={grant.scope_id}
                 onChange={(e) => setGrant({ ...grant, scope_id: e.target.value })} />
        )}
        <button type="button" className="maec-btn primary" disabled={!grant.role_id}
                onClick={() => run('grant', () => admin.grantRole(user.id, {
                  role_id: grant.role_id,
                  scope_type: grant.scope_type,
                  scope_id: grant.scope_type === 'platform' ? null : grant.scope_id,
                }))}>
          Grant
        </button>
      </div>

      <h3 className="maec-h3">Application seats</h3>
      <ul className="maec-chips">
        {options.applications.map((app) => {
          const has = held.has(app.key)
          const left = app.seats_left
          return (
            <li key={app.key}>
              <span className={`maec-chip ${has ? 'granted' : 'inactive'}`}>
                {app.name}
                {app.seats === null
                  ? ' · uncapped'
                  : ` · ${app.seats_in_use}/${app.seats} used`}
              </span>
              <button
                type="button"
                className={`maec-btn ${has ? 'secondary' : 'primary'}`}
                disabled={busy === `seat-${app.key}` || (!has && left === 0)}
                title={!has && left === 0 ? 'No seat free on this subscription' : ''}
                onClick={() => run(`seat-${app.key}`, () => (
                  has ? admin.removeLicense(user.id, app.key)
                      : admin.assignLicense(user.id, app.key)))}
              >
                {has ? 'Remove seat' : 'Assign seat'}
              </button>
            </li>
          )
        })}
      </ul>

      <h3 className="maec-h3">Account</h3>
      <div className="maec-inline-form">
        <button type="button" className="maec-btn secondary"
                disabled={busy === 'status'}
                onClick={() => run('status', () => admin.patchUser(user.id, {
                  status: user.status === 'suspended' ? 'active' : 'suspended',
                }))}>
          {user.status === 'suspended' ? 'Reactivate' : 'Suspend'}
        </button>
        <input className="maec-search" type="text" placeholder="New password"
               value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        <button type="button" className="maec-btn secondary"
                disabled={!newPassword || busy === 'reset'}
                onClick={async () => {
                  const ok = await run('reset',
                                       () => admin.resetPassword(user.id, newPassword))
                  if (ok) {
                    setNewPassword('')
                    setNote('Password reset. They must change it at next sign-in.')
                  }
                }}>
          Reset password
        </button>
      </div>
    </div>
  )
}
