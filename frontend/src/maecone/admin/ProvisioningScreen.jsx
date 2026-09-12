// Screen 003 — Global Provisioning.
//
// Rules can be authored now; nothing acts on them yet, and the screen says
// so. The three cards are whatever the server reports — it derives them from
// what is actually configured, so "Not connected" is a fact about the
// deployment rather than a string somebody typed and forgot to update.

import { useCallback, useEffect, useState } from 'react'
import { admin } from '../api'

const BLANK = {
  directory_group: '', role_id: '', default_modules: [],
  approval_type: 'manual', status: 'active',
}

export default function ProvisioningScreen() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState('')
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState(BLANK)

  const load = useCallback(
    () => admin.provisioning().then(setData).catch((e) => setError(e.message)), [])
  useEffect(() => { load() }, [load])

  const run = async (label, work) => {
    setBusy(label); setError(''); setNote('')
    try {
      await work()
      await load()
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
    const ok = await run('new', () => admin.createProvisioning(form))
    if (ok) { setForm(BLANK); setAdding(false); setNote('Rule saved.') }
  }

  const toggleModule = (key) => setForm((f) => ({
    ...f,
    default_modules: f.default_modules.includes(key)
      ? f.default_modules.filter((m) => m !== key)
      : [...f.default_modules, key],
  }))

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  return (
    <div className="maec-stack">
      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h1 className="maec-h1">Global Provisioning</h1>
            <p className="maec-lede">
              Manage centralized identity sources, default roles, access
              lifecycle, and provisioning rules.
            </p>
          </div>
        </div>

        <div className="maec-cards">
          {data.cards.map((card) => (
            <div key={card.key} className="maec-bigcard">
              <span className="maec-stat-label">{card.label}</span>
              <span className={`maec-chip ${card.state}`}>{card.value}</span>
              <p className="maec-lede">{card.detail}</p>
              {card.action && (
                <button type="button" className="maec-btn secondary"
                        onClick={() => setNote(
                          'Identity provider federation is not built yet. '
                          + `It switches on when ${card.derived_from} are set.`)}>
                  {card.action}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h2 className="maec-h2">Role &amp; Group Provisioning Map</h2>
            <p className="maec-lede">
              What arriving in a directory group confers. Authoring a rule is
              checked as though you were granting the role by hand — you
              cannot write one conferring more than you hold.
            </p>
          </div>
          <button type="button" className="maec-btn primary"
                  onClick={() => setAdding((a) => !a)}>
            + Add Mapping
          </button>
        </div>

        {error && <p className="maec-error">{error}</p>}
        {note && <p className="maec-note">{note}</p>}

        {adding && (
          <form className="maec-form" onSubmit={create}>
            <div className="maec-form-grid">
              <label>Directory group
                <input className="maec-search" required
                       placeholder="MAEC-Engineering"
                       value={form.directory_group}
                       onChange={(e) => setForm({ ...form, directory_group: e.target.value })} />
              </label>
              <label>Persona / role
                <select className="maec-select" required value={form.role_id}
                        onChange={(e) => setForm({ ...form, role_id: e.target.value })}>
                  <option value="">Choose…</option>
                  {data.roles.map((r) => (
                    <option key={r.id} value={r.id}>{r.name}</option>
                  ))}
                </select>
              </label>
              <label>Approval
                <select className="maec-select" value={form.approval_type}
                        onChange={(e) => setForm({ ...form, approval_type: e.target.value })}>
                  {data.approvals.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
              </label>
              <label>Status
                <select className="maec-select" value={form.status}
                        onChange={(e) => setForm({ ...form, status: e.target.value })}>
                  {data.statuses.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
            </div>

            <h3 className="maec-h3">Default modules</h3>
            {data.applications.length === 0 ? (
              <p className="maec-lede">
                This organisation does not subscribe to any application yet.
              </p>
            ) : (
              <ul className="maec-chips">
                {data.applications.map((app) => (
                  <li key={app.key}>
                    <label className="maec-switch-wrap">
                      <input type="checkbox" className="maec-toggle"
                             checked={form.default_modules.includes(app.key)}
                             onChange={() => toggleModule(app.key)} />
                      <span>{app.name}</span>
                    </label>
                  </li>
                ))}
              </ul>
            )}

            <div className="maec-form-actions">
              <button type="submit" className="maec-btn primary" disabled={busy === 'new'}>
                {busy === 'new' ? 'Saving…' : 'Save mapping'}
              </button>
              <button type="button" className="maec-btn secondary"
                      onClick={() => { setAdding(false); setForm(BLANK) }}>
                Cancel
              </button>
            </div>
          </form>
        )}

        <div className="maec-table-wrap">
          <table className="maec-table">
            <thead>
              <tr>
                <th>Directory group</th><th>Persona / role</th>
                <th>Default modules</th><th>Approval</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {data.rules.map((rule) => (
                <tr key={rule.id}>
                  <td><strong>{rule.directory_group}</strong></td>
                  <td>{rule.role_name}</td>
                  <td>
                    {rule.module_names.length
                      ? rule.module_names.join(', ')
                      : <span className="maec-faint">none</span>}
                  </td>
                  <td>
                    <span className={`maec-chip ${
                      rule.approval_type === 'automatic' ? 'scoped' : 'inactive'}`}>
                      {rule.approval_type}
                    </span>
                  </td>
                  <td>
                    <label className="maec-switch-wrap">
                      <input type="checkbox" className="maec-toggle"
                             checked={rule.status === 'active'}
                             disabled={busy === rule.id}
                             onChange={() => run(rule.id, () => admin.patchProvisioning(
                               rule.id,
                               { status: rule.status === 'active' ? 'disabled' : 'active' }))} />
                      <span className={`maec-chip ${
                        rule.status === 'active' ? 'granted' : 'inactive'}`}>
                        {rule.status}
                      </span>
                    </label>
                  </td>
                </tr>
              ))}
              {data.rules.length === 0 && (
                <tr><td colSpan={5}>
                  <p className="maec-lede">
                    No mappings yet. Rules authored here take effect when an
                    identity provider is connected — until then people are
                    created in Users &amp; Access, or imported.
                  </p>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
