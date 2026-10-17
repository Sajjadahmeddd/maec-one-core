// Applications — a Global Admin adds and edits the applications of MAEC One.
//
// The key is permanent: shown, never edited, never reused. Name, status and
// address can change. Nothing is deleted: an application with history is set
// inactive. Whether its gate secret is configured on the server is shown as
// yes or no — never the secret — and, when it is missing, the one step left.

import { useEffect, useState } from 'react'
import { admin } from '../api'
import { ago } from './present.js'

const STATUS = {
  live: { label: 'Live', tone: 'granted' },
  coming_soon: { label: 'Coming soon', tone: 'neutral' },
  inactive: { label: 'Inactive', tone: 'rose' },
}

const KEY = /^[a-z][a-z0-9_]{0,39}$/

const blank = { key: '', name: '', status: 'coming_soon', base_url: '' }

export default function ApplicationsScreen() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState('')
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState(blank)
  const [editing, setEditing] = useState(null)       // { key, name, status, base_url }

  const load = () => admin.applications().then(setData).catch((e) => setError(e.message))
  useEffect(() => { load() }, [])

  const run = async (key, work, done) => {
    setBusy(key); setError(''); setNote('')
    try {
      await work()
      setNote(done)
      await load()
      return true
    } catch (e) {
      setError(e.message)
      return false
    } finally {
      setBusy('')
    }
  }

  const add = async (event) => {
    event.preventDefault()
    const ok = await run('add', () => admin.createApplication({
      key: draft.key.trim(), name: draft.name.trim(), status: draft.status,
      base_url: draft.base_url.trim() || null,
    }), `${draft.name.trim()} added. Its key, ${draft.key.trim()}, is permanent.`)
    if (ok) { setDraft(blank); setAdding(false) }
  }

  const save = async (event) => {
    event.preventDefault()
    const ok = await run(`edit:${editing.key}`, () => admin.patchApplication(editing.key, {
      name: editing.name.trim(), status: editing.status, base_url: editing.base_url.trim() || null,
    }), `${editing.name.trim()} saved.`)
    if (ok) setEditing(null)
  }

  if (error && !data) return <div className="maec-card"><p className="maec-error">{error}</p></div>
  if (!data) return <div className="maec-card"><p className="maec-lede">Loading…</p></div>

  const keyOk = KEY.test(draft.key.trim())

  return (
    <div className="maec-card">
      <h1 className="maec-h1">Applications</h1>
      <p className="maec-lede">
        Add and edit the applications people sign in to through MAEC One. Each
        app reports its own features once it is running.
      </p>

      <div className="maec-toolbar split" style={{ marginTop: 22 }}>
        <span />
        <button type="button" className="maec-btn primary" onClick={() => setAdding((a) => !a)}>
          + Add Application
        </button>
      </div>

      {adding && (
        <form className="maec-form" onSubmit={add}>
          <div className="maec-form-grid">
            <label>
              Key (permanent)
              <input className="maec-search" value={draft.key} placeholder="e.g. itdesk"
                     onChange={(e) => setDraft({ ...draft, key: e.target.value.toLowerCase() })} />
            </label>
            <label>
              Name
              <input className="maec-search" value={draft.name} placeholder="e.g. IT Ticketing"
                     onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
            </label>
            <label>
              Status
              <select className="maec-select" value={draft.status}
                      onChange={(e) => setDraft({ ...draft, status: e.target.value })}>
                {data.statuses.map((s) => <option key={s} value={s}>{STATUS[s]?.label || s}</option>)}
              </select>
            </label>
            <label>
              Address
              <input className="maec-search" value={draft.base_url} placeholder="https://app.mirageaec.com"
                     onChange={(e) => setDraft({ ...draft, base_url: e.target.value })} />
            </label>
          </div>
          <p className="maec-lede" style={{ marginBottom: 12 }}>
            The key is the app&apos;s identity everywhere — its gate header, its
            permission keys, roles scoped to it. Lowercase letters, digits and
            underscores, starting with a letter. It can never be changed or
            used again.
          </p>
          <div className="maec-form-actions">
            <button type="submit" className="maec-btn primary"
                    disabled={!keyOk || !draft.name.trim() || busy === 'add'}>
              {busy === 'add' ? 'Adding…' : 'Add application'}
            </button>
            <button type="button" className="maec-btn secondary" onClick={() => setAdding(false)}>Cancel</button>
          </div>
        </form>
      )}

      {error && <p className="maec-error">{error}</p>}
      {note && <p className="maec-note">{note}</p>}

      <div className="maec-table-wrap">
        <table className="maec-table">
          <thead>
            <tr>
              <th>Key</th><th>Name</th><th>Status</th><th>Address</th>
              <th>Gate secret</th><th>Last reported</th><th />
            </tr>
          </thead>
          <tbody>
            {data.applications.map((a) => {
              const status = STATUS[a.status] || { label: a.status, tone: 'inactive' }
              const open = editing?.key === a.key
              return (
                <tr key={a.key}>
                  <td className="maec-mono">{a.key}</td>
                  {open ? (
                    <td colSpan={3}>
                      <form className="maec-inline-form" style={{ margin: '6px 0' }} onSubmit={save}>
                        <input className="maec-search" aria-label="Name" value={editing.name}
                               onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
                        <select className="maec-select" aria-label="Status" value={editing.status}
                                onChange={(e) => setEditing({ ...editing, status: e.target.value })}>
                          {data.statuses.map((s) => <option key={s} value={s}>{STATUS[s]?.label || s}</option>)}
                        </select>
                        <input className="maec-search" aria-label="Address" value={editing.base_url}
                               placeholder="https://…"
                               onChange={(e) => setEditing({ ...editing, base_url: e.target.value })} />
                        <button type="submit" className="maec-btn primary"
                                disabled={!editing.name.trim() || busy === `edit:${a.key}`}>Save</button>
                        <button type="button" className="maec-btn secondary"
                                onClick={() => setEditing(null)}>Cancel</button>
                      </form>
                    </td>
                  ) : (
                    <>
                      <td>{a.name}</td>
                      <td><span className={`maec-chip ${status.tone}`}>{status.label}</span></td>
                      <td>{a.base_url || <span className="maec-faint">—</span>}</td>
                    </>
                  )}
                  <td>
                    {a.gate_secret_configured
                      ? <span className="maec-chip granted">Yes</span>
                      : (
                        <>
                          <span className="maec-chip warn">No</span>
                          <div className="maec-sub" style={{ maxWidth: 340 }}>
                            Add {a.key}=&lt;secret&gt; to GATE_SECRETS in Core&apos;s settings
                            file on the server and restart Core. Until then this app cannot
                            sign anybody in.
                          </div>
                        </>
                      )}
                  </td>
                  <td className="maec-faint">
                    {a.features_reported_at ? ago(a.features_reported_at) : 'never'}
                  </td>
                  <td>
                    {!open && (
                      <button type="button" className="maec-linkish"
                              onClick={() => setEditing({ key: a.key, name: a.name, status: a.status,
                                                          base_url: a.base_url || '' })}>
                        Edit
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <p className="maec-faint" style={{ fontSize: 11, marginTop: 14 }}>
        Applications are never deleted. Set one Inactive to retire it: the
        launcher leaves it out and its gate refuses everyone, while its history stays.
      </p>
    </div>
  )
}
