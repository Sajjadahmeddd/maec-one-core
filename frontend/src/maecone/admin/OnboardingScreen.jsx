// User Onboarding & Import.
//
// Laid out as the design (frontend/Global admin GUI/User onboarding & Import.png):
// the notice that this is temporary, the upload beside its guidelines, and
// the import history, where a batch opens to its people and the role each
// holds in each application (GET /api/admin/import/batches/{id}).
//
// Upload, see exactly what would be created, then confirm. The preview comes
// from the same resolution the commit performs, so what this screen promises
// is what the server does — and if the database moves in between, the commit
// refuses rather than quietly doing something else.

import { Fragment, useCallback, useEffect, useState } from 'react'
import { admin } from '../api'
import {
  batchColumns, batchLabel, batchStatus, heldIn, roleTone,
} from './present.js'

function BatchPeople({ id }) {
  const [detail, setDetail] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    admin.importBatch(id).then(setDetail).catch((e) => setError(e.message))
  }, [id])

  if (error) return <p className="maec-error" style={{ margin: '8px 4px' }}>{error}</p>
  if (!detail) return <p className="maec-lede" style={{ padding: '8px 16px' }}>Loading…</p>
  if (detail.people.length === 0) {
    return <p className="maec-lede" style={{ padding: '8px 16px' }}>Nobody in this file could be added.</p>
  }

  const columns = batchColumns(detail.applications, detail.people)
  return (
    <div className="maec-table-wrap">
      {!detail.committed && (
        <p className="maec-faint" style={{ margin: '4px 16px 8px', fontSize: 11 }}>
          Validated but not added yet: these are the roles the preview planned.
        </p>
      )}
      <table className="maec-subtable">
        <thead>
          <tr>
            <th>Name</th>
            {columns.map((a) => <th key={a.key}>{a.name}</th>)}
          </tr>
        </thead>
        <tbody>
          {detail.people.map((p) => (
            <tr key={p.email}>
              <td title={p.email}>
                {p.name}
                {p.status !== 'active' && p.status !== 'planned' && (
                  <span className="maec-faint"> ({p.status})</span>
                )}
              </td>
              {columns.map((a) => {
                const held = heldIn(p, a.key)
                return (
                  <td key={a.key}>
                    {held
                      ? <span className={`maec-chip ${roleTone(held)}`}>{held.name}</span>
                      : <span className="maec-faint">—</span>}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function OnboardingScreen() {
  const [batches, setBatches] = useState([])
  const [preview, setPreview] = useState(null)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [dragging, setDragging] = useState(false)
  const [open, setOpen] = useState(null)        // the batch whose people are shown

  const loadBatches = useCallback(
    () => admin.importBatches().then((b) => setBatches(b.batches)).catch(() => {}),
    [])
  useEffect(() => { loadBatches() }, [loadBatches])

  const choose = (picked) => {
    setFile(picked || null)
    setPreview(null)
    setError('')
    setNote('')
  }

  const validate = async () => {
    if (!file) return
    setBusy('validate'); setError(''); setNote('')
    try {
      setPreview(await admin.importValidate(file))
      await loadBatches()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  const commit = async () => {
    if (!preview?.can_commit) return
    setBusy('commit'); setError(''); setNote('')
    try {
      const done = await admin.importCommit(preview.batch_id)
      setNote(`${done.created.length} account(s) created, as invited. `
              + 'Set each a password from Users when they start.')
      setOpen(preview.batch_id)
      setPreview(null)
      setFile(null)
      await loadBatches()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="maec-card">
      <h1 className="maec-h1">User Onboarding &amp; Import</h1>
      <p className="maec-lede">
        Configure bulk user uploads, role mappings, and centralized directory integrations.
      </p>

      <div className="maec-notice">
        <span className="maec-notice-title">Future-state architecture notice</span>
        This manual CSV upload interface is temporary. Once our dedicated
        Onboarding Tool is fully developed, user details and roles will be
        pulled directly from there.
      </div>

      <div className="maec-upload">
        <div>
          <h3>Upload User Details (CSV)</h3>
          {/* the whole box is the file picker; the hidden input is what the
              keyboard and a screen reader reach */}
          <label
            className={`maec-dropbox${dragging ? ' over' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault(); setDragging(false)
              choose(e.dataTransfer.files?.[0])
            }}
          >
            <input type="file" accept=".csv,text/csv"
                   style={{ position: 'absolute', opacity: 0, width: 1, height: 1 }}
                   onChange={(e) => choose(e.target.files?.[0])} />
            <span>Drag and drop your CSV file here, or <u>browse</u></span>
            <small>
              {file
                ? `${file.name} — ${Math.ceil(file.size / 1024)} KB`
                : 'Supports .csv files up to 25MB (Max 5,000 rows per upload)'}
            </small>
          </label>
        </div>

        <div>
          <h3>Upload Guidelines &amp; Schema</h3>
          <div className="maec-guidelines">
            <p className="maec-guidelines-title">Required CSV Columns:</p>
            <div className="maec-tags">
              <span className="maec-chip tag">Name</span>
              <span className="maec-chip tag">Email</span>
              <span className="maec-chip tag">Job Role</span>
            </div>
            <p>* Ensure all email addresses are unique and belong to active corporate domains.</p>
            <p>Role personas must match pre-configured system roles. Department may be added as a fourth column.</p>
          </div>
        </div>
      </div>

      <div className="maec-upload-actions">
        <button type="button" className="maec-btn primary"
                disabled={!file || busy === 'validate'} onClick={validate}>
          {busy === 'validate' ? 'Checking…' : 'Upload & Validate Records'}
        </button>
        <button type="button" className="maec-btn secondary" onClick={() => admin.importTemplate()}>
          Download CSV Template
        </button>
      </div>

      {error && <p className="maec-error" style={{ marginTop: 14 }}>{error}</p>}
      {note && <p className="maec-note" style={{ marginTop: 14 }}>{note}</p>}

      {preview && (
        <div className="maec-detail">
          <h2 className="maec-h2">What this file would create</h2>
          <p className="maec-lede" style={{ marginBottom: 12 }}>
            Nothing has been created yet. This is the same check the commit
            performs — if anything changes before you confirm, the commit
            stops and asks you to upload again.
          </p>

          {preview.file_problems?.length > 0 && (
            <ul className="maec-problems">
              {preview.file_problems.map((p) => <li key={p}>{p}</li>)}
            </ul>
          )}

          {preview.rows?.length > 0 && (
            <>
              <div className="maec-stats" style={{ marginTop: 0, marginBottom: 12 }}>
                <div className="maec-stat">
                  <span className="maec-stat-value">{preview.total}</span>
                  <span className="maec-stat-label">Rows read</span>
                </div>
                <div className="maec-stat">
                  <span className="maec-stat-value">{preview.valid}</span>
                  <span className="maec-stat-label">Would be created</span>
                </div>
                <div className="maec-stat">
                  <span className="maec-stat-value">{preview.failed}</span>
                  <span className="maec-stat-label">Would be skipped</span>
                </div>
              </div>

              <div className="maec-table-wrap">
                <table className="maec-table">
                  <thead>
                    <tr>
                      <th>Line</th><th>Name</th><th>Email</th>
                      <th>Job Role</th><th>Placed in</th><th>Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.rows.map((r) => (
                      <tr key={r.line}>
                        <td className="maec-mono">{r.line}</td>
                        <td>{r.name || '—'}</td>
                        <td>{r.email || '—'}</td>
                        <td>{r.role_key || r.role_persona || '—'}</td>
                        <td className="maec-faint">
                          {r.ok ? `${r.scope_type}${r.scope_id ? ` / ${r.scope_id}` : ''}` : '—'}
                        </td>
                        <td>
                          {r.ok
                            ? <span className="maec-chip granted">Create as invited</span>
                            : (
                              <>
                                <span className="maec-chip denied">Skip</span>
                                <span className="maec-faint"> {r.problems.join('; ')}</span>
                              </>
                            )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          <div className="maec-form-actions" style={{ marginTop: 14 }}>
            <button type="button" className="maec-btn primary"
                    disabled={!preview.can_commit || busy === 'commit'} onClick={commit}>
              {busy === 'commit'
                ? 'Creating…'
                : `Create ${preview.valid} account${preview.valid === 1 ? '' : 's'}`}
            </button>
            <button type="button" className="maec-btn secondary"
                    onClick={() => { setPreview(null); setFile(null) }}>
              Cancel
            </button>
          </div>
          {preview.valid > 0 && (
            <p className="maec-lede" style={{ marginTop: 10 }}>
              Accounts are created as <strong>invited</strong> with no usable
              password. No email is sent yet — set each a password from Users
              when the person starts.
            </p>
          )}
        </div>
      )}

      <h2 className="maec-section">Recent Import History &amp; Status</h2>
      <div className="maec-boxed maec-table-wrap">
        <table className="maec-table">
          <thead>
            <tr>
              <th>Batch ID</th><th>File Name</th><th>Uploaded By</th>
              <th>Records Processed</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {batches.map((b) => {
              const status = batchStatus(b.status)
              const isOpen = open === b.id
              return (
                <Fragment key={b.id}>
                  <tr className={`maec-opens${isOpen ? ' maec-open' : ''}`}
                      onClick={() => setOpen(isOpen ? null : b.id)}>
                    <td>
                      <button type="button" className="maec-linkish" aria-expanded={isOpen}
                              onClick={(e) => { e.stopPropagation(); setOpen(isOpen ? null : b.id) }}>
                        {batchLabel(b.id)}
                      </button>
                    </td>
                    <td>{b.filename}</td>
                    <td>{b.uploaded_by || '—'}</td>
                    <td>{b.records_valid} / {b.records_total} Valid</td>
                    <td><span className={`maec-chip ${status.tone}`}>{status.label}</span></td>
                  </tr>
                  {isOpen && (
                    <tr><td className="maec-subrow" colSpan={5}><BatchPeople id={b.id} /></td></tr>
                  )}
                </Fragment>
              )
            })}
            {batches.length === 0 && (
              <tr><td colSpan={5}><p className="maec-lede">Nothing has been imported yet.</p></td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
