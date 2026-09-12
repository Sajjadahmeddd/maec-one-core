// Screen 005 — User Onboarding & Import.
//
// Upload, see exactly what would be created, then confirm. The preview comes
// from the same resolution the commit performs, so what this screen promises
// is what the server does — and if the database moves in between, the commit
// refuses rather than quietly doing something else.

import { useCallback, useEffect, useState } from 'react'
import { admin } from '../api'

const STATUS_TONE = {
  success: 'granted', warnings: 'warn', failed: 'denied', pending: 'scoped',
}

export default function OnboardingScreen() {
  const [batches, setBatches] = useState([])
  const [preview, setPreview] = useState(null)
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [dragging, setDragging] = useState(false)

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
              + 'Set each a password from Users & Access when they start.')
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
    <div className="maec-stack">
      <div className="maec-card">
        <div className="maec-head">
          <div>
            <h1 className="maec-h1">User Onboarding &amp; Import</h1>
            <p className="maec-lede">
              Configure bulk user uploads, role mappings, and centralized
              directory integrations.
            </p>
          </div>
          <button type="button" className="maec-btn secondary"
                  onClick={() => admin.importTemplate()}>
            Download CSV Template
          </button>
        </div>

        <p className="maec-note">
          Manual CSV upload is temporary. It will be superseded by the
          dedicated onboarding tool, and by directory provisioning once that
          is connected.
        </p>

        <div
          className={`maec-drop${dragging ? ' over' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault(); setDragging(false)
            choose(e.dataTransfer.files?.[0])
          }}
        >
          <p><strong>Drop a .csv here</strong>, or</p>
          <label className="maec-btn secondary">
            Choose file
            <input type="file" accept=".csv,text/csv" hidden
                   onChange={(e) => choose(e.target.files?.[0])} />
          </label>
          {file && <p className="maec-lede">{file.name} — {Math.ceil(file.size / 1024)} KB</p>}
          <p className="maec-lede">Up to 25 MB and 5,000 rows.</p>
        </div>

        <div className="maec-form-actions">
          <button type="button" className="maec-btn primary"
                  disabled={!file || busy === 'validate'} onClick={validate}>
            {busy === 'validate' ? 'Checking…' : 'Upload & Validate Records'}
          </button>
        </div>

        {error && <p className="maec-error">{error}</p>}
        {note && <p className="maec-note">{note}</p>}

        <h3 className="maec-h3">Required columns</h3>
        <ul className="maec-legend">
          <li><span className="maec-chip scoped">name</span><span>The person's full name.</span></li>
          <li><span className="maec-chip scoped">email</span><span>Must be on a domain this organisation owns.</span></li>
          <li><span className="maec-chip scoped">role_persona</span><span>A role that already exists — the template lists them.</span></li>
          <li><span className="maec-chip scoped">department</span><span>Free text; may be blank.</span></li>
        </ul>
      </div>

      {preview && (
        <div className="maec-card">
          <h2 className="maec-h2">What this file would create</h2>
          <p className="maec-lede">
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
              <div className="maec-stats">
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
                      <th>Role</th><th>Placed in</th><th>Outcome</th>
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

          <div className="maec-form-actions">
            <button type="button" className="maec-btn primary"
                    disabled={!preview.can_commit || busy === 'commit'}
                    onClick={commit}>
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
            <p className="maec-lede">
              Accounts are created as <strong>invited</strong> with no usable
              password. No email is sent yet — set each a password from Users
              &amp; Access when the person starts.
            </p>
          )}
        </div>
      )}

      <div className="maec-card">
        <h2 className="maec-h2">Import history</h2>
        <div className="maec-table-wrap">
          <table className="maec-table">
            <thead>
              <tr>
                <th>Batch</th><th>File</th><th>Uploaded by</th>
                <th>Records</th><th>Status</th>
              </tr>
            </thead>
            <tbody>
              {batches.map((b) => (
                <tr key={b.id}>
                  <td className="maec-mono">{b.id.slice(0, 8)}</td>
                  <td>{b.filename}</td>
                  <td>{b.uploaded_by || '—'}</td>
                  <td>
                    {b.records_valid} of {b.records_total}
                    {b.records_failed > 0 && (
                      <span className="maec-faint"> ({b.records_failed} skipped)</span>
                    )}
                  </td>
                  <td>
                    <span className={`maec-chip ${STATUS_TONE[b.status] || 'inactive'}`}>
                      {b.status}
                    </span>
                  </td>
                </tr>
              ))}
              {batches.length === 0 && (
                <tr><td colSpan={5}>
                  <p className="maec-lede">Nothing has been imported yet.</p>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
