// The MAEC One Core client: who you are, what you may open, and the admin API.
//
// This file is Core's, not Engineering Tools'. The product client
// (../api.js) imports SESSION_EXPIRED from here; nothing here imports from
// there. When Core moves to its own repository this file goes with it.

export const SESSION_EXPIRED = 'maec:session-expired'

// A cross-site form post cannot set a custom header, which is what makes
// this a defence. The token is minted with the session and handed back by
// /api/auth/me and /api/auth/login; every admin mutation must carry it.
export const CSRF_HEADER = 'X-CSRF-Token'

let csrf = ''

export function setCsrf(token) {
  csrf = token || ''
}

export function csrfHeaders(extra = {}) {
  return csrf ? { ...extra, [CSRF_HEADER]: csrf } : { ...extra }
}

function sessionLapsed(response) {
  if (response.status === 401) {
    window.dispatchEvent(new CustomEvent(SESSION_EXPIRED))
    throw new Error('Your session has expired. Please sign in again.')
  }
}

async function asJson(response) {
  sessionLapsed(response)
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      detail = (await response.json()).detail || detail
    } catch { /* non-JSON error body */ }
    throw new Error(detail)
  }
  return response.json()
}

/** Remember the CSRF token whenever the server hands one over. */
function keepCsrf(body) {
  if (body && body.csrf_token) setCsrf(body.csrf_token)
  return body
}

export const auth = {
  me() {
    return fetch('/api/auth/me').then(asJson).then(keepCsrf)
  },

  login(email, password) {
    return fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    }).then(async (response) => {
      // 401 here is a wrong password, not a lapsed session — showing the
      // "signed out" banner over the sign-in form would make no sense.
      if (response.status === 401 || response.status === 429) {
        const body = await response.json().catch(() => ({}))
        throw new Error(body.detail || 'Incorrect email address or password.')
      }
      return keepCsrf(await asJson(response))
    })
  },

  logout() {
    return fetch('/api/auth/logout', { method: 'POST', headers: csrfHeaders() })
      .then(asJson)
      .finally(() => setCsrf(''))
  },

  /** Reachable while must_change_password is set — it is the way out. */
  changePassword(currentPassword, newPassword) {
    return fetch('/api/auth/change-password', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        current_password: currentPassword, new_password: newPassword,
      }),
    }).then(asJson).then(keepCsrf)
  },
}

/** Every admin mutation carries the CSRF header; the server refuses without it. */
function send(method, path, body) {
  return fetch(path, {
    method,
    headers: csrfHeaders(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then(asJson)
}

export const admin = {
  whoami() {
    return fetch('/api/admin/whoami').then(asJson)
  },

  // ---- screen 001: the role scheme
  roles() {
    return fetch('/api/admin/roles').then(asJson)
  },
  createRole(name, cloneFrom) {
    return send('POST', '/api/admin/roles',
                { name, clone_from: cloneFrom || null })
  },
  patchRole(id, patch) {
    return send('PATCH', `/api/admin/roles/${id}`, patch)
  },
  deleteRole(id) {
    return send('DELETE', `/api/admin/roles/${id}`)
  },

  // ---- user management
  users({ q = '', status = '', page = 1, page_size: size = 25 } = {}) {
    const query = new URLSearchParams({ q, page, page_size: size })
    if (status) query.set('status', status)
    return fetch(`/api/admin/users?${query}`).then(asJson)
  },
  userOptions() {
    return fetch('/api/admin/users/options').then(asJson)
  },
  createUser(body) {
    return send('POST', '/api/admin/users', body)
  },
  patchUser(id, patch) {
    return send('PATCH', `/api/admin/users/${id}`, patch)
  },
  deleteUser(id) {
    return send('DELETE', `/api/admin/users/${id}`)
  },
  grantRole(id, grant) {
    return send('POST', `/api/admin/users/${id}/roles`, grant)
  },
  revokeRole(id, grantId) {
    return send('DELETE', `/api/admin/users/${id}/roles/${grantId}`)
  },
  assignLicense(id, applicationKey) {
    return send('POST', `/api/admin/users/${id}/licenses`,
                { application_key: applicationKey })
  },
  removeLicense(id, applicationKey) {
    return send('DELETE', `/api/admin/users/${id}/licenses/${applicationKey}`)
  },
  resetPassword(id, password) {
    return send('POST', `/api/admin/users/${id}/reset-password`, { password })
  },

  // ---- screen 003: provisioning
  provisioning() {
    return fetch('/api/admin/provisioning').then(asJson)
  },
  createProvisioning(rule) {
    return send('POST', '/api/admin/provisioning', rule)
  },
  patchProvisioning(id, patch) {
    return send('PATCH', `/api/admin/provisioning/${id}`, patch)
  },

  // ---- screen 005: bulk import
  importValidate(file) {
    const form = new FormData()
    form.append('file', file)
    return fetch('/api/admin/import/validate', {
      method: 'POST', headers: csrfHeaders(), body: form,
    }).then(asJson)
  },
  importCommit(batchId) {
    return send('POST', '/api/admin/import/commit', { batch_id: batchId })
  },
  importBatches() {
    return fetch('/api/admin/import/batches').then(asJson)
  },
  importTemplate() {
    window.location.assign('/api/admin/import/template')
  },

  // ---- screen 004: the audit log (read only, like the table itself)
  audit(params = {}) {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== '' && v !== null && v !== undefined) query.set(k, v)
    })
    return fetch(`/api/admin/audit?${query}`).then(asJson)
  },
  auditStats() {
    return fetch('/api/admin/audit/stats').then(asJson)
  },
  auditControls() {
    return fetch('/api/admin/audit/controls').then(asJson)
  },
  /** Downloads through the browser so the session cookie rides along. */
  exportAudit(params = {}) {
    const query = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => {
      if (v !== '' && v !== null && v !== undefined) query.set(k, v)
    })
    window.location.assign(`/api/admin/audit/export?${query}`)
  },

  // ---- screen 002: per-organisation overrides
  toolRules() {
    return fetch('/api/admin/tool-rules').then(asJson)
  },
  putToolRules(changes) {
    return send('PUT', '/api/admin/tool-rules', { changes })
  },
}
