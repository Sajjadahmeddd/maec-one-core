// How the Global Admin screens put the server's answers into words.
//
// Nothing here decides who may do what — the server does, and refuses on its
// own account. This only orders, labels and colours what it sends, so the
// screens read like the designs in frontend/Global admin GUI/ while every
// value on them stays real.
//
// Pure: no window, no React. `present.test.js` runs it under `node --test`,
// and the backend suite runs that file (test_frontend_rules.py).

/**
 * Roles as the designs list them: the built-in ones from the everyday role
 * up to Global Admin, then the organisation's own, by name.
 */
export function roleOrder(roles = []) {
  const system = roles.filter((r) => r.is_system ?? !r.is_custom)
  const custom = roles.filter((r) => !(r.is_system ?? !r.is_custom))
  return [
    ...system.sort((a, b) => (b.level ?? 0) - (a.level ?? 0) || a.name.localeCompare(b.name)),
    ...custom.sort((a, b) => a.name.localeCompare(b.name)),
  ]
}

const ACCESS = {
  full: { label: 'Full Access', tone: 'granted' },
  edit: { label: 'Edit', tone: 'granted' },
  partial: { label: 'Partial', tone: 'scoped' },
  view: { label: 'View Only', tone: 'scoped' },
  hidden: { label: 'Hidden', tone: 'inactive' },
  none: { label: 'No Access', tone: 'denied' },
}

/**
 * What a role can do with a tool here: what the role grants (`summary`, from
 * /api/admin/roles: full | partial | view | none), narrowed by this
 * organisation's tool rule if there is one. A rule only ever takes access
 * away — so nothing granted is nothing, whatever the rule says.
 *
 * @returns {{ key, label, tone, ruled }}  ruled: a tool rule is in force
 */
export function effectiveAccess(summary, ruleLevel) {
  const granted = ACCESS[summary] ? summary : 'none'
  if (granted === 'none') return { key: 'none', ...ACCESS.none, ruled: !!ruleLevel }
  if (!ruleLevel || ruleLevel === 'full') {
    return { key: granted, ...ACCESS[granted], ruled: ruleLevel === 'full' }
  }
  const key = ruleLevel === 'no_access' ? 'none' : ruleLevel
  return { key, ...(ACCESS[key] || ACCESS.none), ruled: true }
}

/** "Engineering Tools - hapext"; an application's single module is just its name. */
export function toolLabel(module) {
  return module.module_key === 'app'
    ? module.application_name
    : `${module.application_name} - ${module.module_key}`
}

/** live -> Active; anything not yet live -> In-Active. */
export function toolStatus(applicationStatus) {
  return applicationStatus === 'live'
    ? { label: 'Active', tone: 'neutral' }
    : { label: 'In-Active', tone: 'rose' }
}

// ------------------------------------------------------------------ audit
const ACTIONS = {
  'login.success': 'Signed in',
  'login.failed': 'Failed sign-in',
  'login.locked': 'Sign-in locked out',
  logout: 'Signed out',
  'user.create': 'Created user',
  'user.update': 'Updated user',
  'user.status': 'Changed user status',
  'user.delete': 'Deleted user',
  'user.password': 'Reset password',
  'user.password.self': 'Changed own password',
  'user.sessions.revoke': 'Signed user out everywhere',
  'user.import': 'Imported user',
  'role.create': 'Created role',
  'role.delete': 'Deleted role',
  'role.permission': 'Updated role permissions',
  'role.grant': 'Granted role',
  'role.revoke': 'Revoked role',
  'license.assign': 'Assigned seat',
  'license.remove': 'Removed seat',
  'tool_rule.set': 'Changed tool setting',
  'provisioning.rule': 'Changed provisioning rule',
  'import.validate': 'CSV validated',
  'import.commit': 'CSV import completed',
  'import.escalation': 'CSV import refused a role',
  'admin.access': 'Refused admin access',
  'admin.csrf': 'Refused request without CSRF token',
  'permission.denied': 'Refused action',
  'gate.no_access': 'Refused application access',
  'oauth.authorize': 'Application sign-in',
  'oauth.token': 'Application token',
  'oauth.client.register': 'Registered application client',
}

/** An audit action in words; an action this list does not know, as written. */
export const actionLabel = (code) => ACTIONS[code] || code

const SOURCES = {
  // api: anything done in the browser while signed in — an administrator's
  // change, or someone changing their own password
  login: 'Sign-in', api: 'Web console', cli: 'Command line', gate: 'App gate',
  oidc: 'Application sign-in',
}

export const sourceLabel = (source) => (source ? SOURCES[source] || source : '—')

const RESULTS = {
  success: { label: 'Success', tone: 'granted' },
  warning: { label: 'Warning', tone: 'warn' },
  blocked: { label: 'Blocked', tone: 'denied' },
}

export const resultBadge = (result) => RESULTS[result] || { label: result, tone: 'inactive' }

/** The target by name when the server could name it, else its kind and the
 *  start of its id (the row's detail shows all of it). */
export function targetLabel(event) {
  if (event.target_label) return event.target_label
  if (!event.target_type) return '—'
  const id = event.target_id || '—'
  return `${event.target_type}: ${id.length > 12 ? `${id.slice(0, 8)}…` : id}`
}

/** "Sep 07, 01:24" — the designs' timestamp, in the viewer's time zone. */
export function shortWhen(iso, locale) {
  if (!iso) return '—'
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return '—'
  const day = at.toLocaleString(locale || 'en-US', { month: 'short', day: '2-digit' })
  const time = at.toLocaleString(locale || 'en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
  return `${day}, ${time}`
}

/**
 * The security posture card, from /api/admin/audit/controls: Healthy only
 * when every control the server reports is on.
 */
export function posture(controls = []) {
  const on = controls.filter((c) => c.on)
  const healthy = controls.length > 0 && on.length === controls.length
  return {
    label: healthy ? 'Healthy' : 'Needs attention',
    tone: healthy ? 'granted' : 'warn',
    line: on.map((c) => c.short || c.label).join(' • '),
    count: `${on.length} of ${controls.length} controls on`,
  }
}

// ------------------------------------------------------------- onboarding
/** "#BATCH-3F2A9C10", from the batch's id. */
export const batchLabel = (id = '') => `#BATCH-${id.replace(/-/g, '').slice(0, 8).toUpperCase()}`

const BATCH_STATUS = {
  success: { label: 'Successfully Added', tone: 'granted' },
  warnings: { label: 'Added with warnings', tone: 'warn' },
  failed: { label: 'Failed', tone: 'denied' },
  pending: { label: 'Validated, not added', tone: 'inactive' },
}

export const batchStatus = (status) => BATCH_STATUS[status] || { label: status, tone: 'inactive' }

/** The everyday role reads green; anything more senior, amber. */
export const roleTone = (held) => (held && held.level < 4 ? 'warn' : 'granted')

/**
 * The columns of a batch's people table: every live application, plus any
 * other one somebody in the batch holds a role in specifically.
 */
export function batchColumns(applications = [], people = []) {
  const named = new Set(people.flatMap((p) => Object.keys(p.roles || {})))
  return applications.filter((a) => a.status === 'live' || named.has(a.key))
}

/** The role a person holds in one application: there specifically, else everywhere. */
export const heldIn = (person, appKey) => person.roles?.[appKey] || person.everywhere || null
