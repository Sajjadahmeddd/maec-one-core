// node --test frontend/src/maecone/launcher.test.js
//
// Where sign-in lands, what each launcher tile does, and who is offered the
// Admin panel. Run by the backend suite too (test_frontend_rules.py).

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { REASONS, offersAdminPanel, tileState } from './launcher.js'
import { HOME, landing } from './next.js'

const HERE = 'http://auth.maec.local:8000'

const app = (over = {}) => ({
  key: 'engineering', name: 'Engineering Tools', status: 'live',
  base_url: 'http://et.maec.local:8080', entitled: true, ...over,
})

const APPS = [
  app(),
  app({ key: 'projects', name: 'Project Management', base_url: 'http://pm.maec.local:8080' }),
  app({ key: 'timesheet', name: 'Timesheet', status: 'coming_soon', base_url: null, entitled: false }),
]

const ADMIN = { authenticated: true, is_global_admin: true, organization_suspended: false, apps: APPS }
const EMPLOYEE = { authenticated: true, is_global_admin: false, organization_suspended: false, apps: APPS }

// ------------------------------------------------------------- landing
test('sign-in without next lands on the launcher, for a Global Admin too', () => {
  for (const who of [ADMIN, EMPLOYEE]) {
    assert.equal(landing(null, who.apps, HERE), HOME)
    assert.equal(landing('', who.apps, HERE), HOME)
  }
  assert.equal(HOME, '/')
})

test('sign-in with a live app as next goes to the app', () => {
  const wanted = 'http://et.maec.local:8080/hapext/convert?file=a'
  assert.equal(landing(wanted, ADMIN.apps, HERE), wanted)
  assert.equal(landing(wanted, EMPLOYEE.apps, HERE), wanted)
})

test('the change-password page and the authorize endpoint are still followed', () => {
  assert.equal(landing('/change-password', EMPLOYEE.apps, HERE), '/change-password')
  assert.equal(landing('/oauth/authorize?client_id=x', EMPLOYEE.apps, HERE), '/oauth/authorize?client_id=x')
})

test('a refused next lands on the launcher, never the Admin panel', () => {
  for (const raw of ['/admin', 'https://evil.com/', 'http://auth.maec.local:8000/admin']) {
    assert.equal(landing(raw, ADMIN.apps, HERE), HOME, raw)
  }
})

// ------------------------------------------------------------- tiles
test('a tile opens only when live, held, and with an address', () => {
  assert.deepEqual(tileState(app(), EMPLOYEE), { open: true })
})

test('each reason on its own', () => {
  const reason = (a, who = EMPLOYEE) => tileState(a, who).reason
  assert.equal(reason(app(), { ...EMPLOYEE, organization_suspended: true }), REASONS.suspended)
  assert.equal(reason(app({ status: 'coming_soon' })), REASONS.comingSoon)
  assert.equal(reason(app({ entitled: false })), REASONS.noSeat)
  assert.equal(reason(app({ base_url: null })), REASONS.notYet)
  assert.equal(reason(app({ base_url: '' })), REASONS.notYet)
})

test('when several apply, the first wins', () => {
  const suspended = { ...EMPLOYEE, organization_suspended: true }
  const everything = app({ status: 'coming_soon', entitled: false, base_url: null })
  assert.equal(tileState(everything, suspended).reason, REASONS.suspended)
  assert.equal(tileState(everything, EMPLOYEE).reason, REASONS.comingSoon)
  assert.equal(tileState(app({ entitled: false, base_url: null }), EMPLOYEE).reason, REASONS.noSeat)
  // a seat on something coming soon is still coming soon
  assert.equal(tileState(app({ status: 'coming_soon' }), EMPLOYEE).reason, REASONS.comingSoon)
})

test('the wording', () => {
  assert.deepEqual(Object.values(REASONS), [
    'Organisation suspended', 'Coming soon',
    'No access – ask your administrator', 'Not available yet',
  ])
})

test('no application is special: the same rule for every key', () => {
  for (const key of ['engineering', 'projects', 'finance', 'anything-new']) {
    assert.equal(tileState(app({ key, base_url: null }), EMPLOYEE).reason, REASONS.notYet, key)
    assert.deepEqual(tileState(app({ key }), EMPLOYEE), { open: true }, key)
  }
})

// ------------------------------------------------------------- admin card
test('the Admin panel card is offered to Global Admins only', () => {
  assert.equal(offersAdminPanel(ADMIN), true)
  assert.equal(offersAdminPanel(EMPLOYEE), false)
  assert.equal(offersAdminPanel({ ...EMPLOYEE, is_global_admin: undefined }), false)
  assert.equal(offersAdminPanel({ authenticated: false, is_global_admin: true }), false)
  assert.equal(offersAdminPanel(null), false)
})
