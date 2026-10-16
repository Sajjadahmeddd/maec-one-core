// node --test frontend/src/maecone/admin/present.test.js
//
// How the Global Admin screens word, order and colour what the server sends.
// Run by the backend suite too (test_frontend_rules.py).

import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  accessBadge, actionLabel, batchColumns, batchLabel, batchStatus, heldIn,
  posture, resultBadge, roleOrder, roleTone, shortWhen, sourceLabel,
  targetLabel, toolLabel, toolStatus,
} from './present.js'

const role = (key, name, level, is_system = true) => ({ key, name, level, is_system })

test('roles run from the everyday one up to Global Admin, then custom by name', () => {
  const ordered = roleOrder([
    role('global_admin', 'Global Admin', 1),
    role('it_admin', 'IT Admin', 4, false),
    role('business_admin', 'Business & Commercial Lead', 2),
    role('employee', 'Normal User / Engineer', 4),
    role('finance_admin', 'Finance Admin', 4, false),
    role('project_lead', 'Project Lead', 3),
  ])
  assert.deepEqual(ordered.map((r) => r.name), [
    'Normal User / Engineer', 'Project Lead', 'Business & Commercial Lead',
    'Global Admin', 'Finance Admin', 'IT Admin',
  ])
})

test('two levels only: Full Access or No Access', () => {
  assert.deepEqual(accessBadge('full'), { label: 'Full Access', tone: 'granted' })
  assert.deepEqual(accessBadge('no_access'), { label: 'No Access', tone: 'denied' })
  // the retired levels, or nothing, read as what the engine does: refuse
  for (const old of ['view', 'edit', 'hidden', 'partial', undefined]) {
    assert.equal(accessBadge(old).label, 'No Access', String(old))
  }
})

test('tool rows and their status', () => {
  assert.equal(toolLabel({ application_name: 'Engineering Tools', module_key: 'hapext' }),
               'Engineering Tools - hapext')
  assert.equal(toolLabel({ application_name: 'Project Management', module_key: 'app' }),
               'Project Management')
  assert.equal(toolStatus('active').label, 'Active')
  assert.equal(toolStatus('inactive').label, 'Inactive')
  assert.equal(toolStatus(undefined).label, 'Active', 'no setting is active')
})

test('audit rows in words, unknown codes as written', () => {
  assert.equal(actionLabel('role.permission'), 'Updated role permissions')
  assert.equal(actionLabel('login.failed'), 'Failed sign-in')
  assert.equal(actionLabel('something.new'), 'something.new')
  assert.equal(sourceLabel('api'), 'Web console')
  assert.equal(sourceLabel(null), '—')
  assert.deepEqual(resultBadge('blocked'), { label: 'Blocked', tone: 'denied' })
  assert.equal(targetLabel({ target_type: 'role', target_id: 'x', target_label: 'Project Lead' }),
               'Project Lead')
  assert.equal(targetLabel({ target_type: 'user', target_id: 'abc', target_label: null }), 'user: abc')
  assert.equal(targetLabel({ target_type: 'user', target_id: '62e6276a-b8de-44e8-a14a-761492b24482' }),
               'user: 62e6276a…')
  assert.equal(targetLabel({}), '—')
})

test('the short timestamp', () => {
  const when = shortWhen('2026-09-07T01:24:00', 'en-US')
  assert.match(when, /^Sep 07, 01:24$/)
  assert.equal(shortWhen(null), '—')
  assert.equal(shortWhen('not a date'), '—')
})

test('the security posture is Healthy only when every control is on', () => {
  const on = [{ on: true, short: 'CSRF protection' }, { on: true, label: 'Long label' }]
  assert.deepEqual(posture(on), {
    label: 'Healthy', tone: 'granted',
    line: 'CSRF protection • Long label', count: '2 of 2 controls on',
  })
  const one_off = posture([...on, { on: false, short: 'Append-only audit log' }])
  assert.equal(one_off.label, 'Needs attention')
  assert.equal(one_off.count, '2 of 3 controls on')
  assert.ok(!one_off.line.includes('Append-only'), 'an off control is not listed as on')
  assert.equal(posture([]).label, 'Needs attention', 'no answer is not healthy')
})

test('import batches', () => {
  assert.equal(batchLabel('3f2a9c10-1111-2222-3333-444455556666'), '#BATCH-3F2A9C10')
  assert.equal(batchStatus('success').label, 'Successfully Added')
  assert.equal(batchStatus('pending').label, 'Validated, not added')
  assert.equal(roleTone({ level: 4 }), 'granted')
  assert.equal(roleTone({ level: 3 }), 'warn')

  const apps = [{ key: 'engineering', status: 'live' }, { key: 'projects', status: 'coming_soon' },
                { key: 'finance', status: 'coming_soon' }]
  const people = [{ roles: { projects: { name: 'Project Lead', level: 3 } },
                    everywhere: { name: 'Normal User / Engineer', level: 4 } }]
  assert.deepEqual(batchColumns(apps, people).map((a) => a.key), ['engineering', 'projects'])
  assert.equal(heldIn(people[0], 'projects').name, 'Project Lead')
  assert.equal(heldIn(people[0], 'engineering').name, 'Normal User / Engineer')
  assert.equal(heldIn({ roles: {} }, 'engineering'), null)
})
