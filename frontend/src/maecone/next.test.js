// node --test frontend/src/maecone/next.test.js
//
// The open-redirect surface: where the sign-in page may send a browser.
// Run by the backend suite too (backend/identity/tests/test_next_allowlist.py).

import assert from 'node:assert/strict'
import { test } from 'node:test'

import { safeNext } from './next.js'

const HERE = 'http://auth.maec.local:8000'
const APPS = [
  { key: 'engineering', status: 'live', base_url: 'http://et.maec.local:8080' },
  { key: 'timesheet', status: 'live', base_url: null },
  { key: 'projects', status: 'coming_soon', base_url: 'http://pm.maec.local:8080' },
]

test('a page in a live app with an address is followed, exactly', () => {
  const wanted = 'http://et.maec.local:8080/hapext/convert?file=a%20b&x=1'
  assert.equal(safeNext(wanted, APPS, HERE), wanted)
  assert.equal(safeNext('http://et.maec.local:8080', APPS, HERE), 'http://et.maec.local:8080/')
})

test('the authorize path on this origin is still followed', () => {
  const path = '/oauth/authorize?client_id=x&state=s'
  assert.equal(safeNext(path, APPS, HERE), path)
})

// Each of these must land on the launcher: safeNext answers null.
const NEAR_MISSES = {
  'protocol-relative host': '//evil.com',
  'protocol-relative with path': '//evil.com/oauth/authorize',
  'our domain as a path on theirs': 'https://evil.com/.maec.local',
  'our host as a prefix of theirs': 'http://et.maec.local.evil.com',
  'javascript:': 'javascript:alert(1)',
  'JavaScript, cased': 'JaVaScRiPt:alert(1)',
  'data:': 'data:text/html,<script>alert(1)</script>',
  'right host, wrong port': 'http://et.maec.local:8081/page',
  'right host, no port': 'http://et.maec.local/page',
  'right host, wrong scheme': 'https://et.maec.local:8080/page',
  'credentials before the host': 'http://et.maec.local:8080@evil.com/',
  'credentials, and our host after': 'http://user:pw@et.maec.local:8080/',
  'backslash for a slash': '/\\evil.com',
  'backslash in an absolute URL': 'http:\\\\et.maec.local:8080',
  'scheme-less host': 'et.maec.local:8080/page',
  'a coming-soon app': 'http://pm.maec.local:8080/page',
  'Core itself, absolute': 'http://auth.maec.local:8000/admin',
  'a relative path other than authorize': '/admin',
  'authorize, but on another host via the path': '//evil.com/oauth/authorize',
  'a tab inside the host': 'http://et.maec\t.local:8080/',
  'empty': '',
}

for (const [name, raw] of Object.entries(NEAR_MISSES)) {
  test(`refused: ${name}`, () => {
    assert.equal(safeNext(raw, APPS, HERE), null)
  })
}

test('with no catalogue, no absolute URL is followed', () => {
  assert.equal(safeNext('http://et.maec.local:8080/', [], HERE), null)
  assert.equal(safeNext('http://et.maec.local:8080/', undefined, HERE), null)
})
