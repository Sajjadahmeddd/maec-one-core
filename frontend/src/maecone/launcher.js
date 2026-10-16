// What a launcher tile does, and what the launcher offers besides the tiles.
//
// Every application in Core's registry gets a tile; the list and every fact
// about it come from GET /api/auth/me. A tile opens only when all three hold:
// the application is live, this person may use it (`entitled`: a seat, under
// an in-date subscription, in an active organisation — the gate's own test),
// and it has an address. Otherwise it says why, and is not a control at all —
// nothing on the launcher looks clickable and does nothing.
//
// Pure: no window, no React. `launcher.test.js` runs it under `node --test`,
// and the backend suite runs that file (test_frontend_rules.py).

/** Why a tile does not open. When several apply, the first listed wins. */
export const REASONS = {
  suspended: 'Organisation suspended',
  comingSoon: 'Coming soon',
  noSeat: 'No access – ask your administrator',
  notYet: 'Not available yet',
}

/**
 * { open: true } or { open: false, reason }.
 *
 * @param app      one entry of `apps` from /api/auth/me
 * @param session  the /api/auth/me payload it came with
 */
export function tileState(app, session) {
  if (session?.organization_suspended) return { open: false, reason: REASONS.suspended }
  if (app?.status !== 'live') return { open: false, reason: REASONS.comingSoon }
  if (!app.entitled) return { open: false, reason: REASONS.noSeat }
  if (!app.base_url) return { open: false, reason: REASONS.notYet }
  return { open: true }
}

/** The "Admin panel" card: Global Admins only. The API refuses /api/admin/*
 *  to anyone else whatever this says; this only decides what is offered. */
export const offersAdminPanel = (session) =>
  session?.authenticated === true && session.is_global_admin === true
