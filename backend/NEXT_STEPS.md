# Next steps (handoff between PCs)

Updated: 2026-10-21

## After copying backend/ and frontend/ to another PC

1. `npm install` in `backend/` and in `frontend/` (dependencies changed:
   xlsx removed, nodemon dev-only, axios updated).
2. One-time database setup on that PC, if not done yet:
   - MongoDB must run as a replica set (service delivery uses
     transactions): `scripts/enable-mongo-replica-set.ps1`
   - Locations: `node scripts/importLocations.js`
   - Plans (if none): `node seeds/planseeder.js`
3. Check: `npm test` in `backend/` (19 tests; uses its own temporary
   database, never your data).

## Done (local only, not yet pushed or deployed)

- Group 1: quick fixes (error screen crash, audit log access, debug logs).
- Group 2: security: change password, admin reset with temporary
  password, forced change, password rules, login lockout, dependency
  fixes.
- Group 3: UI consistency: MUI 9 migration (old styling props were
  ignored), standard list/detail/form layouts, server paging on
  Activities / Activity Runs / Enrollments (only 10 were reachable),
  readable status chips, dashboard fixes, search-input escaping.
- Group 4: proper HTTP error codes, code splitting (first load about a
  third of before), lint 117 -> 68, automated tests.

## Remaining

- Group 5 (operations):
  - database backups (Atlas),
  - seed plans automatically on startup (was missed on Atlas),
  - review live settings on Render / Atlas.
  Prepare locally; do not touch Render or Atlas until the owner says so.
- Optional: move page data loading to React Query (clears the last
  68 lint hints; not bugs).
- Deploy: push to GitHub and let Render rebuild, only when the owner
  asks.

## To continue with Claude on another PC

Say: "read backend/NEXT_STEPS.md and continue".
