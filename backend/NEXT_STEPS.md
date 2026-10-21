# Next steps (handoff between PCs)

Updated: 2026-10-21

## After copying backend/ and frontend/ to another PC

1. `npm install` in `backend/` and in `frontend/` (dependencies changed:
   xlsx removed, nodemon dev-only, axios updated).
2. One-time database setup on that PC, if not done yet:
   - MongoDB must run as a replica set (service delivery uses
     transactions): `scripts/enable-mongo-replica-set.ps1`
   - Locations: `node scripts/importLocations.js`
   - Plans: created automatically when the server starts.
   - Organizations created before 2026-10-21 may lack lookups:
     `node scripts/seedDefaultLookups.js --dry-run`, then without it.
3. Check: `npm test` in `backend/` (30 tests; uses its own temporary
   database, never your data).

## Maintenance commands (run in backend/)

| Task | Command |
|---|---|
| Back up local DB | `node scripts/backupDatabase.js` |
| Back up LIVE DB (read-only) | `node scripts/backupDatabase.js --uri-file .env.atlas --db ngo_system` |
| Restore (into a NEW db name first) | `node scripts/restoreDatabase.js backups/<folder> --db <new_name>` |
| Fill missing default lookups (preview) | `node scripts/seedDefaultLookups.js --dry-run` |
| Same on LIVE (preview / apply) | `node scripts/seedDefaultLookups.js --uri-file .env.atlas --db ngo_system [--dry-run]` |
| Tests | `npm test` |

Backups land in `backend/backups/` (git-ignored: personal data). Atlas free
tier has no automatic backups, so run the live backup regularly and copy the
folder somewhere safe.

## Done and deployed (2026-10-21)

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

## Done locally, not yet deployed

- Group 5 (operations):
  - new organizations get common lookups (sign-up and super admin);
    backfill script for existing ones
  - default plans created at startup if missing (never overwrites)
  - backup / restore scripts (live backup taken 2026-10-21)
  - live settings reviewed: production mode, security headers, CORS,
    rate limits OK

## Finance module (in progress, local only)

Decisions: fiscal year = calendar year (Jan–Dec, "FY 2026", NOT Ethiopian);
currencies ETB + foreign; separate Finance Officer role; procurement later
(budget formula is Remaining = Budget − Committed − Spent, Committed = 0
until purchase orders exist).

- Step 1 DONE: master budget (program envelope per year, project budget
  lines x years, allocation limits, approval, Finance Officer role,
  Budgets screens). Not deployed yet.
- Step 2 DONE: expenses charged to approved budget lines (Spent /
  Pending / Remaining, over-budget approval with reason, void, foreign
  currency with rate, concurrency-safe approval). Not deployed yet.
- Local sample data (home PC): BUD-000001 program + BUD-000002 Empower
  Girls project budget, expenses EXP-000001..006 (all marked "sample").
- Step 3 DONE: reports "Budget vs Actual" (by project / line, burn rate,
  over-budget lines) and "Spending by Donor" in Reports > Financial,
  with PDF / Excel / CSV. Not deployed yet.
- Step 4 DONE: budget revisions. An approved budget is changed through
  a revision (new figures + reason -> submit -> approve); the old
  figures are kept as a version, expenses stay attached. Budget page
  shows current vs proposed and the version history. Not deployed yet.
- List pages restyled (DONE, not deployed): Programs, Projects, Donors,
  Donations, Service Deliveries, Attendance, Beneficiaries, Enterprises,
  Enterprise Members now use the Budgets / Activities layout. Shared
  helpers: hooks/useServerList, utils/permissions, utils/apiError.
  Donations and Service Deliveries APIs have no paging / search, so those
  two filter in the browser (fine for now; add server paging if they grow).
- Live TOR-000001 has currency "150000": set it to ETB on next deploy.

## Remaining

- Live: deploy group 5, then fill PADet / Test org lookups
  (PADet has no Units / Service Types, so no service delivery yet).
- Optional: scheduled weekly live backup on this PC.
- Optional: Render paid tier to avoid the ~1 min wake-up after idle.
- Optional: move page data loading to React Query (clears the last
  68 lint hints; not bugs).
- Deploy: push to GitHub and let Render rebuild, only when the owner
  asks.

## To continue with Claude on another PC

Say: "read backend/NEXT_STEPS.md and continue".
