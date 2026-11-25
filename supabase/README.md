# GreenGrid – Supabase database (Phase 1)

This folder holds the database schema, row-level security (RLS), workflow rules and security tests for the GreenGrid Solar PV & BESS Project Control dashboard.

Phase 1 covers the database only. The frontend, the Vercel deployment and the production site are **not changed**.

## Files

| File | Purpose |
|---|---|
| `migrations/20261125100001_core_schema.sql` | Tables, constraints, indexes, `updated_at` triggers |
| `migrations/20261125100002_auth_helpers.sql` | `profiles`, role helper functions, signup trigger (new users = Viewer), role-change guard |
| `migrations/20261125100003_rls_and_grants.sql` | RLS on every table, policies, grants (anon has no access) |
| `migrations/20261125100004_workflow_audit.sql` | QA/QC approval workflow, report issue lock, ownership protection, audit log |
| `migrations/20261125100005_progress_views.sql` | Progress views (per activity, by discipline, weighted overall) |
| `seed/demo_seed.sql` | **Optional.** Prototype sample data, flagged `is_demo = true`. Not run automatically. |
| `seed/demo_cleanup.sql` | Preview and delete demo rows only. **Do not run until you approve.** |
| `tests/00_local_auth_shim.sql` | **Local Postgres only.** Imitates Supabase's `auth` schema and roles. Never run on Supabase. |
| `tests/01_rls_security_tests.sql` | 62 RLS, workflow and calculation checks. Runs in one transaction and rolls back. |

## Roles and permissions

| Action | Admin | Engineer | Viewer |
|---|:-:|:-:|:-:|
| Read all project data | ✅ | ✅ | ✅ |
| Log progress, BESS block status, HSE, manpower, equipment status, issues | ✅ | ✅ | ❌ |
| Create/edit QA/QC records and **submit** them | ✅ | ✅ | ❌ |
| **Approve / reject / close** QA/QC | ✅ | ❌ | ❌ |
| Create report drafts | ✅ | ✅ | ❌ |
| **Issue** reports (locks them) | ✅ | ❌ | ❌ |
| Baseline: activities, planned/opening quantities, weights, schedule baseline | ✅ | ❌ | ❌ |
| Project settings (name, capacities) | ✅ | ❌ | ❌ |
| Change roles / activate or deactivate users | ✅ | ❌ | ❌ |
| Delete records | ✅ | ❌ | ❌ |
| Read the audit log | ✅ | ❌ | ❌ |

Rules that depend on row values are enforced by triggers, not only by RLS:
- QA/QC: Engineers cannot create records as Approved, cannot touch submission or review fields, and cannot edit a record while it is Submitted, Approved or Closed.
- Reports: issued reports are locked and cannot be reopened.
- Ownership: `created_by`, `created_at`, `project_id` and `is_demo` cannot be changed by API clients.
- Roles: users cannot change their own role or status.

## Apply the migrations to your existing Supabase project

Use the **existing** Supabase project. Do not create a second one.

**Before you start:** check that the project has no tables you need. The first migration creates tables named `projects`, `activities`, etc. If the project already has tables with those names, stop and tell me.

### Option A: SQL Editor (no CLI needed)

1. Open the Supabase Dashboard → your project → **SQL Editor** → **New query**.
2. Paste and run each file **in this order**, one at a time:
   1. `migrations/20261125100001_core_schema.sql`
   2. `migrations/20261125100002_auth_helpers.sql`
   3. `migrations/20261125100003_rls_and_grants.sql`
   4. `migrations/20261125100004_workflow_audit.sql`
   5. `migrations/20261125100005_progress_views.sql`
3. Do **not** run `seed/demo_seed.sql` yet. Run it only when you want the prototype data loaded as DEMO DATA.

### Option B: Supabase CLI (from your computer)

```bash
supabase login
supabase link --project-ref <your-project-ref>
supabase db push
```

The CLI asks for the database password in your terminal. Do not paste it into chat or into any file.

## Dashboard settings (Authentication)

Set these in the Supabase Dashboard → **Authentication**:

- **Sign-ups:** turn **off** "Allow new users to sign up". Anyone who can sign up could read all project data, even as a Viewer. Admins invite users instead.
- **Email confirmation:** on.
- **URL configuration:** Site URL `https://solar-bess-eight.vercel.app`. Add redirect URLs only when the frontend needs them (Phase 2).
- **Anonymous sign-ins:** off.

## Create the first Admin

1. Invite yourself: Dashboard → **Authentication** → **Users** → **Invite user**.
2. Accept the invitation. This creates your profile as a Viewer.
3. In the SQL Editor, run once (replace the UUID with your user ID from the Users page):

```sql
update public.profiles
set role = 'admin'
where id = '00000000-0000-0000-0000-000000000000';
```

The SQL Editor runs as `postgres`. It is the only path that can change roles without an existing Admin. Use it only for this bootstrap step and for admin maintenance.

## Run the security tests (local only)

**Do not run the tests against the production project.** They insert fake users and project rows. They roll back at the end, but do not risk it.

### With the Supabase CLI and Docker

```bash
supabase start
supabase db reset                      # applies all migrations to the local database
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" \
  -v ON_ERROR_STOP=1 -f supabase/tests/01_rls_security_tests.sql
```

Local Supabase already provides `auth`, `anon` and `authenticated`, so **do not** run `00_local_auth_shim.sql` in this setup.

### With plain PostgreSQL 15+ (no Docker)

```bash
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/tests/00_local_auth_shim.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/migrations/20261125100001_core_schema.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/migrations/20261125100002_auth_helpers.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/migrations/20261125100003_rls_and_grants.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/migrations/20261125100004_workflow_audit.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/migrations/20261125100005_progress_views.sql
psql "<local-connection-string>" -v ON_ERROR_STOP=1 -f supabase/tests/01_rls_security_tests.sql
```

A passing run prints `PASS` lines and no `FAIL`. Any `FAIL` stops the run with the name of the check.

**Status:** I ran these files on PostgreSQL 16 locally. All 62 checks passed. I also confirmed the suite catches a broken guard: with the role-change trigger disabled, check T24 failed. I have **not** run them on a real Supabase instance. Supabase's `auth.users` may have extra required columns, so a first run there may need a small change to the fixture inserts.

## Environment variables

Phase 1 needs **no** environment variables and no secret keys in the repository.

| Variable | Where | Secret? | Used in |
|---|---|---|---|
| `SUPABASE_URL` | Frontend config (Vercel env vars) | No (public) | Phase 2 |
| `SUPABASE_ANON_KEY` | Frontend config (Vercel env vars) | No (public, protected by RLS) | Phase 2 |
| `SUPABASE_SERVICE_ROLE_KEY` | Server only (Supabase Edge Function secret) | **Yes**. Never in frontend code or the repo. | Only if an invite Edge Function is added |
| `SUPABASE_DB_URL` | Your computer, CLI only | **Yes** | Migrations from your computer |

The `service_role` key bypasses RLS. It must never appear in `index.html`, any JavaScript file, `config.js`, or a commit.

## Decisions to confirm

These are choices I made in the schema. Please review them before we build the frontend.

1. **Engineers can edit each other's progress entries and BESS block status.** Only Admins delete. Changing this is one policy line.
2. **Only Admins issue reports.** You did not specify this, so I chose it.
3. **Manpower categories are a fixed list** (Engineer, Supervisor, Technician, Electrician, Labour, QA/QC, HSE, Commissioning, Other). Adding one needs a migration. Tell me the list you want.
4. **Equipment:** Engineers create and update equipment and daily logs. Only Admins delete.
5. **Profiles are readable by all active users.** The table holds only name, role and status. Email stays in Supabase Auth.
6. **Opening quantities** carry over the prototype's "installed" numbers, so history is not lost. Installed quantity = opening + sum of logged entries.
7. **No overall percentage without verified weights.** `project_progress_overview.weighted_overall_pct` stays NULL until every activity has a weight on the same basis (Budget or Man-hours).
8. **Demo data** is flagged `is_demo`. Capacities are NULL: the 232 MW / 526 MWh figures are not carried over.

## Known gaps (for later phases)

- **Last Admin protection:** nothing yet stops an Admin from demoting the last Admin. I will add this if you want it.
- **Audit log retention:** no cleanup policy yet.
- **Engineer edits to QA/QC after submission:** locked by design. If a submitted record needs a correction, the Engineer withdraws it to Draft first.
- **Attachments** (photos, inspection PDFs): not in Phase 1.
- **Frontend:** untouched. Phase 2 connects it to these tables.
