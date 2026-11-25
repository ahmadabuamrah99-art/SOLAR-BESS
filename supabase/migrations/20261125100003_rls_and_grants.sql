-- =====================================================================
-- 20261125100003_rls_and_grants.sql
-- Row Level Security on every table, plus table grants.
--
-- Permission summary (see README):
--   Viewer   : read everything.
--   Engineer : read everything; insert/update operational records
--              (progress, BESS blocks, HSE, manpower, equipment, issues,
--              QA/QC drafts and submissions, report drafts). No deletes.
--   Admin    : everything, including baseline data (projects, activities,
--              weights, schedule baseline), QA/QC approval, report issue,
--              user management, deletes.
--
-- Workflow rules that depend on row values (QA/QC status, report issue,
-- ownership fields) are enforced by triggers in 20261125100004.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Enable RLS on every table. Without a policy, access is denied.
-- ---------------------------------------------------------------------
alter table public.projects             enable row level security;
alter table public.profiles             enable row level security;
alter table public.activities           enable row level security;
alter table public.progress_entries     enable row level security;
alter table public.bess_blocks          enable row level security;
alter table public.schedule_baseline    enable row level security;
alter table public.report_snapshots     enable row level security;
alter table public.qaqc_records         enable row level security;
alter table public.hse_records          enable row level security;
alter table public.manpower_daily       enable row level security;
alter table public.equipment            enable row level security;
alter table public.equipment_daily_log  enable row level security;
alter table public.issues               enable row level security;

-- audit_log is enabled in 20261125100004.

-- ---------------------------------------------------------------------
-- 2. Grants. anon gets nothing. authenticated gets DML, still limited by RLS.
-- ---------------------------------------------------------------------
revoke all on all tables in schema public from anon;
revoke all on all tables in schema public from authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Future tables must not be exposed to anon by default.
alter default privileges in schema public revoke all on tables from anon;
alter default privileges in schema public revoke all on sequences from anon;

-- ---------------------------------------------------------------------
-- 3. projects: everyone reads; only Admin writes.
-- ---------------------------------------------------------------------
create policy projects_select on public.projects
  for select to authenticated using (public.can_read());
create policy projects_insert on public.projects
  for insert to authenticated with check (public.is_admin());
create policy projects_update on public.projects
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy projects_delete on public.projects
  for delete to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 4. profiles: active users can read names and roles (no sensitive data stored here).
--    Users can update their own profile (name only; guard trigger blocks role changes).
--    Admins can update any profile. Profiles are created only by the signup trigger.
-- ---------------------------------------------------------------------
create policy profiles_select on public.profiles
  for select to authenticated using (public.can_read());
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.is_admin()) with check (public.is_admin());
-- No insert or delete policy: profiles are managed by the signup trigger and Admin SQL.

-- ---------------------------------------------------------------------
-- 5. Baseline tables: everyone reads; only Admin writes.
-- ---------------------------------------------------------------------
create policy activities_select on public.activities
  for select to authenticated using (public.can_read());
create policy activities_insert on public.activities
  for insert to authenticated with check (public.is_admin());
create policy activities_update on public.activities
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy activities_delete on public.activities
  for delete to authenticated using (public.is_admin());

create policy schedule_baseline_select on public.schedule_baseline
  for select to authenticated using (public.can_read());
create policy schedule_baseline_insert on public.schedule_baseline
  for insert to authenticated with check (public.is_admin());
create policy schedule_baseline_update on public.schedule_baseline
  for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy schedule_baseline_delete on public.schedule_baseline
  for delete to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 6. Operational tables: everyone reads; Admin and Engineer write; only Admin deletes.
--    created_by must be the caller (also enforced by trigger in 04).
-- ---------------------------------------------------------------------
create policy progress_entries_select on public.progress_entries
  for select to authenticated using (public.can_read());
create policy progress_entries_insert on public.progress_entries
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy progress_entries_update on public.progress_entries
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy progress_entries_delete on public.progress_entries
  for delete to authenticated using (public.is_admin());

create policy bess_blocks_select on public.bess_blocks
  for select to authenticated using (public.can_read());
create policy bess_blocks_insert on public.bess_blocks
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy bess_blocks_update on public.bess_blocks
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy bess_blocks_delete on public.bess_blocks
  for delete to authenticated using (public.is_admin());

create policy hse_records_select on public.hse_records
  for select to authenticated using (public.can_read());
create policy hse_records_insert on public.hse_records
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy hse_records_update on public.hse_records
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy hse_records_delete on public.hse_records
  for delete to authenticated using (public.is_admin());

create policy manpower_daily_select on public.manpower_daily
  for select to authenticated using (public.can_read());
create policy manpower_daily_insert on public.manpower_daily
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy manpower_daily_update on public.manpower_daily
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy manpower_daily_delete on public.manpower_daily
  for delete to authenticated using (public.is_admin());

create policy equipment_select on public.equipment
  for select to authenticated using (public.can_read());
create policy equipment_insert on public.equipment
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy equipment_update on public.equipment
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy equipment_delete on public.equipment
  for delete to authenticated using (public.is_admin());

create policy equipment_daily_log_select on public.equipment_daily_log
  for select to authenticated using (public.can_read());
create policy equipment_daily_log_insert on public.equipment_daily_log
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy equipment_daily_log_update on public.equipment_daily_log
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy equipment_daily_log_delete on public.equipment_daily_log
  for delete to authenticated using (public.is_admin());

create policy issues_select on public.issues
  for select to authenticated using (public.can_read());
create policy issues_insert on public.issues
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy issues_update on public.issues
  for update to authenticated using (public.is_writer()) with check (public.is_writer());
create policy issues_delete on public.issues
  for delete to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 7. QA/QC: Engineers create and edit only Draft/Rejected records, and submit them.
--    Submitted, Approved and Closed records are locked for Engineers.
--    Approval, rejection and closure are Admin-only (trigger in 04 enforces the transitions).
-- ---------------------------------------------------------------------
create policy qaqc_records_select on public.qaqc_records
  for select to authenticated using (public.can_read());
create policy qaqc_records_insert on public.qaqc_records
  for insert to authenticated with check (public.is_writer() and created_by = (select auth.uid()));
create policy qaqc_records_update on public.qaqc_records
  for update to authenticated
  using (
    public.is_admin()
    or (public.is_writer() and status in ('Draft', 'Rejected'))
  )
  with check (
    public.is_admin()
    or (public.is_writer() and status in ('Draft', 'Submitted'))
  );
create policy qaqc_records_delete on public.qaqc_records
  for delete to authenticated using (public.is_admin());

-- ---------------------------------------------------------------------
-- 8. Reports: Engineers create and edit Draft reports only. Only Admin issues.
--    Issued reports are locked for everyone (trigger in 04).
-- ---------------------------------------------------------------------
create policy report_snapshots_select on public.report_snapshots
  for select to authenticated using (public.can_read());
create policy report_snapshots_insert on public.report_snapshots
  for insert to authenticated
  with check (
    public.is_writer() and created_by = (select auth.uid())
    and (status = 'Draft' or public.is_admin())
  );
create policy report_snapshots_update on public.report_snapshots
  for update to authenticated
  using (public.is_admin() or (public.is_writer() and status = 'Draft'))
  with check (public.is_admin() or status = 'Draft');
create policy report_snapshots_delete on public.report_snapshots
  for delete to authenticated using (public.is_admin());
