-- =====================================================================
-- 20261125100001_core_schema.sql
-- GreenGrid Solar PV & BESS Project Control - core data model.
--
-- Migration order:
--   1. 20261125100001_core_schema.sql      (this file: tables)
--   2. 20261125100002_auth_helpers.sql     (profiles, roles, signup trigger)
--   3. 20261125100003_rls_and_grants.sql   (RLS policies, grants)
--   4. 20261125100004_workflow_audit.sql   (QA/QC + report workflow, audit log)
--   5. 20261125100005_progress_views.sql   (progress calculations)
--
-- Notes:
--   * Requires PostgreSQL 15+ (Supabase default).
--   * Contains no secrets.
--   * Every project-scoped table has is_demo so DEMO data can be identified
--     and removed later. Capacities are NULL until verified by the project team.
-- =====================================================================

-- Shared helper: keeps updated_at current.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- ---------------------------------------------------------------------
-- Projects
-- ---------------------------------------------------------------------
create table public.projects (
  id                uuid primary key default gen_random_uuid(),
  name              text not null check (length(btrim(name)) between 1 and 200),
  pv_capacity_mw    numeric(10,2) check (pv_capacity_mw is null or pv_capacity_mw > 0),
  bess_capacity_mwh numeric(10,2) check (bess_capacity_mwh is null or bess_capacity_mwh > 0),
  is_demo           boolean not null default false,
  created_by        uuid references auth.users(id) on delete set null default auth.uid(),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Activities (baseline register: Solar PV and BESS)
-- Quantities, opening quantities and weights are baseline data: Admin only (RLS).
-- ---------------------------------------------------------------------
create table public.activities (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  workstream    text not null check (workstream in ('Solar PV', 'BESS')),
  discipline    text not null check (discipline in ('Mechanical', 'Electrical', 'QA/QC', 'Commissioning')),
  name          text not null check (length(btrim(name)) between 1 and 200),
  unit          text not null check (length(btrim(unit)) between 1 and 30),
  planned_qty   numeric(14,2) not null check (planned_qty > 0),
  -- Quantity installed before the progress log started (carried over from the old prototype).
  opening_qty   numeric(14,2) not null default 0 check (opening_qty >= 0),
  -- Single planned-progress value kept from the prototype. Superseded by schedule_baseline.
  planned_pct   numeric(5,2) check (planned_pct is null or planned_pct between 0 and 100),
  -- Configurable weighting for a future weighted overall progress.
  -- NULL until verified budget or man-hour values exist.
  weight        numeric(14,2) check (weight is null or weight > 0),
  weight_basis  text check (weight_basis is null or weight_basis in ('Budget', 'Man-hours')),
  sort_order    integer not null default 0,
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint activities_id_project_key unique (id, project_id),
  constraint activities_weight_pair_chk check ((weight is null) = (weight_basis is null))
);
create index activities_project_idx on public.activities (project_id, workstream, discipline);

-- ---------------------------------------------------------------------
-- Progress entries (daily / weekly / monthly log).
-- Installed quantity = opening_qty + sum(qty_added), see activity_progress view.
-- ---------------------------------------------------------------------
create table public.progress_entries (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  activity_id   uuid not null,
  entry_date    date not null,
  period_type   text not null check (period_type in ('Daily', 'Weekly', 'Monthly')),
  qty_added     numeric(14,2) not null check (qty_added > 0),
  notes         text not null default '' check (length(notes) <= 2000),
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint progress_activity_fk foreign key (activity_id, project_id)
    references public.activities (id, project_id) on delete restrict
);
create index progress_entries_activity_idx on public.progress_entries (activity_id, entry_date);

-- ---------------------------------------------------------------------
-- BESS blocks (block-level status, replaces the name-matching in the prototype)
-- ---------------------------------------------------------------------
create table public.bess_blocks (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  block_no      integer not null check (block_no > 0),
  block_name    text not null default '' check (length(block_name) <= 100),
  status        text not null default 'Not Started'
                check (status in ('Not Started', 'In Progress', 'Installed', 'Commissioned')),
  notes         text not null default '' check (length(notes) <= 2000),
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint bess_blocks_project_block_key unique (project_id, block_no)
);

-- ---------------------------------------------------------------------
-- Schedule baseline: planned cumulative % per activity per week (Admin only).
-- ---------------------------------------------------------------------
create table public.schedule_baseline (
  id                uuid primary key default gen_random_uuid(),
  project_id        uuid not null references public.projects(id) on delete cascade,
  activity_id       uuid not null,
  baseline_version  integer not null default 1 check (baseline_version > 0),
  week_start        date not null,
  planned_cum_pct   numeric(5,2) not null check (planned_cum_pct between 0 and 100),
  is_demo           boolean not null default false,
  created_by        uuid references auth.users(id) on delete set null default auth.uid(),
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now(),
  constraint schedule_baseline_key unique (activity_id, baseline_version, week_start),
  constraint schedule_baseline_activity_fk foreign key (activity_id, project_id)
    references public.activities (id, project_id) on delete cascade
);

-- ---------------------------------------------------------------------
-- Reports (daily / weekly / monthly). Engineers create drafts; only Admins issue.
-- ---------------------------------------------------------------------
create table public.report_snapshots (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  report_type   text not null check (report_type in ('Daily', 'Weekly', 'Monthly')),
  report_date   date not null,
  period_start  date not null,
  period_end    date not null,
  title         text not null check (length(btrim(title)) between 1 and 200),
  status        text not null default 'Draft' check (status in ('Draft', 'Issued')),
  summary       jsonb not null default '{}'::jsonb,
  issued_by     uuid references auth.users(id) on delete set null,
  issued_at     timestamptz,
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint report_period_chk check (period_end >= period_start),
  constraint report_issue_stamp_chk check ((status = 'Issued') = (issued_at is not null))
);

-- ---------------------------------------------------------------------
-- QA/QC records with submit-for-review workflow.
-- Draft -> Submitted -> Approved | Rejected -> Closed (enforced in 04_workflow_audit).
-- ---------------------------------------------------------------------
create table public.qaqc_records (
  id              uuid primary key default gen_random_uuid(),
  project_id      uuid not null references public.projects(id) on delete cascade,
  ref             text not null check (length(btrim(ref)) between 1 and 60),
  record_type     text not null check (record_type in ('IR', 'ITR', 'WIR', 'NCR', 'Test Report')),
  description     text not null check (length(btrim(description)) between 1 and 2000),
  activity_id     uuid,
  record_date     date not null default current_date,
  owner           text not null default '' check (length(owner) <= 120),
  status          text not null default 'Draft'
                  check (status in ('Draft', 'Submitted', 'Approved', 'Rejected', 'Closed')),
  submitted_by    uuid references auth.users(id) on delete set null,
  submitted_at    timestamptz,
  reviewed_by     uuid references auth.users(id) on delete set null,
  reviewed_at     timestamptz,
  review_comment  text not null default '' check (length(review_comment) <= 2000),
  is_demo         boolean not null default false,
  created_by      uuid references auth.users(id) on delete set null default auth.uid(),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint qaqc_ref_project_key unique (project_id, ref),
  constraint qaqc_id_project_key unique (id, project_id),
  constraint qaqc_activity_fk foreign key (activity_id, project_id)
    references public.activities (id, project_id) on delete set null (activity_id)
);

-- ---------------------------------------------------------------------
-- HSE records
-- ---------------------------------------------------------------------
create table public.hse_records (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  record_date   date not null default current_date,
  category      text not null check (category in ('Safety Observation', 'Toolbox Talk', 'Incident', 'Inspection')),
  description   text not null check (length(btrim(description)) between 1 and 2000),
  severity      text not null default 'Not Applicable'
                check (severity in ('Low', 'Medium', 'High', 'Not Applicable')),
  status        text not null default 'Open' check (status in ('Open', 'In Progress', 'Closed')),
  owner         text not null default '' check (length(owner) <= 120),
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- Manpower: daily headcount by category (and contractor).
-- contractor = '' means direct/own staff.
-- ---------------------------------------------------------------------
create table public.manpower_daily (
  id            uuid primary key default gen_random_uuid(),
  project_id    uuid not null references public.projects(id) on delete cascade,
  log_date      date not null,
  category      text not null check (category in (
                  'Engineer', 'Supervisor', 'Technician', 'Electrician', 'Labour',
                  'QA/QC', 'HSE', 'Commissioning', 'Other')),
  contractor    text not null default '' check (length(contractor) <= 120),
  headcount     integer not null check (headcount >= 0),
  notes         text not null default '' check (length(notes) <= 2000),
  is_demo       boolean not null default false,
  created_by    uuid references auth.users(id) on delete set null default auth.uid(),
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  constraint manpower_daily_key unique (project_id, log_date, category, contractor)
);

-- ---------------------------------------------------------------------
-- Equipment register and daily equipment status
-- ---------------------------------------------------------------------
create table public.equipment (
  id              uuid primary key default gen_random_uuid(),
  project_id      uuid not null references public.projects(id) on delete cascade,
  equipment_code  text not null check (length(btrim(equipment_code)) between 1 and 40),
  description     text not null check (length(btrim(description)) between 1 and 200),
  equipment_type  text not null check (length(btrim(equipment_type)) between 1 and 80),
  area            text not null default 'Common' check (area in ('Solar PV', 'BESS', 'Common')),
  supplier        text not null default '' check (length(supplier) <= 120),
  register_status text not null default 'Active' check (register_status in ('Active', 'Inactive', 'Off Hire')),
  notes           text not null default '' check (length(notes) <= 2000),
  is_demo         boolean not null default false,
  created_by      uuid references auth.users(id) on delete set null default auth.uid(),
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  constraint equipment_code_project_key unique (project_id, equipment_code),
  constraint equipment_id_project_key unique (id, project_id)
);

create table public.equipment_daily_log (
  id               uuid primary key default gen_random_uuid(),
  project_id       uuid not null references public.projects(id) on delete cascade,
  equipment_id     uuid not null,
  log_date         date not null,
  availability     text not null check (availability in ('Available', 'Partially Available', 'Unavailable')),
  operating_status text not null check (operating_status in (
                     'Running', 'Standby', 'Idle', 'Breakdown', 'Maintenance', 'Off Hire')),
  hours_available  numeric(4,1) not null default 0 check (hours_available between 0 and 24),
  hours_used       numeric(4,1) not null default 0 check (hours_used between 0 and 24),
  notes            text not null default '' check (length(notes) <= 2000),
  is_demo          boolean not null default false,
  created_by       uuid references auth.users(id) on delete set null default auth.uid(),
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  constraint equipment_daily_key unique (equipment_id, log_date),
  constraint equipment_hours_chk check (hours_used <= hours_available),
  constraint equipment_daily_fk foreign key (equipment_id, project_id)
    references public.equipment (id, project_id) on delete cascade
);

-- ---------------------------------------------------------------------
-- Issues and risks
-- ---------------------------------------------------------------------
create table public.issues (
  id           uuid primary key default gen_random_uuid(),
  project_id   uuid not null references public.projects(id) on delete cascade,
  issue_no     integer generated always as identity (start with 1) unique,
  item_type    text not null default 'Issue' check (item_type in ('Issue', 'Risk')),
  title        text not null check (length(btrim(title)) between 1 and 200),
  description  text not null default '' check (length(description) <= 4000),
  category     text not null check (category in (
                 'Materials', 'Technical', 'Manpower', 'Equipment', 'Logistics', 'Access', 'Weather', 'Other')),
  priority     text not null check (priority in ('High', 'Medium', 'Low')),
  status       text not null default 'Open' check (status in ('Open', 'In Progress', 'Closed')),
  owner        text not null default '' check (length(owner) <= 120),
  due_date     date,
  closed_at    timestamptz,
  is_demo      boolean not null default false,
  created_by   uuid references auth.users(id) on delete set null default auth.uid(),
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- updated_at triggers
-- ---------------------------------------------------------------------
create trigger projects_updated_at before update on public.projects
  for each row execute function public.set_updated_at();
create trigger activities_updated_at before update on public.activities
  for each row execute function public.set_updated_at();
create trigger progress_entries_updated_at before update on public.progress_entries
  for each row execute function public.set_updated_at();
create trigger bess_blocks_updated_at before update on public.bess_blocks
  for each row execute function public.set_updated_at();
create trigger schedule_baseline_updated_at before update on public.schedule_baseline
  for each row execute function public.set_updated_at();
create trigger report_snapshots_updated_at before update on public.report_snapshots
  for each row execute function public.set_updated_at();
create trigger qaqc_records_updated_at before update on public.qaqc_records
  for each row execute function public.set_updated_at();
create trigger hse_records_updated_at before update on public.hse_records
  for each row execute function public.set_updated_at();
create trigger manpower_daily_updated_at before update on public.manpower_daily
  for each row execute function public.set_updated_at();
create trigger equipment_updated_at before update on public.equipment
  for each row execute function public.set_updated_at();
create trigger equipment_daily_log_updated_at before update on public.equipment_daily_log
  for each row execute function public.set_updated_at();
create trigger issues_updated_at before update on public.issues
  for each row execute function public.set_updated_at();
