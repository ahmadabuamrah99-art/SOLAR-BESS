-- =====================================================================
-- 20261125100004_workflow_audit.sql
-- Row-level workflow rules, ownership protection and the audit log.
--
-- Rules apply to API clients (current_user = 'authenticated' or 'anon').
-- Migrations and SQL-editor work run as 'postgres' and skip these checks.
-- That path is for admin maintenance only and must not be exposed to clients.
-- =====================================================================

-- ---------------------------------------------------------------------
-- A. Ownership: clients cannot change created_by, created_at, project_id or is_demo,
--    and cannot set is_demo = true on insert.
-- ---------------------------------------------------------------------
create or replace function public.guard_owned_row()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user not in ('anon', 'authenticated') then
    return new;
  end if;

  if tg_op = 'INSERT' then
    new.created_by := (select auth.uid());
    new.created_at := now();
    new.is_demo   := false;
  else
    new.created_by := old.created_by;
    new.created_at := old.created_at;
    new.project_id := old.project_id;
    new.is_demo   := old.is_demo;
  end if;
  return new;
end;
$$;

create or replace function public.guard_project_row()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user not in ('anon', 'authenticated') then
    return new;
  end if;

  if tg_op = 'INSERT' then
    new.created_by := (select auth.uid());
    new.created_at := now();
    new.is_demo   := false;
  else
    new.created_by := old.created_by;
    new.created_at := old.created_at;
    new.is_demo   := old.is_demo;
  end if;
  return new;
end;
$$;

create trigger projects_guard before insert or update on public.projects
  for each row execute function public.guard_project_row();
create trigger activities_guard before insert or update on public.activities
  for each row execute function public.guard_owned_row();
create trigger progress_entries_guard before insert or update on public.progress_entries
  for each row execute function public.guard_owned_row();
create trigger bess_blocks_guard before insert or update on public.bess_blocks
  for each row execute function public.guard_owned_row();
create trigger schedule_baseline_guard before insert or update on public.schedule_baseline
  for each row execute function public.guard_owned_row();
create trigger hse_records_guard before insert or update on public.hse_records
  for each row execute function public.guard_owned_row();
create trigger manpower_daily_guard before insert or update on public.manpower_daily
  for each row execute function public.guard_owned_row();
create trigger equipment_guard before insert or update on public.equipment
  for each row execute function public.guard_owned_row();
create trigger equipment_daily_log_guard before insert or update on public.equipment_daily_log
  for each row execute function public.guard_owned_row();
create trigger issues_guard before insert or update on public.issues
  for each row execute function public.guard_owned_row();
create trigger qaqc_records_guard_owner before insert or update on public.qaqc_records
  for each row execute function public.guard_owned_row();
create trigger report_snapshots_guard_owner before insert or update on public.report_snapshots
  for each row execute function public.guard_owned_row();

-- ---------------------------------------------------------------------
-- B. QA/QC workflow.
--    Draft -> Submitted            Engineer or Admin
--    Submitted -> Draft           Engineer or Admin (withdraw)
--    Rejected -> Draft | Submitted Engineer or Admin
--    Submitted -> Approved | Rejected   Admin only
--    Approved | Rejected -> Closed      Admin only
--    Submission and review stamps are set by the system only.
-- ---------------------------------------------------------------------
create or replace function public.guard_qaqc_record()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  is_client boolean := current_user in ('anon', 'authenticated');
  admin_user boolean;
begin
  if not is_client then
    return new;
  end if;
  admin_user := public.is_admin();

  if tg_op = 'INSERT' then
    if new.status not in ('Draft', 'Submitted') then
      raise exception 'New QA/QC records must be created as Draft or Submitted'
        using errcode = 'P0001';
    end if;
    if not admin_user and (new.reviewed_by is not null or new.reviewed_at is not null
                           or new.review_comment <> '') then
      raise exception 'Review fields are set only by an Admin' using errcode = '42501';
    end if;
    new.reviewed_by := null;
    new.reviewed_at := null;
    if new.status = 'Submitted' then
      new.submitted_by := (select auth.uid());
      new.submitted_at := now();
    else
      new.submitted_by := null;
      new.submitted_at := null;
    end if;
    return new;
  end if;

  -- UPDATE
  if not admin_user then
    if new.submitted_by is distinct from old.submitted_by
       or new.submitted_at is distinct from old.submitted_at
       or new.reviewed_by is distinct from old.reviewed_by
       or new.reviewed_at is distinct from old.reviewed_at
       or new.review_comment is distinct from old.review_comment then
      raise exception 'Submission and review fields are managed by the system'
        using errcode = '42501';
    end if;
    if old.status in ('Submitted', 'Approved', 'Closed') and new.status = old.status then
      raise exception 'QA/QC record is locked while in status %', old.status
        using errcode = '42501';
    end if;
  end if;

  if new.status is distinct from old.status then
    if (old.status, new.status) in (
         ('Draft', 'Submitted'), ('Submitted', 'Draft'),
         ('Rejected', 'Draft'), ('Rejected', 'Submitted')) then
      null; -- writer transitions (RLS already limits Engineers)
    elsif (old.status, new.status) in (
         ('Submitted', 'Approved'), ('Submitted', 'Rejected'),
         ('Approved', 'Closed'), ('Rejected', 'Closed')) then
      if not admin_user then
        raise exception 'Only an Admin can approve, reject or close QA/QC records'
          using errcode = '42501';
      end if;
    else
      raise exception 'Invalid QA/QC status change from % to %', old.status, new.status
        using errcode = 'P0001';
    end if;

    if new.status = 'Submitted' then
      new.submitted_by := (select auth.uid());
      new.submitted_at := now();
    elsif new.status in ('Approved', 'Rejected') then
      new.reviewed_by := (select auth.uid());
      new.reviewed_at := now();
    end if;
  end if;

  return new;
end;
$$;

create trigger qaqc_records_workflow before insert or update on public.qaqc_records
  for each row execute function public.guard_qaqc_record();

-- ---------------------------------------------------------------------
-- C. Reports: only Admin issues. Issued reports are locked and cannot be reopened.
-- ---------------------------------------------------------------------
create or replace function public.guard_report_snapshot()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  is_client boolean := current_user in ('anon', 'authenticated');
  admin_user boolean;
begin
  if not is_client then
    return new;
  end if;
  admin_user := public.is_admin();

  if tg_op = 'UPDATE' and old.status = 'Issued' then
    raise exception 'Issued reports are locked and cannot be changed or reopened'
      using errcode = 'P0001';
  end if;

  if new.status = 'Issued' then
    if not admin_user then
      raise exception 'Only an Admin can issue reports' using errcode = '42501';
    end if;
    new.issued_by := (select auth.uid());
    new.issued_at := now();
  else
    new.issued_by := null;
    new.issued_at := null;
  end if;
  return new;
end;
$$;

create trigger report_snapshots_workflow before insert or update on public.report_snapshots
  for each row execute function public.guard_report_snapshot();

-- ---------------------------------------------------------------------
-- D. Issues: closed_at is maintained by the database.
-- ---------------------------------------------------------------------
create or replace function public.set_issue_closed_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.closed_at := case
    when new.status = 'Closed' then
      coalesce(case when tg_op = 'UPDATE' and old.status = 'Closed' then old.closed_at end, now())
    else null
  end;
  return new;
end;
$$;

create trigger issues_closed_at before insert or update on public.issues
  for each row execute function public.set_issue_closed_at();

-- ---------------------------------------------------------------------
-- E. Audit log: append-only record of every change to business tables.
--    Written by a SECURITY DEFINER trigger. Clients cannot write, update or delete it.
--    Only Admins can read it.
-- ---------------------------------------------------------------------
create table public.audit_log (
  id          bigint generated always as identity primary key,
  table_name  text not null,
  record_id   uuid,
  action      text not null check (action in ('INSERT', 'UPDATE', 'DELETE')),
  actor_id    uuid,
  actor_role  text,
  old_data    jsonb,
  new_data    jsonb,
  changed_at  timestamptz not null default now()
);
create index audit_log_record_idx on public.audit_log (table_name, record_id, changed_at);

create or replace function public.write_audit_log()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.audit_log (table_name, record_id, action, actor_id, actor_role, old_data, new_data)
  values (
    tg_table_name,
    coalesce((to_jsonb(new) ->> 'id'), (to_jsonb(old) ->> 'id'))::uuid,
    tg_op,
    (select auth.uid()),
    public.app_role(),
    case when tg_op <> 'INSERT' then to_jsonb(old) end,
    case when tg_op <> 'DELETE' then to_jsonb(new) end
  );
  return coalesce(new, old);
end;
$$;

revoke execute on function public.write_audit_log() from public, anon, authenticated;

create trigger projects_audit after insert or update or delete on public.projects
  for each row execute function public.write_audit_log();
create trigger profiles_audit after insert or update or delete on public.profiles
  for each row execute function public.write_audit_log();
create trigger activities_audit after insert or update or delete on public.activities
  for each row execute function public.write_audit_log();
create trigger progress_entries_audit after insert or update or delete on public.progress_entries
  for each row execute function public.write_audit_log();
create trigger bess_blocks_audit after insert or update or delete on public.bess_blocks
  for each row execute function public.write_audit_log();
create trigger schedule_baseline_audit after insert or update or delete on public.schedule_baseline
  for each row execute function public.write_audit_log();
create trigger report_snapshots_audit after insert or update or delete on public.report_snapshots
  for each row execute function public.write_audit_log();
create trigger qaqc_records_audit after insert or update or delete on public.qaqc_records
  for each row execute function public.write_audit_log();
create trigger hse_records_audit after insert or update or delete on public.hse_records
  for each row execute function public.write_audit_log();
create trigger manpower_daily_audit after insert or update or delete on public.manpower_daily
  for each row execute function public.write_audit_log();
create trigger equipment_audit after insert or update or delete on public.equipment
  for each row execute function public.write_audit_log();
create trigger equipment_daily_log_audit after insert or update or delete on public.equipment_daily_log
  for each row execute function public.write_audit_log();
create trigger issues_audit after insert or update or delete on public.issues
  for each row execute function public.write_audit_log();

alter table public.audit_log enable row level security;

-- Admins read; nobody writes through the API.
create policy audit_log_select_admin on public.audit_log
  for select to authenticated using (public.is_admin());

revoke all on public.audit_log from anon, authenticated;
grant select on public.audit_log to authenticated;
