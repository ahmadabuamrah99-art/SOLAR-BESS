-- =====================================================================
-- 01_rls_security_tests.sql
-- RLS and workflow security tests.
--
-- SAFETY: this file inserts TEST users into auth.users and TEST rows into
-- the project. Run it ONLY on a local or disposable database, never on the
-- production Supabase project. Everything runs inside one transaction and
-- is rolled back at the end, so no test data is kept.
--
-- Run with:  psql <local-connection-string> -v ON_ERROR_STOP=1 -f 01_rls_security_tests.sql
-- Any failing check stops the run with "FAIL ...".
-- =====================================================================

\set ON_ERROR_STOP on
begin;

-- ---------------------------------------------------------------------
-- Test helpers (live in a temporary schema that is dropped at the end)
-- ---------------------------------------------------------------------
create schema rls_test;
grant usage on schema rls_test to anon, authenticated, service_role;

-- Act as a signed-in user, as PostgREST/Supabase does for a JWT with this sub.
create function rls_test.as_user(p_uid uuid) returns void
language plpgsql as $$
begin
  perform set_config('request.jwt.claims',
    json_build_object('sub', p_uid, 'role', 'authenticated')::text, true);
  execute 'set local role authenticated';
end $$;

create function rls_test.as_anon() returns void
language plpgsql as $$
begin
  perform set_config('request.jwt.claims', '', true);
  execute 'set local role anon';
end $$;

create function rls_test.as_postgres() returns void
language plpgsql as $$
begin
  execute 'reset role';
  perform set_config('request.jwt.claims', '', true);
end $$;

-- The Edge Function's role (bypasses RLS, used for rate-limit storage).
create function rls_test.as_service() returns void
language plpgsql as $$
begin
  execute 'reset role';
  execute 'set local role service_role';
end $$;

-- Statement must be DENIED (privilege, RLS, workflow or check constraint).
create function rls_test.expect_denied(p_label text, p_sql text) returns void
language plpgsql as $$
declare
  allowed boolean := false;
begin
  begin
    execute p_sql;
    allowed := true;
  exception when sqlstate '42501' or sqlstate 'P0001' or sqlstate '23514' or sqlstate '23505' then
    raise notice 'PASS %: denied (%)', p_label, sqlerrm;
    return;
  end;
  if allowed then
    raise exception 'FAIL %: statement was ALLOWED but must be denied', p_label;
  end if;
end $$;

-- DML must affect exactly p_expected rows (0 = silently filtered by RLS).
create function rls_test.expect_rows(p_label text, p_sql text, p_expected integer) returns void
language plpgsql as $$
declare n integer;
begin
  execute p_sql;
  get diagnostics n = row_count;
  if n <> p_expected then
    raise exception 'FAIL %: expected % row(s), got %', p_label, p_expected, n;
  end if;
  raise notice 'PASS %: % row(s)', p_label, n;
end $$;

-- Compare two text values.
create function rls_test.assert_eq(p_label text, p_actual text, p_expected text) returns void
language plpgsql as $$
begin
  if p_actual is distinct from p_expected then
    raise exception 'FAIL %: expected [%], got [%]', p_label, p_expected, p_actual;
  end if;
  raise notice 'PASS %: %', p_label, p_actual;
end $$;

grant execute on all functions in schema rls_test to anon, authenticated, service_role;

-- ---------------------------------------------------------------------
-- Fixtures (as postgres: bypasses RLS and workflow guards on purpose)
-- ---------------------------------------------------------------------
select rls_test.as_postgres();

-- Users. Metadata claims role = admin; the signup trigger must ignore it.
insert into auth.users (id, email, raw_user_meta_data) values
  ('00000000-0000-0000-0000-000000000001', 'admin@test.local',    '{"full_name":"Test Admin","role":"admin"}'),
  ('00000000-0000-0000-0000-000000000002', 'engineer@test.local', '{"full_name":"Test Engineer"}'),
  ('00000000-0000-0000-0000-000000000003', 'viewer@test.local',   '{"full_name":"Test Viewer"}'),
  ('00000000-0000-0000-0000-000000000004', 'inactive@test.local', '{"full_name":"Test Inactive"}');

select rls_test.assert_eq('T70 signup ignores metadata role',
  (select role from public.profiles where id = '00000000-0000-0000-0000-000000000001'), 'viewer');
select rls_test.assert_eq('T71 signup profile is active',
  (select is_active::text from public.profiles where id = '00000000-0000-0000-0000-000000000001'), 'true');

update public.profiles set role = 'admin'    where id = '00000000-0000-0000-0000-000000000001';
update public.profiles set role = 'engineer' where id = '00000000-0000-0000-0000-000000000002';
update public.profiles set is_active = false where id = '00000000-0000-0000-0000-000000000004';

-- Project (demo, capacities unknown) and two activities.
insert into public.projects (id, name, is_demo) values
  ('11111111-1111-4111-8111-111111111111', 'TEST project', true);
insert into public.activities (id, project_id, workstream, discipline, name, unit, planned_qty, opening_qty, is_demo) values
  ('22222222-2222-4222-8222-222222222221', '11111111-1111-4111-8111-111111111111',
   'Solar PV', 'Mechanical', 'TEST piling', 'Piles', 1000, 500, true),
  ('22222222-2222-4222-8222-222222222222', '11111111-1111-4111-8111-111111111111',
   'BESS', 'Electrical', 'TEST PCS', 'Units', 10, 0, true);
insert into public.progress_entries (project_id, activity_id, entry_date, period_type, qty_added, created_by) values
  ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221',
   '2026-11-20', 'Daily', 100, '00000000-0000-0000-0000-000000000001');
-- Existing QA/QC records (IR-001 already submitted, IR-002 draft).
insert into public.qaqc_records (id, project_id, ref, record_type, description, status) values
  ('44444444-4444-4444-8444-444444444441', '11111111-1111-4111-8111-111111111111', 'IR-001', 'IR', 'TEST pile IR', 'Submitted'),
  ('44444444-4444-4444-8444-444444444442', '11111111-1111-4111-8111-111111111111', 'IR-002', 'IR', 'TEST draft IR', 'Draft');
insert into public.report_snapshots (project_id, report_type, report_date, period_start, period_end, title) values
  ('11111111-1111-4111-8111-111111111111', 'Daily', '2026-11-20', '2026-11-20', '2026-11-20', 'TEST seed report');

-- Helpers for test users
-- A1 admin, E2 engineer, V3 viewer, I4 inactive.

-- ---------------------------------------------------------------------
-- Anonymous (no login)
-- ---------------------------------------------------------------------
select rls_test.as_anon();
select rls_test.expect_denied('T01 anon cannot read projects', 'select 1 from public.projects');
select rls_test.expect_denied('T01b anon cannot insert progress',
  $$insert into public.progress_entries (project_id, activity_id, entry_date, period_type, qty_added)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221', current_date, 'Daily', 1)$$);

-- ---------------------------------------------------------------------
-- Inactive user: no access at all
-- ---------------------------------------------------------------------
select rls_test.as_user('00000000-0000-0000-0000-000000000004');
select rls_test.assert_eq('T60 inactive user sees 0 projects', (select count(*)::text from public.projects where id = '11111111-1111-4111-8111-111111111111'), '0');
select rls_test.expect_denied('T61 inactive user cannot insert progress',
  $$insert into public.progress_entries (project_id, activity_id, entry_date, period_type, qty_added)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221', current_date, 'Daily', 1)$$);

-- ---------------------------------------------------------------------
-- Viewer: read-only
-- ---------------------------------------------------------------------
select rls_test.as_user('00000000-0000-0000-0000-000000000003');
select rls_test.assert_eq('T02 viewer sees project', (select count(*)::text from public.projects where id = '11111111-1111-4111-8111-111111111111'), '1');
select rls_test.assert_eq('T03 viewer sees progress view rows', (select count(*)::text from public.activity_progress where project_id = '11111111-1111-4111-8111-111111111111'), '2');
select rls_test.assert_eq('T09 viewer sees QA/QC records', (select count(*)::text from public.qaqc_records where project_id = '11111111-1111-4111-8111-111111111111'), '2');
select rls_test.expect_denied('T04 viewer cannot insert progress',
  $$insert into public.progress_entries (project_id, activity_id, entry_date, period_type, qty_added)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221', current_date, 'Daily', 1)$$);
select rls_test.expect_rows('T05 viewer cannot update baseline quantity',
  $$update public.activities set planned_qty = 2000 where id = '22222222-2222-4222-8222-222222222221'$$, 0);
select rls_test.expect_rows('T06 viewer cannot delete QA/QC',
  $$delete from public.qaqc_records$$, 0);
select rls_test.expect_denied('T08 viewer cannot insert manpower',
  $$insert into public.manpower_daily (project_id, log_date, category, headcount)
    values ('11111111-1111-4111-8111-111111111111', current_date, 'Labour', 5)$$);
select rls_test.assert_eq('T07 viewer cannot read audit log', (select count(*)::text from public.audit_log), '0');
select rls_test.expect_denied('T07b viewer cannot write audit log',
  $$insert into public.audit_log (table_name, action) values ('x', 'INSERT')$$);

-- ---------------------------------------------------------------------
-- Engineer: operational writes, QA/QC submission, no baseline or approval
-- ---------------------------------------------------------------------
select rls_test.as_user('00000000-0000-0000-0000-000000000002');

-- Progress: allowed; spoofed created_by is overwritten by the trigger.
select rls_test.expect_rows('T10 engineer logs progress',
  $$insert into public.progress_entries (project_id, activity_id, entry_date, period_type, qty_added, created_by)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221',
            '2026-11-21', 'Daily', 50, '00000000-0000-0000-0000-000000000001')$$, 1);
select rls_test.assert_eq('T11 spoofed created_by is replaced by caller',
  (select created_by::text from public.progress_entries where entry_date = '2026-11-21'),
  '00000000-0000-0000-0000-000000000002');

select rls_test.expect_rows('T12 engineer cannot change baseline quantity',
  $$update public.activities set planned_qty = 2000 where id = '22222222-2222-4222-8222-222222222221'$$, 0);
select rls_test.expect_denied('T13 engineer cannot create project',
  $$insert into public.projects (name) values ('rogue')$$);
select rls_test.expect_denied('T14 engineer cannot set schedule baseline',
  $$insert into public.schedule_baseline (project_id, activity_id, week_start, planned_cum_pct)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221', '2026-12-07', 10)$$);
select rls_test.expect_rows('T14b engineer cannot delete progress',
  $$delete from public.progress_entries$$, 0);

-- QA/QC: create draft, submit, cannot approve.
select rls_test.expect_rows('T15 engineer creates QA/QC draft',
  $$insert into public.qaqc_records (project_id, ref, record_type, description)
    values ('11111111-1111-4111-8111-111111111111', 'IR-010', 'IR', 'TEST new IR')$$, 1);
select rls_test.expect_denied('T16 engineer cannot create record as Approved',
  $$insert into public.qaqc_records (project_id, ref, record_type, description, status)
    values ('11111111-1111-4111-8111-111111111111', 'IR-011', 'IR', 'TEST', 'Approved')$$);
select rls_test.expect_rows('T17 engineer submits own draft',
  $$update public.qaqc_records set status = 'Submitted' where ref = 'IR-010'$$, 1);
select rls_test.assert_eq('T17b submission stamped with engineer',
  (select submitted_by::text from public.qaqc_records where ref = 'IR-010'),
  '00000000-0000-0000-0000-000000000002');
select rls_test.expect_rows('T18 engineer cannot edit a Submitted record',
  $$update public.qaqc_records set description = 'changed' where ref = 'IR-001'$$, 0);
select rls_test.expect_denied('T19 engineer cannot set review fields',
  $$update public.qaqc_records set review_comment = 'approved by me' where ref = 'IR-002'$$);
select rls_test.expect_denied('T20 engineer cannot jump Draft to Approved',
  $$update public.qaqc_records set status = 'Approved' where ref = 'IR-002'$$);
select rls_test.expect_rows('T21 engineer cannot delete QA/QC',
  $$delete from public.qaqc_records$$, 0);

-- Reports: draft only.
select rls_test.expect_rows('T22 engineer creates report draft',
  $$insert into public.report_snapshots (project_id, report_type, report_date, period_start, period_end, title)
    values ('11111111-1111-4111-8111-111111111111', 'Weekly', '2026-11-22', '2026-11-16', '2026-11-22', 'TEST weekly')$$, 1);
select rls_test.expect_denied('T23 engineer cannot issue a report',
  $$update public.report_snapshots set status = 'Issued' where title = 'TEST weekly'$$);

-- Accounts: cannot escalate own role.
select rls_test.expect_denied('T24 engineer cannot promote self to admin',
  $$update public.profiles set role = 'admin' where id = '00000000-0000-0000-0000-000000000002'$$);
select rls_test.expect_rows('T25 engineer can rename self',
  $$update public.profiles set full_name = 'Test Engineer 2' where id = '00000000-0000-0000-0000-000000000002'$$, 1);
select rls_test.expect_rows('T26 engineer cannot change viewer role',
  $$update public.profiles set role = 'admin' where id = '00000000-0000-0000-0000-000000000003'$$, 0);

-- Data validation through check constraints.
select rls_test.expect_denied('T28 negative manpower rejected',
  $$insert into public.manpower_daily (project_id, log_date, category, headcount)
    values ('11111111-1111-4111-8111-111111111111', '2026-11-21', 'Labour', -1)$$);
-- Equipment: engineers register and update, not delete.
select rls_test.expect_rows('T29 engineer registers equipment',
  $$insert into public.equipment (project_id, equipment_code, description, equipment_type)
    values ('11111111-1111-4111-8111-111111111111', 'EX-001', 'TEST excavator', 'Excavator')$$, 1);
select rls_test.expect_rows('T29b engineer logs equipment day',
  $$insert into public.equipment_daily_log (project_id, equipment_id, log_date, availability, operating_status, hours_available, hours_used)
    select '11111111-1111-4111-8111-111111111111', e.id, '2026-11-21', 'Available', 'Running', 8, 6
    from public.equipment e where e.equipment_code = 'EX-001'$$, 1);
select rls_test.expect_denied('T30 equipment hours used > available rejected',
  $$insert into public.equipment_daily_log (project_id, equipment_id, log_date, availability, operating_status, hours_available, hours_used)
    select '11111111-1111-4111-8111-111111111111', e.id, '2026-11-22', 'Available', 'Running', 8, 9
    from public.equipment e where e.equipment_code = 'EX-001'$$);
select rls_test.expect_rows('T29c engineer cannot delete equipment',
  $$delete from public.equipment$$, 0);

select rls_test.expect_rows('T29d engineer logs issue',
  $$insert into public.issues (project_id, title, category, priority)
    values ('11111111-1111-4111-8111-111111111111', 'TEST crane delay', 'Equipment', 'High')$$, 1);

select rls_test.assert_eq('T31 engineer cannot read audit log', (select count(*)::text from public.audit_log), '0');

-- ---------------------------------------------------------------------
-- Admin: baseline, approval, issue, user management, audit
-- ---------------------------------------------------------------------
select rls_test.as_user('00000000-0000-0000-0000-000000000001');

select rls_test.expect_rows('T40 admin approves submitted QA/QC',
  $$update public.qaqc_records set status = 'Approved' where ref = 'IR-001'$$, 1);
select rls_test.assert_eq('T40b approval stamped with admin',
  (select reviewed_by::text from public.qaqc_records where ref = 'IR-001'),
  '00000000-0000-0000-0000-000000000001');
select rls_test.expect_denied('T41 approved record cannot go back to Draft',
  $$update public.qaqc_records set status = 'Draft' where ref = 'IR-001'$$);
select rls_test.expect_rows('T42 admin closes approved record',
  $$update public.qaqc_records set status = 'Closed' where ref = 'IR-001'$$, 1);

select rls_test.expect_rows('T43 admin updates baseline',
  $$update public.activities set opening_qty = 500 where id = '22222222-2222-4222-8222-222222222221'$$, 1);
select rls_test.expect_rows('T44 admin sets schedule baseline',
  $$insert into public.schedule_baseline (project_id, activity_id, week_start, planned_cum_pct)
    values ('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222221', '2026-12-07', 10)$$, 1);
select rls_test.expect_rows('T45 admin changes viewer role',
  $$update public.profiles set role = 'engineer' where id = '00000000-0000-0000-0000-000000000003'$$, 1);

select rls_test.expect_rows('T50 admin cannot change created_by of a log row',
  $$update public.progress_entries set created_by = '00000000-0000-0000-0000-000000000003' where entry_date = '2026-11-21'$$, 1);
select rls_test.assert_eq('T50b created_by unchanged after update',
  (select created_by::text from public.progress_entries where entry_date = '2026-11-21'),
  '00000000-0000-0000-0000-000000000002');

select rls_test.expect_rows('T48 admin issues report',
  $$update public.report_snapshots set status = 'Issued' where title = 'TEST weekly'$$, 1);
select rls_test.expect_denied('T49 issued report cannot be reopened',
  $$update public.report_snapshots set status = 'Draft' where title = 'TEST weekly'$$);

select rls_test.assert_eq('T46 admin sees audit trail for baseline change',
  (select (count(*) > 0)::text from public.audit_log
    where table_name = 'activities' and actor_id = '00000000-0000-0000-0000-000000000001'),
  'true');
select rls_test.expect_denied('T47 nobody can edit the audit log',
  $$update public.audit_log set action = 'INSERT'$$);

-- Workflow: issues closed_at maintained by database.
select rls_test.expect_rows('T51 admin closes issue',
  $$update public.issues set status = 'Closed' where title = 'TEST crane delay'$$, 1);
select rls_test.assert_eq('T51b closed_at set',
  (select (closed_at is not null)::text from public.issues where title = 'TEST crane delay'), 'true');

-- Weighted progress: null until weights exist, then computed only for one basis.
select rls_test.assert_eq('T80 overall progress null without weights',
  (select coalesce(weighted_overall_pct::text, 'NULL') from public.project_progress_overview
    where project_id = '11111111-1111-4111-8111-111111111111'), 'NULL');

select rls_test.expect_rows('T81 admin sets Budget weights',
  $$update public.activities set weight = 2, weight_basis = 'Budget'
    where project_id = '11111111-1111-4111-8111-111111111111'$$, 2);
-- Installed: piling 500 + 100 + 50 = 650 of 1000 -> 65.0%; PCS 0 of 10 -> 0.0%.
-- Equal weights 2 and 2: (65.0*2 + 0.0*2) / 4 = 32.5
select rls_test.assert_eq('T82 weighted overall progress',
  (select weighted_overall_pct::text from public.project_progress_overview
    where project_id = '11111111-1111-4111-8111-111111111111'), '32.5');
select rls_test.assert_eq('T83 installed quantity includes opening and logs',
  (select installed_qty::text from public.activity_progress
    where activity_id = '22222222-2222-4222-8222-222222222221'), '650.00');

select rls_test.expect_rows('T84 mixed weight basis disables overall',
  $$update public.activities set weight_basis = 'Man-hours' where id = '22222222-2222-4222-8222-222222222222'$$, 1);
select rls_test.assert_eq('T85 overall null with mixed basis',
  (select coalesce(weighted_overall_pct::text, 'NULL') from public.project_progress_overview
    where project_id = '11111111-1111-4111-8111-111111111111'), 'NULL');

-- ---------------------------------------------------------------------
-- Last-Admin protection (runs last: admin A is the only active Admin here)
-- ---------------------------------------------------------------------
select rls_test.expect_denied('T90 last admin cannot demote self',
  $$update public.profiles set role = 'viewer' where id = '00000000-0000-0000-0000-000000000001'$$);
select rls_test.expect_denied('T91 last admin cannot deactivate self',
  $$update public.profiles set is_active = false where id = '00000000-0000-0000-0000-000000000001'$$);
select rls_test.expect_rows('T92 admin promotes engineer to admin',
  $$update public.profiles set role = 'admin' where id = '00000000-0000-0000-0000-000000000002'$$, 1);
select rls_test.expect_rows('T93 admin may demote self when another active admin exists',
  $$update public.profiles set role = 'viewer' where id = '00000000-0000-0000-0000-000000000001'$$, 1);

select rls_test.as_user('00000000-0000-0000-0000-000000000002');
select rls_test.expect_denied('T94 new last admin cannot demote self',
  $$update public.profiles set role = 'engineer' where id = '00000000-0000-0000-0000-000000000002'$$);

-- Same rule on the SQL-editor / postgres path (the invariant lives in the database).
select rls_test.as_postgres();
select rls_test.expect_denied('T95 last admin cannot be deactivated via SQL path',
  $$update public.profiles set is_active = false where id = '00000000-0000-0000-0000-000000000002'$$);
select rls_test.expect_denied('T96 last admin profile cannot be removed by auth.users delete',
  $$delete from auth.users where id = '00000000-0000-0000-0000-000000000002'$$);

-- ---------------------------------------------------------------------
-- Username support (migration 20261126100007). Admin here: E (...02).
-- ---------------------------------------------------------------------
select rls_test.as_postgres();
update auth.users set encrypted_password = 'test-hash-admin' where id = '00000000-0000-0000-0000-000000000001';
create table rls_test.pw_before as
  select encrypted_password from auth.users where id = '00000000-0000-0000-0000-000000000001';

select rls_test.as_user('00000000-0000-0000-0000-000000000003');
select rls_test.expect_denied('U01 engineer cannot set own username',
  $$update public.profiles set username = 'eng_self' where id = '00000000-0000-0000-0000-000000000003'$$);

select rls_test.as_user('00000000-0000-0000-0000-000000000001');
select rls_test.expect_denied('U02 viewer cannot set own username',
  $$update public.profiles set username = 'viewer_self' where id = '00000000-0000-0000-0000-000000000001'$$);

select rls_test.as_user('00000000-0000-0000-0000-000000000002');
select rls_test.expect_rows('U03 admin sets username baomahun_soventix',
  $$update public.profiles set username = 'baomahun_soventix' where id = '00000000-0000-0000-0000-000000000001'$$, 1);
select rls_test.expect_denied('U04 uppercase username rejected',
  $$update public.profiles set username = 'Engineer_One' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_denied('U05 username shorter than 3 characters rejected',
  $$update public.profiles set username = 'ab' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_denied('U06 username starting with a digit rejected',
  $$update public.profiles set username = '1engineer' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_denied('U07 username with a space rejected',
  $$update public.profiles set username = 'eng one' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_denied('U08 username longer than 30 characters rejected',
  $$update public.profiles set username = 'a_very_long_username_that_is_too_long' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_denied('U09 duplicate username rejected (unique)',
  $$update public.profiles set username = 'baomahun_soventix' where id = '00000000-0000-0000-0000-000000000003'$$);
select rls_test.expect_rows('U10 admin sets a second, different username',
  $$update public.profiles set username = 'engineer_one' where id = '00000000-0000-0000-0000-000000000003'$$, 1);
select rls_test.assert_eq('U11 admin role unchanged after username change',
  (select role from public.profiles where id = '00000000-0000-0000-0000-000000000002'), 'admin');

-- Rate-limit table: no access for clients at all.
select rls_test.as_user('00000000-0000-0000-0000-000000000002');
select rls_test.expect_denied('U12 signed-in admin cannot read login attempts',
  $$select count(*) from public.auth_login_attempts$$);
select rls_test.expect_denied('U13 signed-in admin cannot write login attempts',
  $$insert into public.auth_login_attempts (key_hash) values (repeat('a', 64))$$);
select rls_test.as_anon();
select rls_test.expect_denied('U14 anonymous cannot read login attempts',
  $$select count(*) from public.auth_login_attempts$$);

-- The Edge Function's role can read, write and clear its own records.
select rls_test.as_service();
select rls_test.expect_rows('U15 service role records a failure',
  $$insert into public.auth_login_attempts (key_hash) values (repeat('b', 64))$$, 1);
select rls_test.assert_eq('U16 service role counts the failure',
  (select count(*)::text from public.auth_login_attempts where key_hash = repeat('b', 64)), '1');
select rls_test.expect_rows('U17 service role clears a username counter',
  $$delete from public.auth_login_attempts where key_hash = repeat('b', 64)$$, 1);

-- Username visible to other signed-in users (for display), password hash untouched.
select rls_test.as_user('00000000-0000-0000-0000-000000000003');
select rls_test.assert_eq('U18 signed-in user can read usernames',
  (select count(*)::text from public.profiles where username = 'baomahun_soventix'), '1');
select rls_test.as_postgres();
select rls_test.assert_eq('U19 password hash unchanged by username change',
  (select (encrypted_password = 'test-hash-admin')::text from auth.users where id = '00000000-0000-0000-0000-000000000001'), 'true');

-- ---------------------------------------------------------------------
-- Cleanup: discard all test data and helpers
-- ---------------------------------------------------------------------
select rls_test.as_postgres();
rollback;

-- rollback removes the fixtures above, including the rls_test schema.
-- A passing run ends with the NOTICE lines above and no FAIL.
