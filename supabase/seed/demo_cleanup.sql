-- =====================================================================
-- demo_cleanup.sql  (ADMIN ONLY, run in the SQL editor, NOT yet approved to run)
--
-- Deletes ONLY rows flagged is_demo = true. Review the row counts it prints,
-- then run the delete section. Do not run it until verified project data is in place.
-- =====================================================================

-- 1. Preview: how many demo rows exist per table.
select 'projects' as table_name, count(*) from public.projects where is_demo
union all select 'activities', count(*) from public.activities where is_demo
union all select 'progress_entries', count(*) from public.progress_entries where is_demo
union all select 'bess_blocks', count(*) from public.bess_blocks where is_demo
union all select 'schedule_baseline', count(*) from public.schedule_baseline where is_demo
union all select 'report_snapshots', count(*) from public.report_snapshots where is_demo
union all select 'qaqc_records', count(*) from public.qaqc_records where is_demo
union all select 'hse_records', count(*) from public.hse_records where is_demo
union all select 'manpower_daily', count(*) from public.manpower_daily where is_demo
union all select 'equipment', count(*) from public.equipment where is_demo
union all select 'equipment_daily_log', count(*) from public.equipment_daily_log where is_demo
union all select 'issues', count(*) from public.issues where is_demo;

-- 2. Delete (uncomment only after review and approval).
-- begin;
-- delete from public.equipment_daily_log where is_demo;
-- delete from public.equipment where is_demo;
-- delete from public.issues where is_demo;
-- delete from public.hse_records where is_demo;
-- delete from public.manpower_daily where is_demo;
-- delete from public.qaqc_records where is_demo;
-- delete from public.report_snapshots where is_demo;
-- delete from public.schedule_baseline where is_demo;
-- delete from public.progress_entries where is_demo;
-- delete from public.bess_blocks where is_demo;
-- delete from public.activities where is_demo;
-- delete from public.projects where is_demo;
-- commit;
