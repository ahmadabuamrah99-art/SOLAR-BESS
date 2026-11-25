-- =====================================================================
-- 20261125100005_progress_views.sql
-- Progress calculations. No overall percentage is shown unless it is
-- weighted with verified weights (see activities.weight).
--
-- All views use security_invoker = true, so the caller's RLS applies.
-- =====================================================================

-- Per-activity progress. Installed = opening + logged quantity.
-- progress_pct is capped at 100 for display; installed_qty is not capped.
create or replace view public.activity_progress
with (security_invoker = true) as
select
  a.id            as activity_id,
  a.project_id,
  a.workstream,
  a.discipline,
  a.name,
  a.unit,
  a.planned_qty,
  a.opening_qty,
  a.opening_qty + coalesce(sum(p.qty_added), 0)                         as installed_qty,
  least(100, round((a.opening_qty + coalesce(sum(p.qty_added), 0))
                   / a.planned_qty * 100, 1))                           as progress_pct,
  a.planned_pct,
  a.weight,
  a.weight_basis,
  a.sort_order,
  a.is_demo
from public.activities a
left join public.progress_entries p on p.activity_id = a.id
group by a.id;

-- Progress by workstream and discipline.
-- Quantities are NOT summed across units. Only activity counts and a weighted
-- percentage are shown. weighted_progress_pct stays NULL until every activity
-- in the group has a weight on the same basis.
create or replace view public.progress_by_discipline
with (security_invoker = true) as
select
  project_id,
  workstream,
  discipline,
  count(*)                                                    as activity_count,
  count(*) filter (where progress_pct >= 100)                 as completed_activity_count,
  case
    when count(*) = count(weight) and count(distinct weight_basis) = 1
    then round(sum(progress_pct * weight) / nullif(sum(weight), 0), 1)
  end                                                         as weighted_progress_pct
from public.activity_progress
group by project_id, workstream, discipline;

-- Overall project progress. Returns NULL until all activities are weighted
-- on the same basis (Budget or Man-hours). This avoids the misleading
-- quantity-based total used in the prototype.
create or replace view public.project_progress_overview
with (security_invoker = true) as
select
  project_id,
  count(*)                                                    as activity_count,
  count(*) filter (where progress_pct >= 100)                 as completed_activity_count,
  case
    when count(*) = count(weight) and count(distinct weight_basis) = 1
    then round(sum(progress_pct * weight) / nullif(sum(weight), 0), 1)
  end                                                         as weighted_overall_pct
from public.activity_progress
group by project_id;

grant select on public.activity_progress, public.progress_by_discipline,
  public.project_progress_overview to authenticated;
revoke all on public.activity_progress, public.progress_by_discipline,
  public.project_progress_overview from anon;
