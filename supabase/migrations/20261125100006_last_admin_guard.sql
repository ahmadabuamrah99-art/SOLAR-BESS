-- =====================================================================
-- 20261125100006_last_admin_guard.sql
-- Always keep at least one active Admin.
--
-- Blocks any change that would leave zero active Admins:
--   * demoting an active Admin (role changed away from 'admin')
--   * deactivating an active Admin (is_active = false)
--   * deleting an active Admin's profile (including cascade from auth.users)
--
-- This applies to every path, including the SQL editor, so the database itself
-- keeps the invariant. An advisory lock serializes concurrent changes so two
-- Admins cannot demote each other at the same moment.
-- =====================================================================

create or replace function public.guard_last_admin()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  other_active_admins integer;
begin
  if tg_op = 'UPDATE'
     and old.role = 'admin' and old.is_active
     and (new.role <> 'admin' or not new.is_active) then
    null; -- fall through to the count check
  elsif tg_op = 'DELETE' and old.role = 'admin' and old.is_active then
    null;
  else
    return case when tg_op = 'DELETE' then old else new end;
  end if;

  perform pg_advisory_xact_lock(hashtext('greengrid_last_admin_guard'));

  select count(*) into other_active_admins
  from public.profiles
  where role = 'admin' and is_active and id <> old.id;

  if other_active_admins = 0 then
    raise exception 'At least one active Admin must remain in the project'
      using errcode = 'P0001';
  end if;

  return case when tg_op = 'DELETE' then old else new end;
end;
$$;

revoke execute on function public.guard_last_admin() from public, anon, authenticated;

create trigger profiles_last_admin_guard
  before update or delete on public.profiles
  for each row execute function public.guard_last_admin();
