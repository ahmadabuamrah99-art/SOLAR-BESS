-- =====================================================================
-- demo_seed.sql  (OPTIONAL, run by an Admin in the SQL editor)
--
-- Loads the prototype's sample data as DEMO DATA. Every row has is_demo = true.
-- Capacities are NULL: the old 232 MW / 526 MWh values were not verified.
-- Activity quantities are illustrative only. Replace them with verified baseline data.
-- Remove with demo_cleanup.sql once real project data is entered.
--
-- Do NOT run this on a database that already holds real project data.
-- =====================================================================

insert into public.projects (id, name, pv_capacity_mw, bess_capacity_mwh, is_demo)
values ('a0000000-0000-4000-8000-000000000001', 'DEMO - Solar PV & BESS Project', null, null, true);

insert into public.activities
  (id, project_id, workstream, discipline, name, unit, planned_qty, opening_qty, planned_pct, sort_order, is_demo)
values
  ('a0000000-0000-4000-8000-000000000101', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Mechanical', 'Piling Installation',      'Piles',      1000,    720, 80, 1,  true),
  ('a0000000-0000-4000-8000-000000000102', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Mechanical', 'Structure Installation',  'Tables',      800,    560, 72, 2,  true),
  ('a0000000-0000-4000-8000-000000000103', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Mechanical', 'Module Installation',     'Modules',   50000,  31000, 55, 3,  true),
  ('a0000000-0000-4000-8000-000000000104', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Mechanical', 'Torque Inspection',       'Tables',      800,    400, 55, 4,  true),
  ('a0000000-0000-4000-8000-000000000105', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Electrical', 'DC Cable Installation',    'Meters',   120000,  45000, 45, 5,  true),
  ('a0000000-0000-4000-8000-000000000106', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Electrical', 'Inverter Installation',    'Units',        80,     35, 50, 6,  true),
  ('a0000000-0000-4000-8000-000000000107', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Electrical', 'AC Cable Installation',    'Meters',    25000,   9000, 35, 7,  true),
  ('a0000000-0000-4000-8000-000000000108', 'a0000000-0000-4000-8000-000000000001', 'Solar PV', 'Electrical', 'Earthing Installation',    'Points',      900,    380, 50, 8,  true),
  ('a0000000-0000-4000-8000-000000000109', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Mechanical', 'Battery Container Installation', 'Containers', 6,       2, 50, 9,  true),
  ('a0000000-0000-4000-8000-00000000010a', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Electrical', 'PCS Installation',           'Units',         6,       2, 45, 10, true),
  ('a0000000-0000-4000-8000-00000000010b', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Electrical', 'BESS Transformer Installation', 'Units',      6,       1, 35, 11, true),
  ('a0000000-0000-4000-8000-00000000010c', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Electrical', 'RMU Installation',           'Units',         6,       1, 30, 12, true),
  ('a0000000-0000-4000-8000-00000000010d', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Electrical', 'E-House Installation',       'Units',         2,       1, 40, 13, true),
  ('a0000000-0000-4000-8000-00000000010e', 'a0000000-0000-4000-8000-000000000001', 'BESS',     'Commissioning', 'Testing & Commissioning', 'Systems',       6,       0,  5, 14, true);

-- Six BESS blocks as in the prototype (blocks 1-2 marked installed, matching the 2 containers).
insert into public.bess_blocks (project_id, block_no, block_name, status, is_demo) values
  ('a0000000-0000-4000-8000-000000000001', 1, 'Block 1', 'Installed',   true),
  ('a0000000-0000-4000-8000-000000000001', 2, 'Block 2', 'Installed',   true),
  ('a0000000-0000-4000-8000-000000000001', 3, 'Block 3', 'Not Started', true),
  ('a0000000-0000-4000-8000-000000000001', 4, 'Block 4', 'Not Started', true),
  ('a0000000-0000-4000-8000-000000000001', 5, 'Block 5', 'Not Started', true),
  ('a0000000-0000-4000-8000-000000000001', 6, 'Block 6', 'Not Started', true);
