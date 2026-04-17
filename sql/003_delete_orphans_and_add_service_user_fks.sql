-- =============================================================================
-- DCRS — single idempotent migration (Supabase SQL editor or psql)
-- =============================================================================
--
-- HOW TO RUN (Supabase)
--   1. Dashboard → SQL → New query.
--   2. Paste this entire file and run once.
--   3. If anything fails: fix the error, then re-run (deletes + FK adds are idempotent).
--
-- CLI (after DATABASE_URL is correct):
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/003_delete_orphans_and_add_service_user_fks.sql
--
-- BEFORE YOU RUN
--   • Backup / PITR snapshot first.
--   • Confirm tables: public.service_users, daily_notes, tasks, medications, observations.
--   • ON DELETE CASCADE removes child rows if a service_users row is deleted — confirm policy.
--
-- =============================================================================
-- Step 0 — optional orphan counts only (copy into a separate query to preview)
-- =============================================================================
-- SELECT 'daily_notes' AS tbl, COUNT(*)::int AS orphans FROM daily_notes x
--   WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = x.service_user_id);
-- SELECT 'tasks' AS tbl, COUNT(*)::int AS orphans FROM tasks x
--   WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = x.service_user_id);
-- SELECT 'medications' AS tbl, COUNT(*)::int AS orphans FROM medications x
--   WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = x.service_user_id);
-- SELECT 'observations' AS tbl, COUNT(*)::int AS orphans FROM observations x
--   WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = x.service_user_id);
--
-- =============================================================================
-- Step 1 — apply (transaction)
-- =============================================================================

SET search_path TO public;

BEGIN;

-- Remove child rows that point at no service user (safe to re-run; second run deletes 0 rows)
DO $$
BEGIN
  IF to_regclass('public.daily_notes') IS NOT NULL THEN
    DELETE FROM daily_notes dn
    WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = dn.service_user_id);
  END IF;
  IF to_regclass('public.tasks') IS NOT NULL THEN
    DELETE FROM tasks t
    WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = t.service_user_id);
  END IF;
  IF to_regclass('public.medications') IS NOT NULL THEN
    DELETE FROM medications m
    WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = m.service_user_id);
  END IF;
  IF to_regclass('public.observations') IS NOT NULL THEN
    DELETE FROM observations o
    WHERE NOT EXISTS (SELECT 1 FROM service_users su WHERE su.id = o.service_user_id);
  END IF;
END $$;

-- FKs: add only if this table does not already have a constraint with that name in public
DO $$
BEGIN
  IF to_regclass('public.daily_notes') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1
       FROM pg_constraint c
       JOIN pg_class rel ON rel.oid = c.conrelid
       JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
       WHERE c.conname = 'daily_notes_service_user_id_fkey'
         AND nsp.nspname = 'public'
         AND rel.relname = 'daily_notes'
     ) THEN
    ALTER TABLE daily_notes
      ADD CONSTRAINT daily_notes_service_user_id_fkey
      FOREIGN KEY (service_user_id) REFERENCES service_users (id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('public.tasks') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint c
       JOIN pg_class rel ON rel.oid = c.conrelid
       JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
       WHERE c.conname = 'tasks_service_user_id_fkey'
         AND nsp.nspname = 'public' AND rel.relname = 'tasks'
     ) THEN
    ALTER TABLE tasks
      ADD CONSTRAINT tasks_service_user_id_fkey
      FOREIGN KEY (service_user_id) REFERENCES service_users (id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('public.medications') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint c
       JOIN pg_class rel ON rel.oid = c.conrelid
       JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
       WHERE c.conname = 'medications_service_user_id_fkey'
         AND nsp.nspname = 'public' AND rel.relname = 'medications'
     ) THEN
    ALTER TABLE medications
      ADD CONSTRAINT medications_service_user_id_fkey
      FOREIGN KEY (service_user_id) REFERENCES service_users (id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('public.observations') IS NOT NULL
     AND NOT EXISTS (
       SELECT 1 FROM pg_constraint c
       JOIN pg_class rel ON rel.oid = c.conrelid
       JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
       WHERE c.conname = 'observations_service_user_id_fkey'
         AND nsp.nspname = 'public' AND rel.relname = 'observations'
     ) THEN
    ALTER TABLE observations
      ADD CONSTRAINT observations_service_user_id_fkey
      FOREIGN KEY (service_user_id) REFERENCES service_users (id) ON DELETE CASCADE;
  END IF;
END $$;

COMMIT;

-- =============================================================================
-- Step 2 — verify (optional; run in a new query)
-- =============================================================================
-- SELECT c.conname, rel.relname AS table_name
-- FROM pg_constraint c
-- JOIN pg_class rel ON rel.oid = c.conrelid
-- JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
-- WHERE nsp.nspname = 'public'
--   AND c.conname LIKE '%service_user_id_fkey%'
-- ORDER BY rel.relname;
