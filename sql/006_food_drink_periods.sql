-- =============================================================================
-- DCRS — Food & Drink chart: add daily "period" buckets
-- =============================================================================
-- Adds a period column so entries can be grouped into:
-- Breakfast, Mid-morning, Lunch, Mid-Afternoon, Evening, Bedtime

SET search_path TO public;

ALTER TABLE public.food_drink_entries
  ADD COLUMN IF NOT EXISTS period text;

-- Enforce allowed values (kept as CHECK for simplicity)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN pg_class rel ON rel.oid = c.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE c.conname = 'food_drink_entries_period_check'
      AND nsp.nspname = 'public'
      AND rel.relname = 'food_drink_entries'
  ) THEN
    ALTER TABLE public.food_drink_entries
      ADD CONSTRAINT food_drink_entries_period_check
      CHECK (period IS NULL OR period IN ('Breakfast','Mid-morning','Lunch','Mid-Afternoon','Evening','Bedtime'));
  END IF;
END $$;

-- Backfill existing rows (best-effort based on created_at hour)
UPDATE public.food_drink_entries
SET period = CASE
  WHEN created_at IS NULL THEN 'Lunch'
  WHEN EXTRACT(HOUR FROM (created_at AT TIME ZONE 'utc')) < 10 THEN 'Breakfast'
  WHEN EXTRACT(HOUR FROM (created_at AT TIME ZONE 'utc')) < 12 THEN 'Mid-morning'
  WHEN EXTRACT(HOUR FROM (created_at AT TIME ZONE 'utc')) < 15 THEN 'Lunch'
  WHEN EXTRACT(HOUR FROM (created_at AT TIME ZONE 'utc')) < 17 THEN 'Mid-Afternoon'
  WHEN EXTRACT(HOUR FROM (created_at AT TIME ZONE 'utc')) < 20 THEN 'Evening'
  ELSE 'Bedtime'
END
WHERE period IS NULL;

-- New rows default to Lunch unless specified
ALTER TABLE public.food_drink_entries
  ALTER COLUMN period SET DEFAULT 'Lunch';

