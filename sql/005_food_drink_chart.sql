-- =============================================================================
-- DCRS — Food & Drink chart (daily)
-- =============================================================================
-- Stores structured hydration/nutrition chart entries per service user.
--
-- Run in Supabase SQL editor or via psql.
--
-- Notes:
-- - Uses DATE column to group by chart day.
-- - Amount is optional to support "ate full meal" style entries.
-- - recorded_by is stored as text for now (display name/email); can be upgraded to FK later.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.food_drink_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  chart_date date NOT NULL DEFAULT (now() at time zone 'utc')::date,
  entry_type text NOT NULL CHECK (entry_type IN ('FOOD', 'DRINK')),
  description text NOT NULL,
  amount_ml integer NULL CHECK (amount_ml IS NULL OR amount_ml >= 0),
  recorded_by text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS food_drink_entries_service_user_date_idx
  ON public.food_drink_entries(service_user_id, chart_date, created_at DESC);

COMMENT ON TABLE public.food_drink_entries IS 'Daily food and drink chart entries for care home residents.';
COMMENT ON COLUMN public.food_drink_entries.chart_date IS 'UTC date for the daily chart.';
COMMENT ON COLUMN public.food_drink_entries.entry_type IS 'FOOD or DRINK.';
COMMENT ON COLUMN public.food_drink_entries.amount_ml IS 'Hydration amount in ml (DRINK entries typically).';

