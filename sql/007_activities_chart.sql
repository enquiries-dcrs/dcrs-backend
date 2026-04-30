-- =============================================================================
-- DCRS — Activities chart (daily)
-- =============================================================================
-- Stores structured activities entries per service user per day.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.activity_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  chart_date date NOT NULL DEFAULT (now() at time zone 'utc')::date,
  activity_type text NOT NULL,
  notes text NULL,
  recorded_by text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT activity_entries_activity_type_check CHECK (
    activity_type IN (
      'Exercise class',
      'Arts and Crafts',
      'Puzzles',
      'Watched television',
      'Movie matinee',
      'Gardening',
      'Sitting in the garden',
      'Pampering session',
      'Bingo',
      'Seasonal crafts',
      'Reading',
      'Social outings',
      'Visitors'
    )
  )
);

CREATE INDEX IF NOT EXISTS activity_entries_service_user_date_idx
  ON public.activity_entries(service_user_id, chart_date, created_at DESC);

COMMENT ON TABLE public.activity_entries IS 'Daily activities chart entries for care home residents.';
COMMENT ON COLUMN public.activity_entries.chart_date IS 'UTC date for the daily chart.';
COMMENT ON COLUMN public.activity_entries.activity_type IS 'One of the approved activity names.';

