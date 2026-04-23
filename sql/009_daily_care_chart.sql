-- =============================================================================
-- DCRS — Daily Care Record chart (daily)
-- =============================================================================
-- Stores structured daily care entries per service user per day.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.daily_care_entries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  chart_date date NOT NULL DEFAULT (now() at time zone 'utc')::date,
  care_item text NOT NULL,
  value text NULL,
  notes text NULL,
  recorded_by text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT daily_care_entries_care_item_check CHECK (
    care_item IN (
      'Bath',
      'Hair',
      'Nails',
      'Bowels Open',
      'Fluids',
      'Medicate',
      'Visitors',
      'Been out',
      'Stayed in',
      'Other'
    )
  )
);

CREATE INDEX IF NOT EXISTS daily_care_entries_service_user_date_idx
  ON public.daily_care_entries(service_user_id, chart_date, created_at DESC);

COMMENT ON TABLE public.daily_care_entries IS 'Daily care record chart entries for care home residents.';
COMMENT ON COLUMN public.daily_care_entries.chart_date IS 'UTC date for the daily chart.';
COMMENT ON COLUMN public.daily_care_entries.care_item IS 'One of the approved daily care chart items.';
COMMENT ON COLUMN public.daily_care_entries.value IS 'Optional short value (e.g. Yes/No, amount, meds given).';
COMMENT ON COLUMN public.daily_care_entries.notes IS 'Optional free-text notes.';

