-- Topical medicines application record sheet (body map regions + audit fields).
SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.topical_application_records (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users (id) ON DELETE CASCADE,
  chart_date date NOT NULL DEFAULT (now() AT TIME ZONE 'utc')::date,
  applied_at timestamptz NOT NULL DEFAULT now(),
  medication_name text NOT NULL,
  medication_id uuid NULL REFERENCES public.medications (id) ON DELETE SET NULL,
  body_regions text[] NOT NULL DEFAULT '{}'::text[],
  site_notes text NULL,
  batch_lot text NULL,
  recorded_by text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS topical_app_records_su_date_idx
  ON public.topical_application_records (service_user_id, chart_date, applied_at DESC);

COMMENT ON TABLE public.topical_application_records IS
  'Topical medication applications with body-site selection; body_regions uses app-defined keys (validated in API).';

COMMENT ON COLUMN public.topical_application_records.body_regions IS
  'Array of region keys (e.g. head, left_forearm, upper_back). Validated against allow-list in server.js.';
