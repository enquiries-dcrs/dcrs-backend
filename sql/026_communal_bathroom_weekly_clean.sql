-- Weekly communal bathroom deep clean checklist (per home, per ISO week starting Monday local to chart).

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.communal_bathroom_weekly_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  home_id uuid NOT NULL REFERENCES public.homes (id) ON DELETE CASCADE,
  week_start_monday date NOT NULL,
  checklist_state jsonb NOT NULL DEFAULT '{}'::jsonb,
  supervisor_notes text NULL,
  updated_by text NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT communal_bathroom_weekly_checks_home_week_uq UNIQUE (home_id, week_start_monday)
);

CREATE INDEX IF NOT EXISTS idx_communal_bath_week_home ON public.communal_bathroom_weekly_checks (home_id, week_start_monday DESC);

COMMENT ON TABLE public.communal_bathroom_weekly_checks IS
  'Weekly deep clean checklist for communal WC/bath; checklist_state keys validated in API (see server.js).';

COMMENT ON COLUMN public.communal_bathroom_weekly_checks.checklist_state IS
  'JSON object: { "tile_walls": { "done": true, "at": "ISO", "by": "Name" }, ... }. Only allow-listed keys.';
