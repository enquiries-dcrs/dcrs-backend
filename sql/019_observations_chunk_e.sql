-- =============================================================================
-- DCRS — Observations (Chunk E): notes + recorder display + list performance
-- =============================================================================
-- Additive only: safe if `observations` already exists from an earlier schema.

SET search_path TO public;

ALTER TABLE public.observations ADD COLUMN IF NOT EXISTS notes text NULL;

ALTER TABLE public.observations ADD COLUMN IF NOT EXISTS recorded_by_name text NULL;

CREATE INDEX IF NOT EXISTS observations_su_type_recorded_idx
  ON public.observations(service_user_id, observation_type, recorded_at DESC);
