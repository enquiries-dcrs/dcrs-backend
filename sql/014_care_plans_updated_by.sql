-- =============================================================================
-- DCRS — Care plans + goals: capture updated_by (v1)
-- =============================================================================

SET search_path TO public;

ALTER TABLE public.care_plans
  ADD COLUMN IF NOT EXISTS updated_by uuid NULL;

ALTER TABLE public.care_plan_goals
  ADD COLUMN IF NOT EXISTS updated_by uuid NULL;

