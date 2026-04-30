-- =============================================================================
-- DCRS — Care plans (v1) safety: single ACTIVE plan per resident
-- =============================================================================
-- Prevents two ACTIVE plans for the same service user (race-condition safety net).

SET search_path TO public;

CREATE UNIQUE INDEX IF NOT EXISTS care_plans_one_active_per_service_user
  ON public.care_plans(service_user_id)
  WHERE status = 'ACTIVE';

