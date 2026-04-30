-- =============================================================================
-- DCRS — Care plans + goals (v1)
-- =============================================================================
-- Minimal structured care plan per service user, with versionable goals/outcomes.
-- Apply in Supabase SQL editor.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.care_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  title text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE',
  created_by uuid NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT care_plans_status_check CHECK (status IN ('DRAFT', 'ACTIVE', 'ARCHIVED'))
);

CREATE INDEX IF NOT EXISTS care_plans_service_user_idx
  ON public.care_plans(service_user_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS public.care_plan_goals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  care_plan_id uuid NOT NULL REFERENCES public.care_plans(id) ON DELETE CASCADE,
  goal_text text NOT NULL,
  target_date date NULL,
  status text NOT NULL DEFAULT 'OPEN',
  created_by uuid NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT care_plan_goals_status_check CHECK (status IN ('OPEN', 'IN_PROGRESS', 'DONE', 'CANCELLED'))
);

CREATE INDEX IF NOT EXISTS care_plan_goals_plan_idx
  ON public.care_plan_goals(care_plan_id, status, updated_at DESC);

COMMENT ON TABLE public.care_plans IS 'Resident care plans (v1 minimal).';
COMMENT ON TABLE public.care_plan_goals IS 'Goals/outcomes linked to a care plan.';

