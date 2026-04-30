-- =============================================================================
-- DCRS — Completed assessments (v1)
-- =============================================================================

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  template_id uuid NOT NULL REFERENCES public.assessment_templates(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'COMPLETED',
  answers_json jsonb NOT NULL,
  score numeric NULL,
  review_date date NULL,
  created_by uuid NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT assessments_status_check CHECK (status IN ('DRAFT', 'COMPLETED'))
);

CREATE INDEX IF NOT EXISTS assessments_service_user_idx
  ON public.assessments(service_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS assessments_template_idx
  ON public.assessments(template_id, created_at DESC);

