-- =============================================================================
-- DCRS — Assessment templates (v1)
-- =============================================================================
-- Generic JSON-based template system for assessments (e.g. MUST, Falls risk).

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.assessment_templates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  version int NOT NULL DEFAULT 1,
  schema_json jsonb NOT NULL,
  scoring_json jsonb NULL,
  is_active boolean NOT NULL DEFAULT true,
  created_by uuid NULL,
  updated_by uuid NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS assessment_templates_active_idx
  ON public.assessment_templates(is_active, name);

