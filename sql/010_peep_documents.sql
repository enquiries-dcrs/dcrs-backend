-- =============================================================================
-- DCRS — PEEP (Personal Emergency Evacuation Plan) document
-- =============================================================================
-- One current PEEP per service user (versioned via updated_at).

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.peep_documents (
  service_user_id uuid PRIMARY KEY REFERENCES public.service_users(id) ON DELETE CASCADE,
  mobility text NULL,
  assistance_required text NULL,
  evacuation_method text NULL,
  alarm_awareness text NULL,
  communication_needs text NULL,
  night_arrangements text NULL,
  equipment_required text NULL,
  key_risks text NULL,
  route_and_refuge text NULL,
  other_notes text NULL,
  review_date date NULL,
  updated_by text NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.peep_documents IS 'Personal Emergency Evacuation Plan (PEEP) document per resident.';
COMMENT ON COLUMN public.peep_documents.service_user_id IS 'Resident/service user ID (one PEEP per resident).';

