-- =============================================================================
-- DCRS — Family portal visit requests (audit + staff task creation from API)
-- =============================================================================
-- Run after 020_family_portal.sql (users, service_users).

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.family_visit_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  requested_by_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  preferred_date date NOT NULL,
  preferred_time_note text NULL,
  message text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS family_visit_requests_resident_idx
  ON public.family_visit_requests(service_user_id, created_at DESC);

COMMENT ON TABLE public.family_visit_requests IS
  'Visit scheduling requests submitted from the family portal; staff also get a high-priority task on the resident.';
