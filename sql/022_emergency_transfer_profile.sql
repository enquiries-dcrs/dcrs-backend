-- =============================================================================
-- DCRS — Emergency / hospital transfer profile fields on service_users
-- =============================================================================
-- Structured fields for the DCRS emergency transfer pack (v1). Populate via
-- resident chart → Overview; used by GET /api/v1/residents/:id/emergency-transfer-pack.

SET search_path TO public;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS known_allergies text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS gp_practice_name text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS gp_practice_phone text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS next_of_kin_name text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS next_of_kin_phone text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS next_of_kin_relationship text NULL;

ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS advance_care_notes text NULL;

COMMENT ON COLUMN public.service_users.known_allergies IS
  'Free-text known allergies and intolerances for emergency transfer (not a substitute for MAR allergy flags).';

COMMENT ON COLUMN public.service_users.advance_care_notes IS
  'Location/summary of advance care planning (e.g. where RESPECT/DNACPR is filed); not a legal determination.';
