-- Per-home clinical risk review ack cooldown (JSON metadata on homes) + home_id on ack rows.
SET search_path TO public;

-- Homes: governance JSON (additive). Example:
--   UPDATE homes SET metadata = jsonb_set(
--     COALESCE(metadata, '{}'::jsonb), '{clinicalRiskReview}', '{"ackCooldownHours": 72}'::jsonb, true
--   ) WHERE id = '...';
ALTER TABLE public.homes
  ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE public.risk_review_acknowledgements
  ADD COLUMN IF NOT EXISTS home_id uuid NULL REFERENCES public.homes (id) ON DELETE SET NULL;

UPDATE public.risk_review_acknowledgements r
SET home_id = su.home_id
FROM public.service_users su
WHERE su.id = r.service_user_id
  AND r.home_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_rr_ack_fp_created ON public.risk_review_acknowledgements (fingerprint, created_at DESC);

COMMENT ON COLUMN public.homes.metadata IS
  'Estate/home governance JSON. clinicalRiskReview.ackCooldownHours (1–168) overrides default acknowledgement cooldown for clinical risk inbox.';

COMMENT ON COLUMN public.risk_review_acknowledgements.home_id IS
  'Resident home at acknowledgement time; used with homes.metadata for per-home cooldown evaluation.';
