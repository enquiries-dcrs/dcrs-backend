-- Clinical risk & review inbox — staff acknowledgements (append-only, audit-friendly).
-- Pair with GET/POST /api/v1/clinical-risk-review in server.js.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.risk_review_acknowledgements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT now(),
  actor_user_id uuid REFERENCES public.users (id) ON DELETE SET NULL,
  actor_email text,
  fingerprint text NOT NULL,
  service_user_id uuid NOT NULL REFERENCES public.service_users (id) ON DELETE CASCADE,
  note text NULL
);

CREATE INDEX IF NOT EXISTS idx_rr_ack_created ON public.risk_review_acknowledgements (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rr_ack_fp_time ON public.risk_review_acknowledgements (fingerprint, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rr_ack_service_user ON public.risk_review_acknowledgements (service_user_id, created_at DESC);

COMMENT ON TABLE public.risk_review_acknowledgements IS
  'Deterministic clinical risk inbox: staff acknowledge review of a fingerprinted item; same item can reappear after cooldown. Optional home_id (see sql/024) supports per-home cooldown in homes.metadata.';
