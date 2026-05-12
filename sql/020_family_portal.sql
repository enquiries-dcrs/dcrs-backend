-- =============================================================================
-- DCRS — Family portal (access links + optional note sharing)
-- =============================================================================
-- Run after public.users and public.service_users exist.
-- 1) family_portal_access: which provisioned DCRS user may view which resident.
-- 2) daily_notes.share_with_family: staff opt-in per note (default false).

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.family_portal_access (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  relationship text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT family_portal_access_user_resident_unique UNIQUE (user_id, service_user_id)
);

CREATE INDEX IF NOT EXISTS family_portal_access_user_idx
  ON public.family_portal_access(user_id);

CREATE INDEX IF NOT EXISTS family_portal_access_resident_idx
  ON public.family_portal_access(service_user_id);

COMMENT ON TABLE public.family_portal_access IS
  'Maps a provisioned DCRS users row (same email as Supabase) to a service user for the family portal.';

ALTER TABLE public.daily_notes
  ADD COLUMN IF NOT EXISTS share_with_family boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN public.daily_notes.share_with_family IS
  'When true, this note may appear on the family portal feed for linked family accounts.';
