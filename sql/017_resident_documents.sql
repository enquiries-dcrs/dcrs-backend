-- =============================================================================
-- DCRS — Resident documents (v1)
-- =============================================================================
-- Metadata rows for files stored in Supabase Storage.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.resident_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_user_id uuid NOT NULL REFERENCES public.service_users(id) ON DELETE CASCADE,
  home_scope_id uuid NULL,
  file_path text NOT NULL,
  file_name text NOT NULL,
  mime_type text NOT NULL,
  size_bytes bigint NOT NULL,
  doc_type text NULL,
  uploaded_by uuid NULL,
  uploaded_at timestamptz NOT NULL DEFAULT now(),
  is_deleted boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS resident_documents_service_user_idx
  ON public.resident_documents(service_user_id, uploaded_at DESC);

CREATE INDEX IF NOT EXISTS resident_documents_home_scope_idx
  ON public.resident_documents(home_scope_id);

