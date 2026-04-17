-- Append-only audit trail (run once against your DCRS Postgres / Supabase DB).
-- Links actors to public.users(id) — ensure types match your users.id column (uuid below).
--
-- If you already had an older public.audit_logs table, CREATE TABLE IF NOT EXISTS does nothing;
-- the ALTER block below adds any missing columns (e.g. occurred_at) before indexes run.

CREATE TABLE IF NOT EXISTS public.audit_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_user_id uuid REFERENCES public.users (id) ON DELETE SET NULL,
  actor_email text,
  actor_role text,
  action text NOT NULL,
  resource_type text,
  resource_id text,
  http_method text,
  request_path text,
  ip_address text,
  user_agent text,
  outcome text NOT NULL DEFAULT 'SUCCESS',
  metadata jsonb
);

-- Upgrade legacy tables that were created without the full column set.
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS occurred_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS actor_user_id uuid;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS actor_email text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS actor_role text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS action text NOT NULL DEFAULT '';
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS resource_type text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS resource_id text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS http_method text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS request_path text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS ip_address text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS user_agent text;
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS outcome text NOT NULL DEFAULT 'SUCCESS';
ALTER TABLE public.audit_logs ADD COLUMN IF NOT EXISTS metadata jsonb;

CREATE INDEX IF NOT EXISTS idx_audit_logs_occurred_at ON public.audit_logs (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON public.audit_logs (actor_user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON public.audit_logs (resource_type, resource_id, occurred_at DESC);

-- Enforce append-only at database level (no UPDATE/DELETE on audit rows).
CREATE OR REPLACE FUNCTION public.audit_logs_block_mutate ()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_append_only ON public.audit_logs;
CREATE TRIGGER audit_logs_append_only
  BEFORE UPDATE OR DELETE ON public.audit_logs
  FOR EACH ROW
  EXECUTE PROCEDURE public.audit_logs_block_mutate ();
