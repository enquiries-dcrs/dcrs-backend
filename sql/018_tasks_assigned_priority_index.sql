-- =============================================================================
-- DCRS — Tasks: assignee + list performance (Chunk D)
-- =============================================================================
-- Adds optional assigned_to for accountability; index supports overdue / due
-- ordering per resident.

SET search_path TO public;

ALTER TABLE public.tasks
  ADD COLUMN IF NOT EXISTS assigned_to uuid NULL REFERENCES public.users(id);

CREATE INDEX IF NOT EXISTS tasks_service_user_status_due_idx
  ON public.tasks(service_user_id, status, due_date);

CREATE INDEX IF NOT EXISTS tasks_assigned_to_idx
  ON public.tasks(assigned_to)
  WHERE assigned_to IS NOT NULL;
