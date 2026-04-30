-- =============================================================================
-- DCRS — Care plan goal ↔ tasks link (v1)
-- =============================================================================
-- Allows storing which tasks were created for (or linked to) a specific goal.

SET search_path TO public;

CREATE TABLE IF NOT EXISTS public.care_plan_goal_tasks (
  goal_id uuid NOT NULL REFERENCES public.care_plan_goals(id) ON DELETE CASCADE,
  task_id uuid NOT NULL REFERENCES public.tasks(id) ON DELETE CASCADE,
  created_by uuid NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (goal_id, task_id)
);

CREATE INDEX IF NOT EXISTS care_plan_goal_tasks_task_idx
  ON public.care_plan_goal_tasks(task_id);

