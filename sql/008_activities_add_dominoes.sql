-- =============================================================================
-- DCRS — Activities chart: add "Dominoes"
-- =============================================================================
-- Updates the CHECK constraint on activity_entries.activity_type to include Dominoes.

SET search_path TO public;

DO $$
BEGIN
  -- Drop existing constraint if present
  IF EXISTS (
    SELECT 1
    FROM pg_constraint c
    JOIN pg_class rel ON rel.oid = c.conrelid
    JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
    WHERE c.conname = 'activity_entries_activity_type_check'
      AND nsp.nspname = 'public'
      AND rel.relname = 'activity_entries'
  ) THEN
    ALTER TABLE public.activity_entries
      DROP CONSTRAINT activity_entries_activity_type_check;
  END IF;

  -- Recreate with Dominoes included
  ALTER TABLE public.activity_entries
    ADD CONSTRAINT activity_entries_activity_type_check CHECK (
      activity_type IN (
        'Exercise class',
        'Arts and Crafts',
        'Puzzles',
        'Watched television',
        'Movie matinee',
        'Gardening',
        'Sitting in the garden',
        'Pampering session',
        'Bingo',
        'Seasonal crafts',
        'Reading',
        'Social outings',
        'Visitors',
        'Dominoes'
      )
    );
END $$;

