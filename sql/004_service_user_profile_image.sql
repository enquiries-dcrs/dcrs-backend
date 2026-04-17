-- Public URL for the service user's profile photo (e.g. Supabase Storage or CDN).
ALTER TABLE public.service_users
  ADD COLUMN IF NOT EXISTS profile_image_url text;

COMMENT ON COLUMN public.service_users.profile_image_url IS 'HTTPS (or http) URL to a profile photo for identification on the chart.';
