-- =============================================================================
-- DCRS — Seed assessment templates (Supabase / Postgres)
-- =============================================================================
-- Run after 015_assessment_templates.sql (and 016_assessments.sql if you record
-- completed assessments). Safe to re-run: inserts only when name is missing.
--
-- In Supabase: SQL Editor → paste → Run.

SET search_path TO public;

-- -----------------------------------------------------------------------------
-- 1) Nutrition screening (MUST-inspired, simplified)
-- -----------------------------------------------------------------------------
INSERT INTO public.assessment_templates (
  name,
  version,
  schema_json,
  scoring_json,
  is_active,
  created_by,
  updated_by
)
SELECT
  'Nutrition screening (MUST-inspired)',
  1,
  $$
  {
    "fields": [
      {
        "key": "bmi_band",
        "label": "BMI band",
        "type": "select",
        "required": true,
        "options": [">20", "18.5–20", "<18.5"]
      },
      {
        "key": "unintentional_weight_loss",
        "label": "Unintentional weight loss (approx. last 3–6 months)",
        "type": "select",
        "required": true,
        "options": ["None / unsure", "5–10%", ">10%"]
      },
      {
        "key": "acute_disease_effect",
        "label": "Acute disease and likely no nutritional intake >5 days",
        "type": "select",
        "required": true,
        "options": ["No", "Yes"]
      },
      {
        "key": "notes",
        "label": "Clinical notes / actions",
        "type": "textarea",
        "required": false
      }
    ]
  }
  $$::jsonb,
  $$
  {
    "type": "sum",
    "fields": {
      "bmi_band": {
        "default": 0,
        "map": { ">20": 0, "18.5–20": 1, "<18.5": 2 }
      },
      "unintentional_weight_loss": {
        "default": 0,
        "map": { "None / unsure": 0, "5–10%": 1, ">10%": 2 }
      },
      "acute_disease_effect": {
        "default": 0,
        "map": { "No": 0, "Yes": 2 }
      }
    },
    "bands": [
      { "min": 0, "max": 0, "label": "Low risk (0)" },
      { "min": 1, "max": 1, "label": "Medium risk (1)" },
      { "min": 2, "max": 99, "label": "High risk (2+)" }
    ]
  }
  $$::jsonb,
  true,
  NULL,
  NULL
WHERE NOT EXISTS (
  SELECT 1 FROM public.assessment_templates t WHERE t.name = 'Nutrition screening (MUST-inspired)'
);

-- -----------------------------------------------------------------------------
-- 2) Falls risk (basic screen)
-- -----------------------------------------------------------------------------
INSERT INTO public.assessment_templates (
  name,
  version,
  schema_json,
  scoring_json,
  is_active,
  created_by,
  updated_by
)
SELECT
  'Falls risk (basic screen)',
  1,
  $$
  {
    "fields": [
      {
        "key": "prior_falls_12m",
        "label": "Fall(s) in the last 12 months",
        "type": "select",
        "required": true,
        "options": ["No", "Yes"]
      },
      {
        "key": "mobility_aid",
        "label": "Walking / transfers",
        "type": "select",
        "required": true,
        "options": ["Independent", "Supervision / equipment", "Hoist / full assist"]
      },
      {
        "key": "medication_risk",
        "label": "Medicines associated with falls (e.g. sedatives, hypotensives)",
        "type": "select",
        "required": true,
        "options": ["None known", "One or more"]
      },
      {
        "key": "cognition_orientation",
        "label": "Cognition / orientation to environment",
        "type": "select",
        "required": true,
        "options": ["Unimpaired", "Mild impairment", "Significant impairment"]
      },
      {
        "key": "actions",
        "label": "Planned actions / referrals",
        "type": "textarea",
        "required": false
      }
    ]
  }
  $$::jsonb,
  $$
  {
    "type": "sum",
    "fields": {
      "prior_falls_12m": { "default": 0, "map": { "No": 0, "Yes": 2 } },
      "mobility_aid": {
        "default": 0,
        "map": {
          "Independent": 0,
          "Supervision / equipment": 1,
          "Hoist / full assist": 2
        }
      },
      "medication_risk": { "default": 0, "map": { "None known": 0, "One or more": 1 } },
      "cognition_orientation": {
        "default": 0,
        "map": {
          "Unimpaired": 0,
          "Mild impairment": 1,
          "Significant impairment": 2
        }
      }
    },
    "bands": [
      { "min": 0, "max": 2, "label": "Lower score (0–2)" },
      { "min": 3, "max": 5, "label": "Moderate (3–5)" },
      { "min": 6, "max": 99, "label": "Higher score (6+)" }
    ]
  }
  $$::jsonb,
  true,
  NULL,
  NULL
WHERE NOT EXISTS (
  SELECT 1 FROM public.assessment_templates t WHERE t.name = 'Falls risk (basic screen)'
);

-- -----------------------------------------------------------------------------
-- 3) Pressure area care (Waterlow-inspired, simplified)
-- -----------------------------------------------------------------------------
INSERT INTO public.assessment_templates (
  name,
  version,
  schema_json,
  scoring_json,
  is_active,
  created_by,
  updated_by
)
SELECT
  'Pressure area care (Waterlow-inspired)',
  1,
  $$
  {
    "fields": [
      {
        "key": "build_weight_for_height",
        "label": "Build / weight for height",
        "type": "select",
        "required": true,
        "options": ["Average", "Above average", "Below average", "Obese"]
      },
      {
        "key": "skin_visual_risk",
        "label": "Skin condition (pressure damage risk)",
        "type": "select",
        "required": true,
        "options": ["Healthy", "Tissue paper / dry", "Oedema", "Discoloured / broken"]
      },
      {
        "key": "mobility",
        "label": "Mobility",
        "type": "select",
        "required": true,
        "options": ["Full", "Restless / fidgety", "Apathetic", "Chair bound", "Bed bound"]
      },
      {
        "key": "continence",
        "label": "Continence",
        "type": "select",
        "required": true,
        "options": ["Complete", "Occasionally incontinent", "Catheter / incontinence of faeces", "Doubly incontinent"]
      },
      {
        "key": "tissue_malnutrition",
        "label": "Tissue malnutrition / chronic illness",
        "type": "select",
        "required": true,
        "options": ["None", "Smoking", "Diabetes / MS / Parkinson / stroke", "Terminal cachexia"]
      },
      {
        "key": "equipment_plan",
        "label": "Equipment / repositioning plan",
        "type": "textarea",
        "required": false
      }
    ]
  }
  $$::jsonb,
  $$
  {
    "type": "sum",
    "fields": {
      "build_weight_for_height": {
        "default": 0,
        "map": { "Average": 1, "Above average": 2, "Below average": 3, "Obese": 4 }
      },
      "skin_visual_risk": {
        "default": 0,
        "map": {
          "Healthy": 0,
          "Tissue paper / dry": 1,
          "Oedema": 2,
          "Discoloured / broken": 3
        }
      },
      "mobility": {
        "default": 0,
        "map": {
          "Full": 0,
          "Restless / fidgety": 1,
          "Apathetic": 2,
          "Chair bound": 3,
          "Bed bound": 4
        }
      },
      "continence": {
        "default": 0,
        "map": {
          "Complete": 0,
          "Occasionally incontinent": 1,
          "Catheter / incontinence of faeces": 2,
          "Doubly incontinent": 3
        }
      },
      "tissue_malnutrition": {
        "default": 0,
        "map": {
          "None": 0,
          "Smoking": 1,
          "Diabetes / MS / Parkinson / stroke": 2,
          "Terminal cachexia": 3
        }
      }
    },
    "bands": [
      { "min": 1, "max": 6, "label": "Lower cumulative score (1–6) — align with local Waterlow policy" },
      { "min": 7, "max": 11, "label": "Moderate cumulative score (7–11)" },
      { "min": 12, "max": 99, "label": "Higher cumulative score (12+)" }
    ]
  }
  $$::jsonb,
  true,
  NULL,
  NULL
WHERE NOT EXISTS (
  SELECT 1 FROM public.assessment_templates t WHERE t.name = 'Pressure area care (Waterlow-inspired)'
);
