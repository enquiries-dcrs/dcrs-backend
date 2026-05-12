# DSCR gap register (internal)

## Primary frame (procurement / assured solutions)

This register uses **NHS England — Core capabilities for digital social care records (DSCRs)** as the **sole authoritative structure**: one row per **literal** sub-capability under the six published capability areas. That keeps RFP and assured-solutions discussions **traceable** (“Category 3, worker task list”) without inventing parallel requirement IDs.

**Supporting columns only (not alternative frames):**

| Column | Purpose |
|--------|---------|
| **MVP** | Internal delivery priority for a pilot (Y/N). Does not redefine the clause. |
| **CQC** | Flags whether the same gap weakens inspection-style evidence; see `CQC_OPERATIONAL_CHECKLIST.md` for operational controls. |
| **Target release** | Engineering banding until roadmap is fixed. |

**Severity** — risk to making a **defensible** “meets this DSCR clause” statement if challenged, not story points.

| Level | Meaning |
|-------|---------|
| **Critical** | Honest assurance claim against the clause is not supportable; or major IG/access risk. |
| **High** | Material gap; partial workaround only. |
| **Medium** | Substantial coverage; gaps are specific and disclosable. |
| **Low** | Meets or nearly meets clause; polish or depth beyond minimum. |

**Source of clause text:** NHS DSCR core capabilities wording as used for the assured solutions list (internal copy aligned to published criteria). Update this table if NHS republishes wording.

---

## Register (literal assured-list mapping)

**Column key:** **ID** = `DSCR-C{category}-{item}` (stable handle). **Capability** = verbatim sub-requirement. **Product evidence** = what exists in DCRS-App today. **Gap** = what is still missing for the clause.

| ID | Category (NHS DSCR §) | Capability (verbatim) | Product evidence / gap | Sev | MVP | CQC | Target |
|----|------------------------|------------------------|-------------------------|-----|-----|-----|--------|
| DSCR-C1-01 | **1 — Inclusive care planning and needs assessment** | Capturing a person-centered care plan. | **Evidence:** `care_plans` + goals on resident. **Gap:** Limited person-centred narrative / preferences model vs full “about me” record. | Med | Y | Y | 0.x |
| DSCR-C1-02 | **1 — Inclusive care planning…** | Undertaking and capturing care needs assessments using templates or pre-built criteria. | **Evidence:** Assessment templates + resident assessments (API + UI). **Gap:** Depth/breadth of template set and clinical sign-off workflow is product-defined. | Med | Y | Y | MVP |
| DSCR-C1-03 | **1 — Inclusive care planning…** | Creating care plans using templates or pre-built care plans. | **Evidence:** Plans + goals created per resident. **Gap:** No first-class **care plan template library** / clone-from-national-or-local-template. | High | Y | Y | 0.x |
| DSCR-C1-04 | **1 — Inclusive care planning…** | Allowing social care providers to add to care plan templates. | **Evidence:** Providers can edit **assessment** templates (privileged roles). **Gap:** **Care plan** template contribution pathway not equivalent / not clearly separated. | High | N | Y | 1.0 |
| DSCR-C1-05 | **1 — Inclusive care planning…** | Involving individuals in their own care planning process. | **Evidence:** Authenticated **Family** users; Postgres `family_portal_access` (per user ↔ service user); `GET /api/v1/family/context` and `GET /api/v1/family/residents/:id/feed` with server-side scope checks; feed from **real** `daily_notes` where `share_with_family`, plus activities and selected daily-care chart lines; invite flows (resident Overview, Settings admin link); `POST /api/v1/family/residents/:id/visit-request` persists `family_visit_requests` and raises a **high-priority task** for the home (migration `021_family_visit_requests.sql`). **Gap:** No in-product **co-production** on the formal **care plan** document (goals/plan text editable by the person or family); family path is **updates, transparency slice, and visit requests**, not a full MDT / “about me” structured contribution workflow. | High | Y | Y | MVP |
| DSCR-C1-06 | **1 — Inclusive care planning…** | Setting target outcomes/goals for individuals and associated lists of tasks/actions. | **Evidence:** Goals with targets/status; `care_plan_goal_tasks` links tasks to goals. **Gap:** Not all routine tasks forced through plan linkage in UI. | Med | Y | Y | MVP |
| DSCR-C2-01 | **2 — Real-time, auditable records, notes, and observations** | Structured data for routine tasks (e.g., task completion) linked to the care plan. | **Evidence:** Tasks, observations, charts; goal–task links. **Gap:** Structured task completion **not always** explicitly tied to a care plan line in data model. | Med | Y | Y | 0.x |
| DSCR-C2-02 | **2 — Real-time…** | Unstructured data (e.g., activities, patient comments) linked to the care plan. | **Evidence:** Notes, activities, documents on resident timeline. **Gap:** Weak **structured** FK-style link from every unstructured item to a **specific** plan goal. | Med | N | Y | 0.x |
| DSCR-C2-03 | **2 — Real-time…** | Consistent data capture and display throughout the system. | **Evidence:** Shared UI patterns across modules. **Gap:** No formal UX/accessibility assurance pack tied to clause. | Low | N | N | Backlog |
| DSCR-C2-04 | **2 — Real-time…** | A longitudinal picture of care provided over time. | **Evidence:** Resident profile history, notes, observations, CSV exports. **Gap:** Estate-level longitudinal analytics / warehouse views still thin. | Med | Y | Y | 0.x |
| DSCR-C2-05 | **2 — Real-time…** | Capture of written and verbal notes (converted to unstructured text). | **Evidence:** Written notes; AI handover from **existing text**. **Gap:** No regulated **verbal → text** (e.g. clinical speech-to-text) pipeline. | High | N | Y | 1.0 |
| DSCR-C2-06 | **2 — Real-time…** | Uploading of existing third-party documents and images. | **Evidence:** Resident documents + PEEP uploads, download routes, type allowlists. **Gap:** Scanning, malware workflow, structured document metadata policies are operational. | Med | Y | Y | MVP |
| DSCR-C3-01 | **3 — Task planning, allocation, management, and completion** | Allocate tasks to appropriate staff members. | **Evidence:** `assigned_to`, PATCH, assignee enrichment in task APIs (requires DB migration). **Gap:** None critical if migration applied; skills-based allocation out of scope. | Med | Y | N | MVP |
| DSCR-C3-02 | **3 — Task planning…** | Provide real-time task status information. | **Evidence:** Status on tasks; list APIs. **Gap:** **Poll-based** refresh; no documented push/WebSocket “real-time” contract. | Low | N | N | 1.0 |
| DSCR-C3-03 | **3 — Task planning…** | List tasks assigned to individual workers, showing outstanding vs. completed. | **Evidence:** `GET /api/v1/tasks` + client views; resident task lists. **Gap:** **First-class “my tasks”** filter by assignee + outstanding/completed split in one assured API contract is incomplete. | High | Y | Y | 0.x |
| DSCR-C3-04 | **3 — Task planning…** | Manually identify priority tasks. | **Evidence:** Priority field + filters (e.g. high priority). **Gap:** Governance (who may set Critical) not fully productised. | Med | Y | N | MVP |
| DSCR-C3-05 | **3 — Task planning…** | Automatically flag overdue tasks. | **Evidence:** `overdue=true` query + dashboard use. **Gap:** None material for clause wording. | Low | Y | Y | MVP |
| DSCR-C3-06 | **3 — Task planning…** | Calculate individual risk and flag the need for care plan reviews based on rising risk. | **Evidence:** None production-grade. **Gap:** Dashboard “risk” sample is **mock**; no engine tying metrics → **mandated care plan review** workflow. | Crit | N | Y | 1.0 |
| DSCR-C3-07 | **3 — Task planning…** | Generate handover information for shift changes. | **Evidence:** AI handover endpoint + save as note. **Gap:** Not a full **structured handover** artefact (mandatory fields, sign-off, distribution). | High | Y | Y | 0.x |
| DSCR-C3-08 | **3 — Task planning…** | Provide an **aggregated dashboard view** of task status for care managers. | **Evidence:** Dashboard + task inbox + analytics stubs. **Gap:** Limited **aggregates** (by home/unit/workload/completion rate) vs mature manager dashboards. | High | Y | Y | 0.x |
| DSCR-C4-01 | **4 — Controlled access to data** | Access for individuals to view their own care plans/records. | **Evidence:** **Family** role backed by Postgres (not JWT metadata alone); `family_portal_access` enforces **only linked service users** (not whole-home directory); family-only JSON APIs under `/api/v1/family/…`; clinical routes use `requireRole` lists that **exclude** Family; feed + visit request as in C1-05; audit events for family feed views. **Gap:** Clause wording implies **full** care **plans/records** for the individual — product delivers a **controlled, staff-opt-in disclosure feed** plus visit scheduling, **not** download or browse of the complete clinical record or signed care plan artefact. | High | Y | Y | MVP |
| DSCR-C4-02 | **4 — Controlled access…** | Access for authorized care workers and health professionals to view and edit care plans/assessments/records (including those they did not create). | **Evidence:** Role matrix + `home_scope_id` + scoped queries. **Gap:** “Health professionals” cross-organisation access model not evidenced (trust-wide roles / shared care). | Med | Y | Y | MVP |
| DSCR-C4-03 | **4 — Controlled access…** | Viewability on third-party devices (e.g., devices owned by health professionals). | **Evidence:** Responsive web. **Gap:** No kiosk mode, device attestation, or BYOD policy features in product. | Med | N | N | TBD (policy) |
| DSCR-C4-04 | **4 — Controlled access…** | The ability for providers to set access controls. | **Evidence:** Admin user + role assignment in app. **Gap:** No **granular** provider-defined ACL matrix (feature-level toggles per home). | High | N | N | 1.0 |
| DSCR-C4-05 | **4 — Controlled access…** | An audit log of all changes, including who accessed the record, the date, and what changes were made. | **Evidence:** Append-only `audit_logs`, many actions, IP/UA/path. **Gap:** **“What changes were made”** often event-level, not full field-level clinical diff; metadata minimised for IG. | High | Y | Y | 0.x |
| DSCR-C5-01 | **5 — Data sharing with other systems** | Export data and reports in flat-file formats (e.g., PDF). | **Evidence:** PDF accepted as uploads. **Gap:** **Server-generated** assurance PDFs for reports largely **absent**; analytics placeholders reference PDF without implementation. | High | N | Y | 0.x |
| DSCR-C5-02 | **5 — Data sharing…** | Export data and reports in interrogatable/importable formats (e.g., CSV). | **Evidence:** Resident exports, audit CSV, roster CSV, UTF-8 BOM. **Gap:** Not every managerial report exists as CSV yet. | Med | Y | Y | MVP |
| DSCR-C5-03 | **5 — Data sharing…** | Upload documents into an individual's care record. | **Evidence:** Resident document upload API + UI. **Gap:** Operational virus scan / retention. | Med | Y | Y | MVP |
| DSCR-C5-04 | **5 — Data sharing…** | Produce key information for emergency hospital admissions in a compliant format. | **Evidence:** PEEP + clinical exports fragments. **Gap:** No named **standard** emergency admission / transfer dataset + pack (e.g. national transfer requirements). | Crit | N | Y | 1.0 |
| DSCR-C5-05 | **5 — Data sharing…** | *(Implied by category title)* Live interoperability with other digital systems. | **Evidence:** UI/settings references; demo GP-style data. **Gap:** **Production** FHIR/GP Connect/ADT etc. **not** implemented. | Crit | N | N | 1.0 |
| DSCR-C6-01 | **6 — Operation and management of a care setting** | Generating, saving, and amending pre-built summary reports for individual recipients. | **Evidence:** CSV exports + AI assist. **Gap:** No **saved/amendable report definitions** catalogue per recipient. | High | N | Y | 1.0 |
| DSCR-C6-02 | **6 — Operation…** | Generating, saving, and amending pre-built summary reports at a site and service level. | **Evidence:** Analytics KPIs, roster CSV, placeholders. **Gap:** No site/service **report library** with versioning/amend workflow. | High | N | Y | 0.x |
| DSCR-C6-03 | **6 — Operation…** | Viewing a chronology of interactions and activities for auditing/inspection and incident management. | **Evidence:** Notes + observations + audit export + timelines. **Gap:** No single **incident** chronology module; inspection narrative may require multiple screens/exports. | Med | Y | Y | 0.x |
| DSCR-C6-04 | **6 — Operation…** | Providing reports that support meeting the "Key Lines of Enquiry" of the CQC inspection regime. | **Evidence:** `GET /api/v1/analytics/assurance-pack` + `assurance-pack.csv` (Deputy Manager+ / same scope as resident roster export): metrics mapped to CQC **quality statement themes** (Safe, Effective, Caring, Responsive, Well-led) from notes, observations, activities, assessments, documents, tasks, care plans, audit activity, family portal links and visit requests; Analytics UI section with disclaimer; operational checklist doc + existing CSV exports. **Gap:** Not a full **KLOE-by-KLOE** narrative or rating model; no server-generated inspection PDF; audit slice for “Well-led” is partly estate-wide when no home filter. | Med | Y | Y | MVP |

**Note:** DSCR-C5-05 is the **category-level** interoperability expectation; keep it explicit so procurement Q&A does not assume CSV alone satisfies “other systems.”

**Family portal / visit requests (engineering SoT):** apply `backend/sql/020_family_portal.sql` (`family_portal_access`, `daily_notes.share_with_family`) and `backend/sql/021_family_visit_requests.sql` in production DBs; without these, related API routes return explicit migration errors.

---

## Maintenance

- **Owner:** TBD. **Cadence:** Before any assured-list positioning or major tender; at least quarterly.
- When NHS republishes DSCR text, update the **Capability** column verbatim and bump **Source** footnote date.
- When family portal or access model changes materially, update **DSCR-C1-05** and **DSCR-C4-01** together so procurement language stays consistent.
