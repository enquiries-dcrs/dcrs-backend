# DSCR gap register (internal)

**Primary framing: assured-list** — Each row traces to NHS England *Core capabilities for digital social care records (DSCRs)* (assured solutions list expectations). Severity reflects **compliance / assurance risk** if claimed against that clause, not engineering effort alone.

**Secondary lenses (columns):**

| Lens | Use |
|------|-----|
| **MVP** | Minimum viable product for a first live pilot (Y/N or P0–P2). |
| **CQC evidence** | Whether the gap also weakens *inspection-ready* evidence (notes/chronology/reports); overlaps `CQC_OPERATIONAL_CHECKLIST.md` but is product not process. |

**Severity scale**

| Level | Meaning |
|-------|---------|
| **Critical** | Would block honest “meets clause” claims or creates major IG/access risk. |
| **High** | Material gap vs clause; workaround exists but weak. |
| **Medium** | Partial coverage; acceptable for early pilot with disclosure. |
| **Low** | Nice-to-have polish or enterprise depth beyond clause minimum. |

**Target release** — Placeholder bands until roadmap is fixed: `MVP`, `0.x`, `1.0`, `Backlog`, `TBD (policy)`.

---

| ID | DSCR clause (summary) | Current state (short) | Severity | MVP | CQC evidence | Target release |
|----|------------------------|------------------------|----------|-----|----------------|----------------|
| DSCR-01 | **1** Person-centred care plan | Structured plan + goals; limited “about me” / preferences model | Medium | Y | Y | 0.x |
| DSCR-02 | **1** Needs assessments via templates / criteria | Assessment templates + resident assessments | Medium | Y | Y | MVP |
| DSCR-03 | **1** Care plans from **pre-built templates** | Plans are record-led; no template library / clone-from-template | High | Y | Y | 0.x |
| DSCR-04 | **1** Providers **add to care plan templates** | Assessment template edit exists; care plan template pack unclear | High | N | Y | 1.0 |
| DSCR-05 | **1** **Individual** involved in own planning | Family route is demo/mock; no real scoped citizen access | Critical | Y | Y | MVP |
| DSCR-06 | **1** Goals/outcomes + **tasks/actions** linked to plan | Goals + `care_plan_goal_tasks`; usage not enforced everywhere | Medium | Y | Y | MVP |
| DSCR-07 | **2** Structured data at point of care linked to plan | Observations, tasks, charts; linkage to plan varies | Medium | Y | Y | 0.x |
| DSCR-08 | **2** Unstructured data linked to care plan | Notes/documents; weak structured link to specific goals | Medium | N | Y | 0.x |
| DSCR-09 | **2** Consistent capture/display | Generally consistent UI; not formally verified | Low | N | N | Backlog |
| DSCR-10 | **2** Longitudinal picture over time | Resident timeline + exports; analytics depth limited | Medium | Y | Y | 0.x |
| DSCR-11 | **2** Written + **verbal** notes as text | Written notes; AI handover from text, not regulated STT | High | N | Y | 1.0 |
| DSCR-12 | **2** Upload third-party documents/images | Resident + PEEP uploads supported | Medium | Y | Y | MVP |
| DSCR-13 | **3** Allocate tasks to staff | Assignee on tasks + APIs (migration-dependent) | Medium | Y | N | MVP |
| DSCR-14 | **3** Real-time task status | Poll-based; no push sync model documented | Low | N | N | 1.0 |
| DSCR-15 | **3** List tasks **per worker** (outstanding vs completed) | Global task list + filters; “my inbox” not first-class in API | High | Y | Y | 0.x |
| DSCR-16 | **3** Manual **priority** tasks | Priority levels + UI | Medium | Y | N | MVP |
| DSCR-17 | **3** **Overdue** tasks flagged | Query filters + dashboard overdue | Medium | Y | Y | MVP |
| DSCR-18 | **3** **Risk** → flag **care plan review** | Dashboard risk is mock; no closed-loop review trigger | Critical | N | Y | 1.0 |
| DSCR-19 | **3** **Handover** for shift changes | AI summary + save as note; not formal handover record | High | Y | Y | 0.x |
| DSCR-20 | **3** **Aggregated dashboard** for care managers | Early dashboard + analytics stub; limited aggregates | High | Y | Y | 0.x |
| DSCR-21 | **4** **Individual** access to own plans/records | Not production (see DSCR-05) | Critical | Y | Y | MVP |
| DSCR-22 | **4** Authorised staff/professionals view/edit (incl. not creator) | Roles + home scope; edit rights by role | Medium | Y | Y | MVP |
| DSCR-23 | **4** View on **third-party devices** | Web responsive; no kiosk/attestation | Medium | N | N | TBD (policy) |
| DSCR-24 | **4** Providers set **access controls** | Fixed role matrix in code; no granular admin ACL UI | High | N | N | 1.0 |
| DSCR-25 | **4** **Audit log** — who, when, **what changed** | Append-only audit + actions; limited field-level change diff | High | Y | Y | 0.x |
| DSCR-26 | **5** Export **PDF** reports | Upload PDFs; few/no server-generated assurance PDFs | High | N | Y | 0.x |
| DSCR-27 | **5** Export **CSV** / importable formats | Resident exports, audit CSV, roster CSV | Medium | Y | Y | MVP |
| DSCR-28 | **5** Upload documents to individual record | Supported | Medium | Y | Y | MVP |
| DSCR-29 | **5** **Emergency admission** info — compliant format | PEEP/clinical data exist; no named standard transfer pack | Critical | N | Y | 1.0 |
| DSCR-30 | **5** Data sharing with **other systems** (live) | GP Connect etc. largely mock / settings copy | Critical | N | N | 1.0 |
| DSCR-31 | **6** Pre-built summaries **for individuals** (save/amend) | Exports + AI assist; no report-definition catalogue | High | N | Y | 1.0 |
| DSCR-32 | **6** Pre-built summaries **site/service level** (save/amend) | KPIs + CSV; placeholders; no report library | High | N | Y | 0.x |
| DSCR-33 | **6** **Chronology** for audit/incidents | Notes + audit + exports; no single incident chronology module | Medium | Y | Y | 0.x |
| DSCR-34 | **6** Reports supporting **CQC KLOE** | Partial via exports/checklist; no KLOE-mapped packs | High | N | Y | 1.0 |

---

## Framing choice (for PM / compliance)

**Prefer assured-list as the master column** so prioritisation stays aligned with NHS DSCR wording and external assurance questions.

- Use **MVP** column to sequence **pilot-safe** delivery without rewriting clauses.
- Use **CQC evidence** to flag items that also affect **inspection narrative** even if not literal DSCR text.

**Review:** Quarterly or before any “assured list” / formal claims. Owner: TBD.
