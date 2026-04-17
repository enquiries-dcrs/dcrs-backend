# Care home operations & IG discipline (CQC-oriented)

Use this as a living checklist alongside your DPIA / policies. It complements technical controls in `server.js` and `sql/`.

## Backups and recovery

- [ ] **Automated backups** enabled for production Postgres (Supabase: PITR / daily backups per plan).
- [ ] **Restore test** at least **quarterly** (restore to a non-production branch or clone, verify critical tables).
- [ ] Document **RPO/RTO** (how much data you can lose; how long to be back online) and who approves failover.
- [ ] Secrets (`DATABASE_URL`, Supabase keys) stored only in the host secret manager, not in chat or tickets.

## Multi-factor authentication (MFA)

- [ ] **MFA enforced** in Supabase Auth (or your IdP) for all staff who access live resident data.
- [ ] **Break-glass** account procedure documented (rare use, strong monitoring, password rotation after use).
- [ ] Shared **reception** or **kiosk** devices: policy on logout, timeout, and no saved passwords.

## Access reviews

- [ ] **Quarterly** review of `users`: role, `home_scope_id`, `is_active`; remove or adjust leavers same day where possible.
- [ ] **Sample** `audit_logs` monthly (or automated alerts): impossible travel, off-hours bulk exports, repeated failures.
- [ ] **Invite** process: only named roles may invite; verify new joiners appear in `users` before first shift.

## Retention and audit logs

- [ ] **Retention period** for `audit_logs` (and clinical tables) agreed with your **records / IG** lead and **legal** advice.
- [ ] **Export** or archive process if you trim old rows (append-only table: prefer archive table, not UPDATE/DELETE on `audit_logs` if trigger enforces immutability).
- [ ] **Subject access** / erasure requests: process for redacting third parties in logs where required.

## Training (people, not just software)

- [ ] **Confidentiality**: no discussion of identifiable residents in unsecured channels; no screenshots to personal phones.
- [ ] **Minimum necessary**: only open records for residents you support; challenge unfamiliar wide access.
- [ ] **Incidents**: who to tell and how fast if device lost, suspected misuse, or supplier outage.
- [ ] **AI** (if enabled): output is assistive only; never copy into legal records without human review and local policy.

## Schema-level integrity (when data is clean)

- [ ] Run orphan checks in `sql/002_resident_child_data_invariants.sql` (commented queries).
- [ ] Apply **`sql/003_delete_orphans_and_add_service_user_fks.sql`** in the Supabase SQL editor: it **deletes** orphan child rows, then adds **`ON DELETE CASCADE`** FKs (backup first; confirm table/column names match your schema).
- [ ] Re-run orphan checks after any bulk import or migration.

## Related files

- `sql/001_audit_logs.sql` — append-only audit table + trigger.
- `sql/002_resident_child_data_invariants.sql` — app-enforced joins + optional FK patterns and orphan checks.
- `sql/003_delete_orphans_and_add_service_user_fks.sql` — one-shot delete orphans + add FKs (transaction).
