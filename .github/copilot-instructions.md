## Project Overview
Policy Weaver synchronizes data access policies from source catalogs to Microsoft Fabric OneLake Security (Data Access Roles). This codebase focuses on the **Dataverse connector**, which extracts Dynamics 365 Dataverse security metadata and translates it into Fabric policies.

Use these instructions as the default working context for Dataverse changes, especially for BU-aware row-level security behavior.

## Dev Environment
- ARM64-based Windows PC
- Python >= 3.11, activate venv with `\.venv-x64\Scripts\Activate.ps1`
- Formatter/linter: **ruff** (configured in `pyproject.toml`) - run `ruff check .` and `ruff format .` before committing
- Tests: `pytest` - Dataverse tests are in `tests/test_dataverse_*.py`
- Git: feature branches on fork `anlkorkut/Policy-Weaver`, branch `dataverse-postmerge`

## Architecture
```
policyweaver/
├── plugins/dataverse/
│   ├── api.py        <- Dataverse Web API extraction (users, teams, BUs, roles, field security)
│   ├── client.py     <- Policy mapping logic (CLS/RLS generation, depth resolution)
│   └── model.py      <- DataverseSourceMap config model
├── models/
│   ├── export.py     <- Shared export policy models (ask before editing)
│   └── fabric.py     <- Shared Fabric models (ask before editing)
└── weaver.py         <- Shared orchestration (ask before editing)
```

## Dataverse Security Model Mapping
| Dataverse Concept | Policy Weaver Mapping |
|---|---|
| Security Roles (prvRead* privileges) | Table-level SELECT permissions |
| Users (systemusers) | PermissionObject with Entra object ID |
| Teams (AAD-backed, teamtype 2/3) | PermissionObject as GROUP with Entra group ID |
| Teams (Owner/Access, teamtype 0/1) | Expanded to individual user PermissionObjects |
| Field Security Profiles + Field Permissions | ColumnConstraint (CLS) |
| Privilege Depth (Basic/Local/Deep/Global) | RowConstraint (RLS) with BU-aware filters |
| Business Unit Hierarchy | Descendant BU traversal for Deep-depth row filters |

## CSW Context (Top Of Mind)
Customer Service Workspace (CSW) requirements matter for connector correctness:
- Current state commonly relies on **team-owned cases** and team membership visibility.
- Exceptions may use **record-level sharing (POA/assist case patterns)**.
- Future state shifts to stronger **BU-hierarchy-driven access** and multi-persona users across BUs.
- Do not assume team-based patterns disappear immediately; code changes must preserve both current-state and future-state migration compatibility.

When evaluating impact:
- Treat BU depth semantics and ownership semantics as security-critical.
- Explicitly call out whether behavior matches Dataverse semantics for Current vs Future state.

## Privilege Depth Semantics (RLS)
Core logic is in `client.py` and `api.py`.
- **Global** -> no row filter (all rows visible)
- **Deep** -> `_owningbusinessunit_value in ('BU', 'descendant BUs')` via BU hierarchy traversal
- **Local** -> `_owningbusinessunit_value = 'BU'` (role BU only)
- **Basic** -> `_ownerid_value in ('principal IDs')` (rows owned by assigned principals)
- **Highest depth wins** for role/entity combinations

### Security-sensitive caveats
- Unknown or malformed depth currently defaults to Global in normalization paths.
- Unknown depth in row-filter builder can also fall through to no filter.
- Any change to depth normalization or fallback behavior must prefer **fail-closed** defaults unless explicitly approved.

## CLS (Column-Level Security)
- Derived from field security profiles and field permissions.
- `canread = 4` grants read; no grant = denied.
- If all columns are denied for a role+table, the table is excluded from that role.

## Config Toggles
Both CLS and RLS are YAML-gated and only meaningful with `policy_mapping: role_based`:
- `constraints.columns.columnlevelsecurity: true/false`
- `constraints.rows.rowlevelsecurity: true/false`

Important behavior:
- In `table_based` mode, constraint toggles are effectively no-op for Dataverse mapping path.
- Any change that alters this behavior must update README and tests.

## Dataverse API Conventions (`api.py`)
- Use OData `$select` - never fetch full entities.
- Use `$expand` for related collections where supported.
- Handle pagination via `@odata.nextLink`.
- Privilege pattern: `prvRead{EntityLogicalName}`.
- AAD-backed teams: teamtype 2 or 3. Owner teams: 0, Access teams: 1.

## Known Risk Areas (Must Re-check In Reviews)
1. **Depth fail-open risk**
	- Unknown depth defaults can over-grant.
2. **Basic-depth over-grant risk**
	- Ensure `_ownerid_value` logic does not unintentionally grant peer visibility beyond intended owner scope.
3. **Owner/Access team resolution edge case**
	- Multi-member teamtype 0/1 paths can degrade to unresolved GROUP objects if no Entra object ID is available.
4. **Dataverse config validation gap**
	- Validate `config.dataverse.environment_url` explicitly and fail with clear error messages.
5. **Dead/unused code paths**
	- Re-check methods like per-privilege depth helpers for usage before extending them.

## Secret Handling
- Never commit live secrets.
- `configdataverse.yaml` is intended as local-only and should remain ignored.
- Prefer Key Vault-backed secret references for production-like examples and docs.
- If a secret appears in logs/chat/context, recommend rotation.

## Test Conventions
| Test File | Covers |
|---|---|
| `test_dataverse_depth_precedence.py` | Highest-depth-wins across multiple roles |
| `test_dataverse_row_filter_columns.py` | Row filter column semantics per depth |
| `test_dataverse_permission_object_resolution.py` | User/team -> PermissionObject mapping |
| `test_dataverse_role_naming_context.py` | Role name generation and deduplication |
| `test_dataverse_business_unit_query_filter.py` | BU query and hierarchy behavior |

- Test both config-enabled and config-disabled paths for CLS/RLS gated logic.
- Add targeted tests for every security-impacting change (especially depth fallback and owner/team resolution).
- Keep test data minimal: include only fields used by the unit under test.
- Name tests: `test_<what>_<condition>_<expected>`.

## Code Style
- Type hints on all function signatures and return types.

Important remaining gaps:

Dedupe-by-Entra-ID behavior in policy assembly is not directly asserted.
Current tests focus on resolver output, not dedupe in role/table export builders in client.py.
Dataverse config validation is not currently covered by dedicated tests.
The validation path exists in client.py, but there is no focused test file for invalid/missing URL cases.
Basic-depth over-grant semantic concern is still not explicitly tested for owner-only equivalence behavior.