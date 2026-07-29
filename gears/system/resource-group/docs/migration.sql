-- Created:  2026-03-06 by Constructor Tech
-- Updated:  2026-07-29 by Constructor Tech

-- Reference DDL for the resource-group gear.
--
-- The authoritative migration is
-- `resource-group/src/infra/storage/migrations/m20260306_000001_initial.rs`; this file is a
-- readable rendering of it, kept in sync by hand. Differences that are intentional and cosmetic:
-- the Rust migration wraps every statement in `IF NOT EXISTS` (omitted here for readability) and
-- carries no `COMMENT ON` statements (the comments below document intent for DBAs and are not
-- applied by the migration). Everything else — types, constraints, constraint names, indexes —
-- matches the migration statement for statement. MySQL is rejected outright by the migration:
-- only PostgreSQL and SQLite are supported.

-- ═════════════════════════════════════════════════════════════════════════════
-- PostgreSQL
-- ═════════════════════════════════════════════════════════════════════════════

-- ── GTS type path domain ─────────────────────────────────────────────────────
-- GTS type identifier: single or chained, always ends with ~ (schema, not instance).
-- Format: gts.<vendor>.<package>.<namespace>.<type>.v<MAJOR>[.<MINOR>][~<segment>]*~
-- Spec:   https://github.com/GlobalTypeSystem/gts-spec
--
-- The DOMAIN constrains length only. Format is validated at the application layer
-- (`domain::validation::validate_type_code`), which checks the `gts.cf.core.rg.type.v1~` prefix,
-- non-emptiness and the 1024-character limit. There is deliberately no regex CHECK here: a
-- database-level pattern would have to be kept in sync with the GTS grammar by hand.
CREATE DOMAIN gts_type_path AS TEXT
    CHECK (
        LENGTH(VALUE) <= 1024
    );

-- ── GTS types ────────────────────────────────────────────────────────────────

CREATE TABLE gts_type (
    id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    schema_id gts_type_path NOT NULL UNIQUE,
    metadata_schema JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT NULL
);

COMMENT ON TABLE gts_type
    IS 'GTS type definitions. schema_id = GTS type path ($id without the gts:// prefix); the UNIQUE constraint is case-sensitive. metadata_schema holds the JSON Schema for the metadata object of instances of this type (e.g. tenant barrier, department category) and additionally carries reserved system keys prefixed with __: __can_be_root stores the can_be_root flag (there is no column for it), and __user_schema wraps a non-object user schema. Reserved keys are stripped on read; when __can_be_root is absent, can_be_root falls back to allowed_parent_types being empty. Surrogate SMALLINT id is used as the FK from resource_group, resource_group_membership and the junction tables; it is never exposed through the API.';

-- ── GTS type relationships (junction tables) ─────────────────────────────────

CREATE TABLE gts_type_allowed_parent (
    type_id        SMALLINT NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    parent_type_id SMALLINT NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    PRIMARY KEY (type_id, parent_type_id)
);

COMMENT ON TABLE gts_type_allowed_parent
    IS 'Many-to-many: which GTS types are allowed as parents for a given RG type. E.g. department → tenant means departments can be children of tenants.';

CREATE TABLE gts_type_allowed_membership (
    type_id            SMALLINT NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    membership_type_id SMALLINT NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    PRIMARY KEY (type_id, membership_type_id)
);

COMMENT ON TABLE gts_type_allowed_membership
    IS 'Many-to-many: which resource types are allowed as members of groups of a given RG type. E.g. branch → user means users can be members of branches.';

-- NOTE: The placement invariant (can_be_root OR at least one allowed_parent) is enforced at the
-- application layer, not by a constraint.

-- ── Resource groups ──────────────────────────────────────────────────────────

CREATE TABLE resource_group (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID,
    gts_type_id SMALLINT NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    metadata JSONB,
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT NULL,
    CONSTRAINT fk_rg_gts_type
        FOREIGN KEY (gts_type_id)
        REFERENCES gts_type(id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_resource_group_parent
        FOREIGN KEY (parent_id)
        REFERENCES resource_group(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
);

-- ── resource_group indexes ─────────────────────────────────────────────────

-- parent_id: equality and IN filters
CREATE INDEX idx_rg_parent_id
    ON resource_group (parent_id);

-- name: equality and IN filters
CREATE INDEX idx_rg_name
    ON resource_group (name);

-- gts_type_id + id: composite allows seek by type and ordered scan by id (avoids PK scan + filter)
CREATE INDEX idx_rg_gts_type_id
    ON resource_group (gts_type_id, id);

-- tenant_id: SecureORM injects WHERE tenant_id IN (...) on every query via AccessScope
CREATE INDEX idx_rg_tenant_id
    ON resource_group (tenant_id);

COMMENT ON TABLE resource_group
    IS 'Hierarchical resource groups with closure table pattern for efficient ancestor/descendant queries';
COMMENT ON COLUMN resource_group.parent_id
    IS 'Direct parent group reference; NULL for root groups (e.g. top-level tenants)';
COMMENT ON COLUMN resource_group.gts_type_id
    IS 'Reference to gts_type.id defining the type of this resource group. Immutable after creation: the update path reuses the stored value.';
COMMENT ON COLUMN resource_group.tenant_id
    IS 'Owning tenant. For a tenant-typed group (schema_id starting with the tenant RG type path) the effective tenant is the group''s own id. This is the column SecureORM filters on; the five other tables carry no tenant column and are marked no_tenant, which makes them deny-all unless a caller path supplies an explicit scope.';
COMMENT ON COLUMN resource_group.updated_at
    IS 'Rewritten on every successful update, including updates that change no field values.';

-- ── Closure table ────────────────────────────────────────────────────────────

CREATE TABLE resource_group_closure (
    ancestor_id UUID NOT NULL,
    descendant_id UUID NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT fk_closure_ancestor
        FOREIGN KEY (ancestor_id)
        REFERENCES resource_group(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT fk_closure_descendant
        FOREIGN KEY (descendant_id)
        REFERENCES resource_group(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT
);

COMMENT ON TABLE resource_group_closure
    IS 'Closure table for resource group hierarchy - stores all ancestor-descendant relationships with depth';
COMMENT ON COLUMN resource_group_closure.depth
    IS 'Distance between ancestor and descendant: 0 = self-reference, 1 = direct descendant, 2+ = deeper descendants';

-- Closure indexes: JOIN on descendant_id and filter by ancestor+depth
CREATE INDEX idx_rgc_descendant_id
    ON resource_group_closure (descendant_id);

CREATE INDEX idx_rgc_ancestor_depth
    ON resource_group_closure (ancestor_id, depth);

-- ── Memberships ──────────────────────────────────────────────────────────────

CREATE TABLE resource_group_membership (
    group_id UUID NOT NULL,
    gts_type_id SMALLINT NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_rgm_group_id
        FOREIGN KEY (group_id)
        REFERENCES resource_group(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT fk_rgm_gts_type
        FOREIGN KEY (gts_type_id)
        REFERENCES gts_type(id)
        ON DELETE RESTRICT,
    PRIMARY KEY (group_id, gts_type_id, resource_id)
);

COMMENT ON TABLE resource_group_membership
    IS 'Links resources to groups. The composite (group_id, gts_type_id, resource_id) is the PRIMARY KEY, so uniqueness is enforced by the PK rather than by a separately named UNIQUE constraint; a duplicate insert surfaces as a unique-violation and is classified into a typed DuplicateMembership (HTTP 409). There is no tenant column: tenant scope is derived from the referenced group, and scoped list queries add a correlated EXISTS against resource_group.';

-- ── resource_group_membership indexes ──────────────────────────────────────

-- gts_type_id + resource_id (without group_id): supports membership lookups by resource
CREATE INDEX idx_rgm_gts_type_resource
    ON resource_group_membership (gts_type_id, resource_id);

-- ═════════════════════════════════════════════════════════════════════════════
-- SQLite
-- ═════════════════════════════════════════════════════════════════════════════
--
-- The migration ships a second branch for SQLite, used by the unit and integration test suites and
-- by the local e2e stack. It is structurally identical — same tables, same constraint names, same
-- four + two + one indexes — and differs only in the type system:
--
--   * gts_type.id            INTEGER PRIMARY KEY AUTOINCREMENT   (instead of SMALLINT IDENTITY)
--   * UUID columns           TEXT
--   * JSONB columns          TEXT   (metadata, metadata_schema)
--   * TIMESTAMPTZ columns    TEXT DEFAULT (datetime('now'))
--   * resource_group.id      TEXT PRIMARY KEY with no default — the application supplies the UUID
--   * no CREATE DOMAIN       (SQLite has no DOMAIN concept; the length limit is not enforced by
--                             the schema on this backend)
--
-- Note that `ON DELETE`/`ON UPDATE` clauses are only honoured when `PRAGMA foreign_keys = ON`.

CREATE TABLE gts_type (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_id TEXT NOT NULL UNIQUE,
    metadata_schema TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT NULL
);

CREATE TABLE gts_type_allowed_parent (
    type_id        INTEGER NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    parent_type_id INTEGER NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    PRIMARY KEY (type_id, parent_type_id)
);

CREATE TABLE gts_type_allowed_membership (
    type_id            INTEGER NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    membership_type_id INTEGER NOT NULL REFERENCES gts_type(id) ON DELETE CASCADE,
    PRIMARY KEY (type_id, membership_type_id)
);

CREATE TABLE resource_group (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    gts_type_id INTEGER NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    metadata TEXT,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT NULL,
    CONSTRAINT fk_rg_gts_type
        FOREIGN KEY (gts_type_id) REFERENCES gts_type(id) ON DELETE RESTRICT,
    CONSTRAINT fk_resource_group_parent
        FOREIGN KEY (parent_id) REFERENCES resource_group(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE INDEX idx_rg_parent_id ON resource_group (parent_id);
CREATE INDEX idx_rg_name ON resource_group (name);
CREATE INDEX idx_rg_gts_type_id ON resource_group (gts_type_id, id);
CREATE INDEX idx_rg_tenant_id ON resource_group (tenant_id);

CREATE TABLE resource_group_closure (
    ancestor_id TEXT NOT NULL,
    descendant_id TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT fk_closure_ancestor
        FOREIGN KEY (ancestor_id) REFERENCES resource_group(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_closure_descendant
        FOREIGN KEY (descendant_id) REFERENCES resource_group(id)
        ON UPDATE CASCADE ON DELETE RESTRICT
);

CREATE INDEX idx_rgc_descendant_id ON resource_group_closure (descendant_id);
CREATE INDEX idx_rgc_ancestor_depth ON resource_group_closure (ancestor_id, depth);

CREATE TABLE resource_group_membership (
    group_id TEXT NOT NULL,
    gts_type_id INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    CONSTRAINT fk_rgm_group_id
        FOREIGN KEY (group_id) REFERENCES resource_group(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_rgm_gts_type
        FOREIGN KEY (gts_type_id) REFERENCES gts_type(id) ON DELETE RESTRICT,
    PRIMARY KEY (group_id, gts_type_id, resource_id)
);

CREATE INDEX idx_rgm_gts_type_resource
    ON resource_group_membership (gts_type_id, resource_id);

-- ═════════════════════════════════════════════════════════════════════════════
-- Rollback
-- ═════════════════════════════════════════════════════════════════════════════
--
-- The migration's `down()` drops the tables in FK-safe order on both backends, and additionally
-- drops the DOMAIN on PostgreSQL.

DROP TABLE IF EXISTS resource_group_membership;
DROP TABLE IF EXISTS resource_group_closure;
DROP TABLE IF EXISTS resource_group;
DROP TABLE IF EXISTS gts_type_allowed_membership;
DROP TABLE IF EXISTS gts_type_allowed_parent;
DROP TABLE IF EXISTS gts_type;

-- PostgreSQL only:
DROP DOMAIN IF EXISTS gts_type_path;
