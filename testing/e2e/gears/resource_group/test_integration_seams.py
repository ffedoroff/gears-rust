# Created: 2026-04-16 by Constructor Tech
# @cpt-dod:cpt-cf-resource-group-dod-e2e-test-suite:p1
"""E2E integration seam tests for resource-group gear (Feature 0007).

11 tests. One file. < 15 seconds. Zero flakes.

Each test guards a specific integration seam -- a point where two independently
correct components can break when connected. If the seam is already covered by
a unit test (Feature 0006), there is no E2E test for it.

See: gears/system/resource-group/docs/features/0007-e2e-testing.md
"""
import os
import uuid

import httpx
import pytest

from .conftest import REQUEST_TIMEOUT, assert_group_shape


# ── URL helpers ──────────────────────────────────────────────────────────


def _groups(base: str) -> str:
    return f"{base}/resource-group/v1/groups"


def _types(base: str) -> str:
    return f"{base}/types-registry/v1/types"


def _memberships(base: str) -> str:
    return f"{base}/resource-group/v1/memberships"


# ── S1: Route smoke ─────────────────────────────────────────────────────


@pytest.mark.smoke
async def test_route_smoke_all_endpoints(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Route registration -- handlers mounted on correct method + path.

    Verifies every endpoint/method combination responds (not 404/405), meaning
    routes are registered and handlers are wired. Endpoints already exercised
    by S2-S10 are not repeated here; this test covers only the gaps.
    """
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        h = rg_headers

        # --- Endpoints NOT covered by other seam tests ---

        # GET /types -- list types, not exercised elsewhere
        r = await c.get(_types(rg_base_url), headers=h)
        assert r.status_code not in (404, 405), f"GET /types: {r.status_code}"

        # GET /types/{code} -- get single type, not exercised elsewhere
        type_data = await create_type("s1route")
        type_code = type_data["code"]
        r = await c.get(f"{_types(rg_base_url)}/{type_code}", headers=h)
        assert r.status_code not in (404, 405), f"GET /types/{{code}}: {r.status_code}"

        # PUT /types/{code} -- update type, not exercised elsewhere.
        # A full replacement: every replaceable field must be present, and
        # `code` must NOT be (it is the identity, taken from the path, and the
        # body rejects unknown fields).
        r = await c.put(
            f"{_types(rg_base_url)}/{type_code}", headers=h,
            json={
                "can_be_root": True,
                "allowed_parent_types": [],
                "allowed_membership_types": [],
                "metadata_schema": None,
            },
        )
        assert r.status_code == 200, f"PUT /types/{{code}}: {r.status_code} {r.text}"

        # DELETE /types/{code} -- delete type, not exercised elsewhere
        del_type = await create_type("s1del")
        r = await c.delete(f"{_types(rg_base_url)}/{del_type['code']}", headers=h)
        assert r.status_code not in (404, 405), f"DELETE /types/{{code}}: {r.status_code}"

        # DELETE /memberships/{group_id}/{type}/{id} -- not exercised elsewhere
        member_type = await create_type("s1mem", allowed_membership_types=[])
        org_type = await create_type("s1org", allowed_membership_types=[member_type["code"]])
        group = await create_group(org_type["code"], "S1 Route")
        r = await c.post(
            f"{_memberships(rg_base_url)}/{group['id']}/{member_type['code']}/res-s1",
            headers=h,
        )
        assert r.status_code == 201, f"POST membership setup: {r.status_code}"
        r = await c.delete(
            f"{_memberships(rg_base_url)}/{group['id']}/{member_type['code']}/res-s1",
            headers=h,
        )
        assert r.status_code not in (404, 405), f"DELETE /memberships/...: {r.status_code}"

        # GET /groups/{id}/descendants -- hierarchy endpoint
        grp = await create_group(org_type["code"], "S1 Desc")
        r = await c.get(
            f"{_groups(rg_base_url)}/{grp['id']}/descendants", headers=h,
        )
        assert r.status_code not in (404, 405), f"GET /groups/{{id}}/descendants: {r.status_code}"

        # GET /groups/{id}/ancestors -- hierarchy endpoint
        r = await c.get(
            f"{_groups(rg_base_url)}/{grp['id']}/ancestors", headers=h,
        )
        assert r.status_code not in (404, 405), f"GET /groups/{{id}}/ancestors: {r.status_code}"


# ── S2: DTO roundtrip ───────────────────────────────────────────────────


@pytest.mark.smoke
async def test_dto_roundtrip_group_json_shape(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: DTO serialization -- JSON field names, types match OpenAPI contract.

    Unit tests (0006 G39-G45) test Rust struct conversions, NOT the JSON wire
    format. A serde attribute typo passes unit tests but breaks clients.
    """
    type_data = await create_type("s2dto")
    group = await create_group(
        type_data["code"], "S2 DTO Test", metadata={"self_managed": True},
    )

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            f"{_groups(rg_base_url)}/{group['id']}", headers=rg_headers,
        )
        assert r.status_code == 200
        data = r.json()

    # Structural validation
    assert_group_shape(data)

    # Exact top-level key set (no internal field leaks)
    allowed_top_keys = {"id", "type", "name", "hierarchy", "metadata"}
    assert set(data.keys()) <= allowed_top_keys, (
        f"Unexpected top-level keys: {set(data.keys()) - allowed_top_keys}"
    )
    assert "metadata" in data
    assert data["metadata"] == {"self_managed": True}

    # "type" key (NOT legacy "type_path" or "gts_type_id")
    assert "type" in data
    assert "type_path" not in data
    assert "gts_type_id" not in data

    # Hierarchy sub-object -- exact key set
    hier = data["hierarchy"]
    allowed_hier_keys = {"tenant_id", "parent_id"}
    assert set(hier.keys()) <= allowed_hier_keys, (
        f"Unexpected hierarchy keys: {set(hier.keys()) - allowed_hier_keys}"
    )
    assert "tenant_id" in hier
    # Root group: parent_id absent or null
    assert hier.get("parent_id") is None

    # No timestamps in GroupDto (per DESIGN)
    assert "created_at" not in data
    assert "updated_at" not in data


# ── S3: AuthZ tenant filter ─────────────────────────────────────────────


@pytest.mark.smoke
async def test_authz_tenant_filter_applied(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: AuthZ -> SecureORM -- SecurityContext produces correct tenant filter.

    Unit tests mock PolicyEnforcer; real wiring only exists in gear.rs.
    """
    type_data = await create_type("s3authz")
    type_code = type_data["code"]
    group = await create_group(type_code, "S3 AuthZ Test")
    group_id = group["id"]
    tenant_id = group["hierarchy"]["tenant_id"]

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # List filtered by unique type -- created group must appear
        r = await c.get(
            _groups(rg_base_url), headers=rg_headers,
            params={"$filter": f"type eq '{type_code}'"},
        )
        assert r.status_code == 200
        ids = [item["id"] for item in r.json()["items"]]
        assert group_id in ids, "Created group not found in filtered list"

        # GET -- tenant_id must match
        r = await c.get(
            f"{_groups(rg_base_url)}/{group_id}", headers=rg_headers,
        )
        assert r.status_code == 200
        assert r.json()["hierarchy"]["tenant_id"] == tenant_id


# ── S4: Cross-tenant invisible ──────────────────────────────────────────


async def test_cross_tenant_invisible(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Same as S3 but negative -- tenant boundary enforced.

    Uses two real HTTP tokens producing different SecurityContexts.
    Defaults to e2e-token-tenant-b (configured in config/e2e-local.yaml).
    """
    token_b = os.getenv("E2E_AUTH_TOKEN_TENANT_B", "e2e-token-tenant-b")

    headers_b = {**rg_headers, "Authorization": f"Bearer {token_b}"}

    type_data = await create_type("s4xtenant")
    type_code = type_data["code"]
    group = await create_group(type_code, "S4 Cross-Tenant")
    group_id = group["id"]

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # Token B: single-entity GET -> 404 (hides existence)
        r = await c.get(
            f"{_groups(rg_base_url)}/{group_id}", headers=headers_b,
        )
        assert r.status_code == 404, (
            f"Cross-tenant GET should be 404, got {r.status_code}"
        )

        # Token B: list filtered by type -- group not in items
        r = await c.get(
            _groups(rg_base_url), headers=headers_b,
            params={"$filter": f"type eq '{type_code}'"},
        )
        assert r.status_code == 200
        ids = [item["id"] for item in r.json()["items"]]
        assert group_id not in ids, "Group visible to other tenant"

        # Token A: still visible
        r = await c.get(
            f"{_groups(rg_base_url)}/{group_id}", headers=rg_headers,
        )
        assert r.status_code == 200


# ── S5: Hierarchy + closure ─────────────────────────────────────────────


@pytest.mark.smoke
async def test_hierarchy_closure(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Closure table INSERT SQL across the hierarchy endpoint.

    Verifies closure rows are produced for self/descendant/ancestor with the
    expected depths over a 3-level tree. Backend-agnostic — runs on whatever
    DB the test config points the resource-group gear at.
    """
    root_type = await create_type("s5root")
    child_type = await create_type(
        "s5child", can_be_root=False, allowed_parent_types=[root_type["code"]],
    )
    gc_type = await create_type(
        "s5gc", can_be_root=False, allowed_parent_types=[child_type["code"]],
    )

    root = await create_group(root_type["code"], "S5 Root")
    child = await create_group(child_type["code"], "S5 Child", parent_id=root["id"])
    grandchild = await create_group(gc_type["code"], "S5 Grandchild", parent_id=child["id"])

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # Hierarchy from root
        r = await c.get(
            f"{_groups(rg_base_url)}/{root['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 3, f"Expected 3 items, got {len(items)}"

        by_id = {item["id"]: item for item in items}
        assert by_id[root["id"]]["hierarchy"]["depth"] == 0
        assert by_id[child["id"]]["hierarchy"]["depth"] == 1
        assert by_id[grandchild["id"]]["hierarchy"]["depth"] == 2

        # Descendants from child: self + grandchild
        r = await c.get(
            f"{_groups(rg_base_url)}/{child['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 2  # self(child) + descendant(grandchild)
        by_id = {item["id"]: item for item in items}
        assert by_id[child["id"]]["hierarchy"]["depth"] == 0
        assert by_id[grandchild["id"]]["hierarchy"]["depth"] == 1

        # Ancestors from child: self + root
        r = await c.get(
            f"{_groups(rg_base_url)}/{child['id']}/ancestors",
            headers=rg_headers,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) == 2  # self(child) + ancestor(root)
        by_id = {item["id"]: item for item in items}
        assert by_id[root["id"]]["hierarchy"]["depth"] == -1
        assert by_id[child["id"]]["hierarchy"]["depth"] == 0


# ── S6: Move + closure rebuild ──────────────────────────────────────────


async def test_move_closure_rebuild(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Closure table DELETE + re-INSERT on parent change.

    Driven through POST /groups/{id}/move -- the dedicated structural
    operation. The move runs DELETE FROM closure WHERE descendant IN (subtree)
    then INSERT INTO...SELECT new paths. Verifies the subtree is detached from
    the old root and reattached to the new root with correct depths, and that
    the strict PUT no longer accepts the structural field.
    Backend-agnostic.
    """
    root_type = await create_type("s6root")
    child_type = await create_type(
        "s6child", can_be_root=False, allowed_parent_types=[root_type["code"]],
    )
    gc_type = await create_type(
        "s6gc", can_be_root=False, allowed_parent_types=[child_type["code"]],
    )

    root_a = await create_group(root_type["code"], "S6 Root A")
    child = await create_group(child_type["code"], "S6 Child", parent_id=root_a["id"])
    grandchild = await create_group(gc_type["code"], "S6 Grandchild", parent_id=child["id"])
    root_b = await create_group(root_type["code"], "S6 Root B")

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # Move child subtree from root_a to root_b.
        #
        # Moving is its own operation: POST /groups/{id}/move with a mandatory
        # `parent_id`. It used to be a field on PUT, where this very request
        # also carried `type` -- silently discarded, because a group's type is
        # immutable -- and returned 200 anyway. The move body rejects unknown
        # fields, so that mistake is now impossible to make quietly.
        r = await c.post(
            f"{_groups(rg_base_url)}/{child['id']}/move",
            headers=rg_headers,
            json={"parent_id": root_b["id"]},
        )
        assert r.status_code == 200, f"Move failed: {r.status_code} {r.text}"
        assert r.json()["hierarchy"]["parent_id"] == root_b["id"]

        # PUT no longer accepts `parent_id` (nor the immutable `type`): a
        # client still sending the pre-split payload gets an explicit 400
        # instead of a silently-dropped mutation.
        r = await c.put(
            f"{_groups(rg_base_url)}/{child['id']}",
            headers=rg_headers,
            json={"name": "S6 Child", "parent_id": root_a["id"], "metadata": None},
        )
        assert r.status_code == 400, (
            f"PUT with parent_id must be rejected: {r.status_code} {r.text}"
        )

        # ...and PUT without `metadata` is a 400 too, rather than a 200 that
        # silently erases the stored metadata.
        r = await c.put(
            f"{_groups(rg_base_url)}/{child['id']}",
            headers=rg_headers,
            json={"name": "S6 Child"},
        )
        assert r.status_code == 400, (
            f"PUT without metadata must be rejected: {r.status_code} {r.text}"
        )

        # root_a hierarchy: only root_a remains
        r = await c.get(
            f"{_groups(rg_base_url)}/{root_a['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        ids_a = [i["id"] for i in r.json()["items"]]
        assert child["id"] not in ids_a, "Child still in old tree after move"

        # root_b hierarchy: root_b + moved subtree
        r = await c.get(
            f"{_groups(rg_base_url)}/{root_b['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        by_id = {i["id"]: i for i in r.json()["items"]}
        assert child["id"] in by_id, "Child not in new tree"
        assert grandchild["id"] in by_id, "Grandchild not in new tree"
        assert by_id[child["id"]]["hierarchy"]["depth"] == 1
        assert by_id[grandchild["id"]]["hierarchy"]["depth"] == 2

        # Subtree from child preserved
        r = await c.get(
            f"{_groups(rg_base_url)}/{child['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        child_items = r.json()["items"]
        child_ids = [i["id"] for i in child_items]
        assert grandchild["id"] in child_ids, "Grandchild lost from subtree"


# ── S7: Force delete cascade ────────────────────────────────────────────


@pytest.mark.smoke
async def test_force_delete_cascade(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: FK ON DELETE RESTRICT + service-level cascade ordering.

    Force delete must delete in correct order: memberships first, then
    children bottom-up, then target. Wrong order fails on FK constraints.
    Backend-agnostic — exercised against whatever DB the test config uses.
    """
    member_type = await create_type("s7member")
    root_type = await create_type(
        "s7root", allowed_membership_types=[member_type["code"]],
    )
    child_type = await create_type(
        "s7child", can_be_root=False,
        allowed_parent_types=[root_type["code"]],
        allowed_membership_types=[member_type["code"]],
    )

    root = await create_group(root_type["code"], "S7 Root")
    child = await create_group(child_type["code"], "S7 Child", parent_id=root["id"])

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # Add membership on child
        r = await c.post(
            f"{_memberships(rg_base_url)}/{child['id']}/{member_type['code']}/res-s7",
            headers=rg_headers,
        )
        assert r.status_code == 201, f"Add membership: {r.status_code} {r.text}"

        # Force delete root
        r = await c.delete(
            f"{_groups(rg_base_url)}/{root['id']}",
            headers=rg_headers,
            params={"force": "true"},
        )
        assert r.status_code == 204

        # Root gone
        r = await c.get(
            f"{_groups(rg_base_url)}/{root['id']}", headers=rg_headers,
        )
        assert r.status_code == 404

        # Child gone (cascade)
        r = await c.get(
            f"{_groups(rg_base_url)}/{child['id']}", headers=rg_headers,
        )
        assert r.status_code == 404

        # Membership cleaned up
        r = await c.get(
            _memberships(rg_base_url), headers=rg_headers,
            params={"$filter": f"group_id eq {child['id']}"},
        )
        assert r.status_code == 200
        assert len(r.json()["items"]) == 0, "Membership not cleaned up"


# ── S8: Error response format ───────────────────────────────────────────


@pytest.mark.smoke
async def test_error_response_rfc9457(rg_base_url, rg_headers):
    """Seam: Error middleware -- DomainError -> application/problem+json.

    Unit tests assert DomainError variant, not HTTP headers. If the error handler
    is missing, clients get generic framework errors instead of RFC 9457.
    One 404 path is enough to confirm the middleware is wired. Duplicate/409
    is left to Rust REST tests.
    """
    rid = str(uuid.uuid4())

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            f"{_groups(rg_base_url)}/{rid}", headers=rg_headers,
        )
        assert r.status_code == 404
        ct = r.headers.get("content-type", "")
        assert "application/problem+json" in ct, (
            f"Expected problem+json, got: {ct}"
        )
        body = r.json()
        assert body.get("status") == 404
        assert "title" in body
        assert "detail" in body
        # No internal leaks
        assert "stack" not in body
        assert "trace" not in body


# ── S9: Cursor pagination ───────────────────────────────────────────────


async def test_pagination_cursor_roundtrip(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Cursor encode/decode across HTTP -- no duplicates, no missing.

    0006 tests Page<T> construction. The cursor codec (base64 encode/decode)
    only runs in the handler layer over HTTP.
    """
    type_data = await create_type("s9page")
    type_code = type_data["code"]
    created_ids = set()
    for i in range(5):
        g = await create_group(type_code, f"S9 Page {i}")
        created_ids.add(g["id"])

    # Paginate with limit=2, filtered to our type only
    all_ids = []
    cursor = None
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        for _ in range(10):  # safety cap
            params = {
                "limit": "2",
                "$filter": f"type eq '{type_code}'",
            }
            if cursor:
                params["cursor"] = cursor

            r = await c.get(
                _groups(rg_base_url), headers=rg_headers, params=params,
            )
            assert r.status_code == 200
            data = r.json()

            page_ids = [item["id"] for item in data["items"]]
            all_ids.extend(page_ids)

            page_info = data["page_info"]
            next_cur = page_info.get("next_cursor")
            if not next_cur:
                break
            cursor = next_cur

    # No duplicates
    assert len(all_ids) == len(set(all_ids)), (
        f"Duplicate IDs in pagination: {all_ids}"
    )
    # All created groups present
    for gid in created_ids:
        assert gid in all_ids, f"Group {gid} missing from paginated results"


# ── S10: Membership filter wiring ───────────────────────────────────────


@pytest.mark.smoke
async def test_membership_filter_wiring(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: OData $filter parsing -> SQL WHERE for memberships.

    0006 verifies field mapping. The full chain -- HTTP $filter -> OData parser
    -> FilterField -> SQL WHERE -- is never tested end-to-end.
    """
    member_type = await create_type("s10member")
    org_type = await create_type("s10org", allowed_membership_types=[member_type["code"]])

    group_a = await create_group(org_type["code"], "S10 Group A")
    group_b = await create_group(org_type["code"], "S10 Group B")

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # Add memberships to different groups
        r = await c.post(
            f"{_memberships(rg_base_url)}/{group_a['id']}/{member_type['code']}/res-1",
            headers=rg_headers,
        )
        assert r.status_code == 201

        r = await c.post(
            f"{_memberships(rg_base_url)}/{group_b['id']}/{member_type['code']}/res-2",
            headers=rg_headers,
        )
        assert r.status_code == 201

        # Filter by group_a -- should only see res-1
        r = await c.get(
            _memberships(rg_base_url), headers=rg_headers,
            params={"$filter": f"group_id eq {group_a['id']}"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert all(
            m["group_id"] == group_a["id"] for m in items
        ), "Filter leaked items from other group"
        assert any(m["resource_id"] == "res-1" for m in items)
        assert not any(m["resource_id"] == "res-2" for m in items)

        # Filter by group_b -- should only see res-2
        r = await c.get(
            _memberships(rg_base_url), headers=rg_headers,
            params={"$filter": f"group_id eq {group_b['id']}"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert all(m["group_id"] == group_b["id"] for m in items)
        assert any(m["resource_id"] == "res-2" for m in items)


# ── S10b: Membership filter by resource_type (VHP-1731) ─────────────────


async def test_membership_filter_by_resource_type(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: OData $filter on `resource_type` -- GTS type-path string ->
    SMALLINT surrogate resolution at the persistence boundary (VHP-1731).

    `resource_type` is exposed on the wire as a GTS type-path string but
    stored as the SMALLINT `gts_type_id` column; the repository must resolve
    the string to its surrogate id before filtering, mirroring the `type`
    resolution `list_groups` already does. S10 above only filters on
    `group_id`, so this seam -- resolve-then-filter for `resource_type` --
    was never exercised end-to-end.

    NOTE: added alongside a fix for VHP-1954/VHP-1731; not run locally (no
    live cluster in this environment) -- verify against a real deployment.
    """
    member_type_a = await create_type("s10ta")
    member_type_b = await create_type("s10tb")
    org_type = await create_type(
        "s10torg",
        allowed_membership_types=[member_type_a["code"], member_type_b["code"]],
    )
    group = await create_group(org_type["code"], "S10b Group")

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.post(
            f"{_memberships(rg_base_url)}/{group['id']}/{member_type_a['code']}/res-a",
            headers=rg_headers,
        )
        assert r.status_code == 201

        r = await c.post(
            f"{_memberships(rg_base_url)}/{group['id']}/{member_type_b['code']}/res-b",
            headers=rg_headers,
        )
        assert r.status_code == 201

        # Filter by resource_type -- should only see res-a
        r = await c.get(
            _memberships(rg_base_url), headers=rg_headers,
            params={"$filter": f"resource_type eq '{member_type_a['code']}'"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        assert any(m["resource_id"] == "res-a" for m in items), (
            "resource_type filter must resolve the GTS path to its surrogate "
            f"id and return res-a: {items}"
        )
        assert not any(m["resource_id"] == "res-b" for m in items), (
            f"resource_type filter leaked res-b: {items}"
        )


# ── S10c: Quoted-UUID $filter must be 400, not 500 (VHP-1954) ───────────


async def test_membership_filter_group_id_quoted_uuid_returns_400(
    rg_base_url, rg_headers,
):
    """Seam: client-caused $filter errors -> 400, not 500 (VHP-1954).

    The OData grammar only parses a *bare* hex8-4-4-4-12 UUID literal as
    `Value::Uuid`; the same literal wrapped in single quotes parses as
    `Value::String`, which fails `FilterField` validation for `group_id`
    (Uuid-kind) -- exactly the shape the ticket's reporter hit. Before the
    fix this was folded into a blanket `DomainError::database(..)`, turning
    a client mistake into a 500; S10 above never caught it because it always
    sends the bare (unquoted) form.

    NOTE: added alongside a fix for VHP-1954/VHP-1731; not run locally (no
    live cluster in this environment) -- verify against a real deployment.
    """
    some_uuid = str(uuid.uuid4())

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        r = await c.get(
            _memberships(rg_base_url), headers=rg_headers,
            params={"$filter": f"group_id eq '{some_uuid}'"},
        )
        assert r.status_code == 400, (
            f"quoted-UUID $filter must be a 400 client error, "
            f"not {r.status_code}: {r.text}"
        )


# ── S11: Hierarchy depth filter wiring ─────────────────────────────────


async def test_hierarchy_depth_filter_wiring(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: OData hierarchy/depth filter -> SQL shaping -> response subset.

    The full chain -- HTTP query string -> OData parser -> hierarchy filter
    extraction -> SQL WHERE -> correct depth subset -- is never tested E2E.
    """
    root_type = await create_type("s11root")
    child_type = await create_type(
        "s11child", can_be_root=False, allowed_parent_types=[root_type["code"]],
    )
    gc_type = await create_type(
        "s11gc", can_be_root=False, allowed_parent_types=[child_type["code"]],
    )

    root = await create_group(root_type["code"], "S11 Root")
    child = await create_group(child_type["code"], "S11 Child", parent_id=root["id"])
    grandchild = await create_group(gc_type["code"], "S11 GC", parent_id=child["id"])

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # /descendants returns self + descendants (depth >= 0), so a `ge 0`
        # predicate would be tautological. Use `eq 1` to actually exercise
        # the filter -> SQL shaping seam: self (depth=0) must be filtered
        # out, only the immediate descendant (depth=1) remains.
        r = await c.get(
            f"{_groups(rg_base_url)}/{child['id']}/descendants",
            headers=rg_headers,
            params={"$filter": "hierarchy/depth eq 1"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        by_id = {item["id"]: item for item in items}

        # Root is an ancestor: never returned by /descendants regardless of filter
        assert root["id"] not in by_id, "Ancestor must not be returned by /descendants"

        # Child (self, depth=0) must be filtered out by `eq 1`
        assert child["id"] not in by_id, "Self node should be filtered out by depth eq 1"

        # Grandchild (descendant, depth=1) must remain
        assert grandchild["id"] in by_id, "Descendant missing"
        assert by_id[grandchild["id"]]["hierarchy"]["depth"] == 1


# ── S12: Barrier metadata preserved in hierarchy ──────────────────────


async def test_barrier_metadata_in_descendants(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: Barrier data flows through RG HTTP hierarchy endpoint.

    RG does NOT filter barriers -- it returns all descendants with metadata.
    This verifies the data contract that AuthZ plugins rely on:
    barrier groups have metadata.self_managed = true, descendants are present.
    The AuthZ plugin (not RG) is responsible for excluding barrier subtrees.
    """
    root_type = await create_type("s12root")
    child_type = await create_type(
        "s12child", can_be_root=False, allowed_parent_types=[root_type["code"]],
    )
    gc_type = await create_type(
        "s12gc", can_be_root=False, allowed_parent_types=[child_type["code"]],
    )

    root = await create_group(root_type["code"], "S12 Root")
    barrier = await create_group(
        child_type["code"], "S12 Barrier",
        parent_id=root["id"], metadata={"self_managed": True},
    )
    behind = await create_group(
        gc_type["code"], "S12 Behind",
        parent_id=barrier["id"],
    )
    normal = await create_group(
        child_type["code"], "S12 Normal",
        parent_id=root["id"],
    )

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        # GET descendants of root — RG returns ALL including barrier subtree
        r = await c.get(
            f"{_groups(rg_base_url)}/{root['id']}/descendants",
            headers=rg_headers,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        ids = {item["id"] for item in items}

        # All 4 groups present (RG does not filter barriers)
        assert root["id"] in ids, "root missing"
        assert barrier["id"] in ids, "barrier missing"
        assert behind["id"] in ids, "behind-barrier missing"
        assert normal["id"] in ids, "normal missing"
        assert len(items) == 4

        # Barrier group has metadata.self_managed = true
        barrier_item = next(i for i in items if i["id"] == barrier["id"])
        assert barrier_item.get("metadata", {}).get("self_managed") is True, (
            f"self_managed metadata expected, got: {barrier_item.get('metadata')}"
        )

        # Non-barrier groups do NOT have self_managed metadata
        normal_item = next(i for i in items if i["id"] == normal["id"])
        normal_meta = normal_item.get("metadata")
        assert normal_meta is None or normal_meta.get("self_managed") is not True

# ── S12: Hierarchy cursor codec over the wire ───────────────────────────


@pytest.mark.smoke
async def test_hierarchy_cursor_codec_over_the_wire(
    rg_base_url, rg_headers, create_type, create_group,
):
    """Seam: hierarchy offset-cursor codec <-> HTTP (13_e2e_testing.md:58).

    The offset cursor of `/descendants` is a different codec from the keyset
    cursor of the flat `/groups` list, and S9 exercises only the latter. This
    one drives the hierarchy token specifically: base64url through a query
    string, back through the decoder, and on to a second page under the same
    `$filter`.

    Why this cannot move down a tier: the repository-level tests decode the
    token by calling `CursorV1::decode` directly, so they never touch URL
    encoding or the handler's parse of `?cursor=`. That part only runs here.

    What it deliberately does not test: the offset arithmetic, or whether the
    filter is honoured. Both are pinned by unit and repository tests, and
    `13:85` sends anything reachable there to those tiers. The filter below is
    a plain `type eq`, supported before this change as well, precisely so a
    failure here means the codec and not the evaluator.
    """
    root_type = await create_type("s12root")
    child_type = await create_type(
        "s12child", can_be_root=False, allowed_parent_types=[root_type["code"]],
    )

    root = await create_group(root_type["code"], "S12 Root")
    created = {
        (await create_group(child_type["code"], f"S12 Child {i}", parent_id=root["id"]))["id"]
        for i in range(3)
    }

    params = {"limit": "2", "$filter": f"type eq '{child_type['code']}'"}
    seen: list[str] = []
    cursor = None

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as c:
        for _ in range(5):  # safety cap
            page_params = dict(params)
            if cursor:
                page_params["cursor"] = cursor

            r = await c.get(
                f"{_groups(rg_base_url)}/{root['id']}/descendants",
                headers=rg_headers,
                params=page_params,
            )
            assert r.status_code == 200, (
                f"a cursor this endpoint minted must be accepted back: {r.text}"
            )
            data = r.json()
            seen.extend(item["id"] for item in data["items"])

            cursor = data["page_info"].get("next_cursor")
            if not cursor:
                break

    assert len(seen) == len(set(seen)), f"cursor round trip duplicated rows: {seen}"
    assert created <= set(seen), "cursor round trip lost rows"

