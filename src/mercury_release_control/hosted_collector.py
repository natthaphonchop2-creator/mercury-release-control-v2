"""Trusted live collector for Render, Supabase, FlowAccount, and public MCP."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

from mercury_release_control.provider_inspector import (
    InspectionError,
    inspect_supabase_connection,
    validate_database_url,
)

_EXPECTED_TOOLS = frozenset(
    {
        "check_flow_syntax",
        "connector_capabilities",
        "connector_status",
        "create_public_workspace",
        "flow_cheat_sheet",
        "get_accounting_skill_schema",
        "get_connector_setup",
        "get_document",
        "get_public_workspace",
        "inspect_flow_files",
        "link_connector_profile",
        "list_accounting_skills",
        "list_connectors",
        "list_workspace_flows",
        "retrieve_context_pack",
        "retrieve_workspace_context_pack",
        "run_accounting_skill",
        "run_flow_files",
        "run_inline_flow",
        "run_workspace_flow",
        "save_workspace_flow",
        "search_knowledge",
        "unlink_connector_profile",
        "validate_connector_connection",
    }
)
_CREDENTIAL_KEY = re.compile(
    r"(?:api[_-]?key|authorization|client[_-]?(?:id|secret)|credential|password|secret|token)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    rb"(?:gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|"
    rb"eyJ[A-Za-z0-9_-]{16,}|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)"
)
_MAX_RESPONSE = 32 * 1024 * 1024
_RENDER_OWNER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_RENDER_SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


@dataclass(frozen=True, slots=True)
class _Response:
    body: bytes
    headers: Mapping[str, str]
    status: int


class HostedProviderCollector:
    def collect(
        self,
        *,
        policy: Mapping[str, object],
        environment: Mapping[str, str],
        reviewed_sha: str,
        staging: Any,
    ) -> Mapping[str, object]:
        del staging
        required = {
            "FLOWACCOUNT_SANDBOX_BASE_URL",
            "FLOWACCOUNT_SANDBOX_CLIENT_ID",
            "FLOWACCOUNT_SANDBOX_CLIENT_SECRET",
            "MERCURY_PUBLIC_MCP_TOKEN",
            "MERCURY_PUBLIC_MCP_URL",
            "RENDER_API_TOKEN",
            "RENDER_API_URL",
            "RENDER_OWNER_ID",
            "RENDER_SERVICE_ID",
            "SUPABASE_DB_URL",
        }
        if not required <= set(environment) or any(
            not isinstance(environment[name], str) or not environment[name] for name in required
        ):
            raise InspectionError("provider_environment_invalid")
        render, public_mcp = self._render_and_mcp(environment, reviewed_sha)
        supabase = self._supabase(policy, environment)
        flowaccount = self._flowaccount(environment)
        return {
            "flowaccount": flowaccount,
            "public_mcp": public_mcp,
            "render": render,
            "supabase": supabase,
        }

    def _render_and_mcp(
        self, environment: Mapping[str, str], reviewed_sha: str
    ) -> tuple[dict[str, object], dict[str, object]]:
        public_url = _https_base(environment["MERCURY_PUBLIC_MCP_URL"])
        render_url = _https_base(environment["RENDER_API_URL"])
        if not render_url.endswith("/v1"):
            render_url += "/v1"
        service_id = environment["RENDER_SERVICE_ID"]
        owner_id = environment["RENDER_OWNER_ID"]
        if _RENDER_SERVICE_ID_RE.fullmatch(service_id) is None:
            raise InspectionError("render_service_invalid")
        if _RENDER_OWNER_ID_RE.fullmatch(owner_id) is None:
            raise InspectionError("render_owner_invalid")
        render_headers = {"Authorization": f"Bearer {environment['RENDER_API_TOKEN']}"}
        service = _json_request(f"{render_url}/services/{service_id}", headers=render_headers)
        details = service.get("serviceDetails")
        if (
            service.get("id") != service_id
            or not isinstance(details, dict)
            or details.get("url") != public_url
        ):
            raise InspectionError("render_service_binding_invalid")
        deploys = _json_request(
            f"{render_url}/services/{service_id}/deploys?limit=100",
            headers=render_headers,
        )
        if not isinstance(deploys, list) or len(deploys) > 100:
            raise InspectionError("render_deployment_invalid")
        if not any(_live_deploy(row, reviewed_sha) for row in deploys):
            raise InspectionError("render_commit_mismatch")
        health = _json_request(f"{public_url}/healthz")
        status = _json_request(f"{public_url}/api/status")
        if not isinstance(health, dict) or health.get("status") != "ok":
            raise InspectionError("render_health_invalid")
        if (
            not isinstance(status, dict)
            or status.get("status") != "ok"
            or status.get("version") != "0.3.0"
            or status.get("deployment_commit") != reviewed_sha
        ):
            raise InspectionError("render_status_invalid")
        endpoint = status.get("mcp_endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith(public_url + "/"):
            raise InspectionError("public_mcp_endpoint_invalid")
        bearer = environment["MERCURY_PUBLIC_MCP_TOKEN"]
        public_headers = {"Authorization": f"Bearer {bearer}"}
        catalog = _json_request(
            f"{public_url}/api/cloud/v1/catalog/actions", headers=public_headers
        )
        actions = catalog.get("actions") if isinstance(catalog, dict) else None
        if not isinstance(actions, list) or len(actions) != 254:
            raise InspectionError("public_mcp_catalog_inventory_invalid")
        mcp = _McpProbe(endpoint=endpoint, token=bearer)
        initialized = mcp.initialize()
        server = initialized.get("serverInfo")
        if not isinstance(server, dict) or server.get("name") != "Mercury Tools":
            raise InspectionError("public_mcp_initialize_invalid")
        tools = mcp.list_tools()
        names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
        if len(tools) != 24 or names != _EXPECTED_TOOLS:
            raise InspectionError("public_mcp_tool_inventory_invalid")
        if any(_contains_credential_key(tool.get("inputSchema")) for tool in tools):
            raise InspectionError("public_mcp_boundary_invalid")
        citations = {
            connector: mcp.citation_count(connector) for connector in ("flowaccount", "peak")
        }
        for log_type in ("build", "runtime"):
            raw = _request(
                _render_log_url(
                    render_url,
                    service_id=service_id,
                    owner_id=owner_id,
                    log_type=log_type,
                ),
                headers=render_headers,
            ).body
            _assert_no_secret(raw, environment.values())
        return (
            {
                "catalog_action_count": len(actions),
                "commit": reviewed_sha,
                "hosted_tool_count": len(tools),
                "logs_scanned": True,
                "status": "live",
                "version": "0.3.0",
            },
            {
                "catalog_action_count": len(actions),
                "flowaccount_citations": citations["flowaccount"],
                "hosted_tool_count": len(tools),
                "peak_citations": citations["peak"],
                "status": 200,
                "write_tools_exposed": False,
            },
        )

    def _supabase(
        self, policy: Mapping[str, object], environment: Mapping[str, str]
    ) -> dict[str, object]:
        supabase = policy.get("supabase")
        if not isinstance(supabase, dict):
            raise InspectionError("supabase_policy_invalid")
        project_ref = supabase.get("project_ref")
        tables = supabase.get("tables")
        functions = supabase.get("functions")
        migration_id = supabase.get("migration_id")
        if (
            not isinstance(project_ref, str)
            or not isinstance(tables, list)
            or not isinstance(functions, list)
            or not isinstance(migration_id, str)
        ):
            raise InspectionError("supabase_policy_invalid")
        expected_functions: dict[str, str] = {}
        for function in functions:
            if not isinstance(function, dict):
                raise InspectionError("supabase_policy_invalid")
            signature = function.get("signature")
            digest = function.get("definition_sha256")
            if not isinstance(signature, str) or not isinstance(digest, str):
                raise InspectionError("supabase_policy_invalid")
            expected_functions[signature] = digest
        database_url = environment["SUPABASE_DB_URL"]
        validate_database_url(database_url, project_ref=project_ref)
        try:
            psycopg = importlib.import_module("psycopg")
            connection = psycopg.connect(database_url, connect_timeout=15)
        except Exception as exc:
            raise InspectionError("database_connection_failed") from exc
        try:
            observed = inspect_supabase_connection(
                connection,
                expected_tables=sorted(tables),
                expected_functions=expected_functions,
                expected_migration_id=migration_id,
            )
            observed["project_ref_sha256"] = _sha256(project_ref)
            return observed
        finally:
            with suppress(Exception):
                connection.rollback()
            with suppress(Exception):
                connection.close()

    def _flowaccount(self, environment: Mapping[str, str]) -> dict[str, object]:
        base = _https_base(environment["FLOWACCOUNT_SANDBOX_BASE_URL"])
        if base != "https://openapi.flowaccount.com/test":
            raise InspectionError("flowaccount_sandbox_binding_invalid")
        body = urllib.parse.urlencode(
            {
                "client_id": environment["FLOWACCOUNT_SANDBOX_CLIENT_ID"],
                "client_secret": environment["FLOWACCOUNT_SANDBOX_CLIENT_SECRET"],
                "grant_type": "client_credentials",
                "scope": "flowaccount-api",
            }
        ).encode()
        token = _json_request(
            f"{base}/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        access_token = token.get("access_token") if isinstance(token, dict) else None
        if not isinstance(access_token, str) or not access_token or len(access_token) > 4096:
            raise InspectionError("flowaccount_token_invalid")
        company = _request(
            f"{base}/company/info",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        payload = _parse_json(company.body)
        if not isinstance(payload, dict) or payload.get("error"):
            raise InspectionError("flowaccount_sandbox_read_failed")
        return {"environment": "sandbox", "read_only": True, "status": company.status}


def _render_log_url(
    render_base: str,
    *,
    service_id: str,
    owner_id: str,
    log_type: str,
) -> str:
    if (
        _RENDER_SERVICE_ID_RE.fullmatch(service_id) is None
        or _RENDER_OWNER_ID_RE.fullmatch(owner_id) is None
        or log_type not in {"build", "runtime"}
    ):
        raise InspectionError("render_log_query_invalid")
    query = urllib.parse.urlencode(
        {"resource": service_id, "ownerId": owner_id, "type": log_type}
    )
    return f"{render_base.rstrip('/')}/logs?{query}"


class _McpProbe:
    def __init__(self, *, endpoint: str, token: str) -> None:
        self._endpoint = endpoint
        self._headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._session: str | None = None
        self._request_id = 0

    def initialize(self) -> dict[str, object]:
        result, response = self._call(
            "initialize",
            {
                "capabilities": {},
                "clientInfo": {"name": "mercury-release-control-v2", "version": "0.3.0"},
                "protocolVersion": "2025-03-26",
            },
        )
        session = response.headers.get("mcp-session-id")
        if not session or len(session) > 1024:
            raise InspectionError("public_mcp_session_invalid")
        self._session = session
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> list[dict[str, object]]:
        result, _response = self._call("tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list) or result.get("nextCursor") is not None:
            raise InspectionError("public_mcp_tool_inventory_invalid")
        return tools

    def citation_count(self, connector: str) -> int:
        count = 0
        for name, field in (
            ("search_knowledge", "results"),
            ("retrieve_context_pack", "context"),
        ):
            arguments: dict[str, object] = {
                "filters": {
                    "connector": connector,
                    "doc_type": "endpoint_validation",
                    "review_status": "reviewed",
                },
                "query": f"{connector} invoice accounting validation",
            }
            arguments["top_k" if name == "search_knowledge" else "max_chunks"] = 2
            result, _response = self._call("tools/call", {"arguments": arguments, "name": name})
            payload = _tool_payload(result)
            rows = payload.get(field)
            if not isinstance(rows, list) or not rows:
                raise InspectionError(f"public_mcp_{connector}_rag_invalid")
            for row in rows:
                metadata = row.get("metadata") if isinstance(row, dict) else None
                citation = row.get("citation") if isinstance(row, dict) else None
                if (
                    not isinstance(metadata, dict)
                    or metadata.get("connector") != connector
                    or metadata.get("doc_type") != "endpoint_validation"
                    or metadata.get("review_status") != "reviewed"
                    or not isinstance(citation, dict)
                    or not citation
                ):
                    raise InspectionError(f"public_mcp_{connector}_rag_invalid")
                count += 1
        return count

    def _call(
        self, method: str, params: Mapping[str, object]
    ) -> tuple[dict[str, object], _Response]:
        self._request_id += 1
        payload = {
            "id": self._request_id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        response = _request(
            self._endpoint,
            method="POST",
            headers=self._session_headers(),
            body=json.dumps(payload, separators=(",", ":")).encode(),
        )
        envelope = _mcp_envelope(response)
        result = envelope.get("result")
        if envelope.get("id") != self._request_id or not isinstance(result, dict):
            raise InspectionError("public_mcp_response_invalid")
        return result, response

    def _notify(self, method: str) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": {}}
        _request(
            self._endpoint,
            method="POST",
            headers=self._session_headers(),
            body=json.dumps(payload, separators=(",", ":")).encode(),
        )

    def _session_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        if self._session is not None:
            headers["Mcp-Session-Id"] = self._session
        return headers


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    body: bytes | None = None,
) -> _Response:
    _https_url(url)
    request = urllib.request.Request(url, method=method, headers=dict(headers or {}), data=body)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read(_MAX_RESPONSE + 1)
            response_headers = {key.casefold(): value for key, value in response.headers.items()}
            status = response.status
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as exc:
        raise InspectionError("provider_http_failed") from exc
    if len(content) > _MAX_RESPONSE or status < 200 or status >= 300:
        raise InspectionError("provider_http_failed")
    return _Response(body=content, headers=response_headers, status=status)


def _json_request(url: str, **kwargs):
    return _parse_json(_request(url, **kwargs).body)


def _parse_json(body: bytes):
    try:
        return json.loads(body, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise InspectionError("provider_json_invalid") from exc


def _mcp_envelope(response: _Response) -> dict[str, object]:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    if content_type == "application/json":
        payload = _parse_json(response.body)
    elif content_type == "text/event-stream":
        rows = [
            line[5:].strip() for line in response.body.splitlines() if line.startswith(b"data:")
        ]
        if len(rows) != 1:
            raise InspectionError("public_mcp_response_invalid")
        payload = _parse_json(rows[0])
    else:
        raise InspectionError("public_mcp_response_invalid")
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or payload.get("error"):
        raise InspectionError("public_mcp_response_invalid")
    return payload


def _tool_payload(result: Mapping[str, object]) -> dict[str, object]:
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    content = result.get("content")
    if not isinstance(content, list) or not content:
        raise InspectionError("public_mcp_response_invalid")
    first = content[0]
    if not isinstance(first, dict) or first.get("type") != "text":
        raise InspectionError("public_mcp_response_invalid")
    text = first.get("text")
    if not isinstance(text, str):
        raise InspectionError("public_mcp_response_invalid")
    payload = _parse_json(text.encode())
    if not isinstance(payload, dict):
        raise InspectionError("public_mcp_response_invalid")
    return payload


def _live_deploy(row: object, reviewed_sha: str) -> bool:
    if not isinstance(row, dict) or row.get("status") != "live":
        return False
    commit = row.get("commit")
    observed = commit.get("id") if isinstance(commit, dict) else row.get("commitId")
    return observed == reviewed_sha


def _contains_credential_key(value: object) -> bool:
    pending = [value]
    for _ in range(100_000):
        if not pending:
            return False
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if _CREDENTIAL_KEY.search(str(key)):
                    return True
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
    return True


def _assert_no_secret(payload: bytes, values) -> None:
    if _SECRET_VALUE.search(payload):
        raise InspectionError("render_log_secret_found")
    for value in values:
        if isinstance(value, str) and len(value) >= 12 and value.encode() in payload:
            raise InspectionError("render_log_secret_found")


def _https_base(value: str) -> str:
    _https_url(value)
    return value.rstrip("/")


def _https_url(value: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise InspectionError("provider_url_invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or len(value) > 4096
    ):
        raise InspectionError("provider_url_invalid")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
