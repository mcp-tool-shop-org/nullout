"""NullOut MCP server — stdio JSON-RPC 2.0 loop."""

from __future__ import annotations

import json
import sys
from typing import Any

from nullout.config import Root, load_roots, get_token_secret
from nullout.errors import err
from nullout.store import Store
from nullout.tools import (
    handle_list_allowed_roots,
    handle_scan_reserved_names,
    handle_get_finding,
    handle_plan_cleanup,
    handle_delete_entry,
    handle_who_is_using,
    handle_get_server_info,
    set_store,
)

# --- MCP tools/list schema (paste-ready from spec) ---

TOOLS_LIST: list[dict[str, Any]] = [
    {
        "name": "list_allowed_roots",
        "description": "List allowlisted roots. Windows-only. Reparse policy: deny_all.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "scan_reserved_names",
        "description": (
            "Scan an allowlisted root for reserved-device / Win32-hostile entries. "
            "Does not traverse reparse points (deny_all)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "rootId": {"type": "string"},
                "recursive": {"type": "boolean"},
                "maxDepth": {"type": "integer", "minimum": 0},
                "includeDirs": {"type": "boolean"},
            },
            "required": ["rootId", "recursive", "includeDirs"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_finding",
        "description": "Return full details for a findingId returned by scan.",
        "inputSchema": {
            "type": "object",
            "properties": {"findingId": {"type": "string"}},
            "required": ["findingId"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "plan_cleanup",
        "description": (
            "Create an explicit plan and per-entry confirmToken (TTL) bound to "
            "finding identity (volumeSerial+fileId) and strategy."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "findingIds": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "requestedActions": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["DELETE"]},
                    "minItems": 1,
                },
            },
            "required": ["findingIds", "requestedActions"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "delete_entry",
        "description": (
            "Delete a file or an EMPTY directory only. "
            "Requires confirmToken. No raw paths accepted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "findingId": {"type": "string"},
                "confirmToken": {"type": "string"},
            },
            "required": ["findingId", "confirmToken"],
            "additionalProperties": False,
        },
        "annotations": {"destructiveHint": True},
    },
    {
        "name": "who_is_using",
        "description": (
            "Tier A attribution: list processes currently using the target "
            "via Windows Restart Manager. Read-only — never kills processes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"findingId": {"type": "string"}},
            "required": ["findingId"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "get_server_info",
        "description": (
            "Server metadata: name, version, platform, policies, and capabilities. "
            "Useful for debugging version mismatches and understanding server config."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
]


class NullOutServer:
    """MCP server with tool routing over stdio JSON-RPC."""

    def __init__(self, roots: dict[str, Root], store: Store, token_secret: bytes) -> None:
        self.roots = roots
        self.store = store
        self.token_secret = token_secret

    def handle_rpc(self, req: dict[str, Any]) -> dict[str, Any]:
        """Route a single JSON-RPC request to the appropriate handler."""
        rpc_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        if method == "tools/list":
            return self._rpc_ok(rpc_id, {"tools": TOOLS_LIST})

        handlers = {
            "list_allowed_roots": lambda p: handle_list_allowed_roots(p, self.roots),
            "scan_reserved_names": lambda p: handle_scan_reserved_names(p, self.roots, self.store),
            "get_finding": lambda p: handle_get_finding(p, self.store),
            "plan_cleanup": lambda p: handle_plan_cleanup(p, self.store, self.token_secret),
            "delete_entry": lambda p: handle_delete_entry(p, self.roots, self.store, self.token_secret),
            "who_is_using": lambda p: handle_who_is_using(p, self.roots, self.store),
            "get_server_info": lambda p: handle_get_server_info(p),
        }

        handler = handlers.get(method)
        if not handler:
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

        try:
            result = handler(params)
            return self._rpc_ok(rpc_id, result)
        except Exception as e:
            return self._rpc_ok(
                rpc_id,
                err("E_INTERNAL", "Unhandled server error.", {"exception": str(e)}),
            )

    def _rpc_ok(self, rpc_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def main() -> None:
    """Entry point: load config, run stdio JSON-RPC loop."""
    roots = load_roots()
    token_secret = get_token_secret()
    store = Store()
    set_store(store)

    server = NullOutServer(roots, store, token_secret)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue

        resp = server.handle_rpc(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
