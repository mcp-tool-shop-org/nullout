# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.2] - 2026-02-28

### Fixed

- Exclude ci-root/ from sdist to prevent hatchling crash on trailing-space test fixtures

## [1.1.1] - 2026-02-28

### Added

- Shipcheck audit (all hard gates pass)
- Landing page via @mcptoolshop/site-theme
- README translations (8 languages)
- SECURITY.md with full threat model
- Codecov coverage reporting

## [1.1.0] - 2026-02-28

### Added

- `who_is_using` tool — real process attribution via Windows Restart Manager (ctypes bindings to rstrtmgr.dll)
- `get_server_info` tool — server metadata (name, version, platform, policies, capabilities)
- Normalized-path fallback hint for trailing dot/space entries in RM queries
- PyPI packaging (`nullout-mcp`) with trusted publishing workflow
- Regression test for undocumented RM ApplicationType values (e.g. 1000 on Windows 11)

### Changed

- `who_is_using` upgraded from stub to full Restart Manager implementation
- Updated tool description for `who_is_using` to reflect live RM integration
- Package name set to `nullout-mcp` for PyPI registry

### Fixed

- `os.scandir()` on trailing-dot directories now uses extended path prefix (WinError 3 fix)
- SyntaxWarning in `create_fixtures.py` docstring escape sequence

## [1.0.0] - 2026-02-27

### Added

- Initial release
- 6 MCP tools: `list_allowed_roots`, `scan_reserved_names`, `get_finding`, `plan_cleanup`, `delete_entry`, `who_is_using` (stub)
- Allowlisted root confinement with `NULLOUT_ROOTS` env var
- HMAC-SHA256 confirmation tokens bound to file identity (volume serial + file ID)
- Reparse point detection and `deny_all` traversal policy
- Extended path namespace (`\\?\`) for all destructive operations
- Hazard detection: reserved device names, trailing dots/spaces, overlong paths
- Empty-only directory deletion policy
- Structured error envelopes with error codes and next-step suggestions
- 17 deterministic tests with 3x CI runs
- End-to-end shipcheck (stdio JSON-RPC smoke test)
