# Changelog

All notable changes to MCP Keyholder are listed here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-30

First public version.

- Encrypted local vault: Argon2id master password, XChaCha20-Poly1305 values, signed key policies.
- MCP server for agents (`kh mcp`): `list_secrets`, `request_grant`, `my_grants`, `get_secret`, `prepare_run`, `report_leak`, `check_leak`.
- Per-session grants approved by a human; approval levels: no window, soft, PIN, OTP (one code — one approval), sealed (never given to agents).
- Codes and the master password are typed on a separate Windows desktop, never in a webview or a chat.
- `env` mode: `kh run` puts a key into a process environment; the agent never sees the value.
- Leak reports from agents and leak search in text (`check_leak`, `kh scan`).
- Audit log with an HMAC chain, integrity check and an external anchor file.
- Service mode: the core runs as a Windows service under its own account.
- Moving a vault between computers with an encrypted `.mcpkey` file.
- Sealed keys for your own records: any text, multi-line, names in any language.
- Signed automatic updates.
- Light and dark themes, tray, bulk editing, import from `.txt`.
