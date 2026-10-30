# Contributing

Thanks for helping with MCP Keyholder!

## Before you start

- Security issues go through [SECURITY.md](SECURITY.md), not public issues.
- For anything bigger than a small fix, open an issue first so we can agree on the approach.

## Development

You need Rust (stable), Node.js 20+ and, on Windows, Visual Studio Build Tools.

```bash
cargo test -p kh-core -p kh-daemon     # core tests
cd app && npm install && npx tsc --noEmit -p .
npx tauri dev                          # run the app
```

Useful switches for debug builds are listed in [README.ru.md](README.ru.md#разработка):

- `KH_DATA_DIR=<folder>` gives a separate test vault, and the debug app can then run next to an installed one;
- `KH_NO_SECURE_DESKTOP=1` lets you type codes in the app window instead of on a separate desktop.

## Pull requests

- Keep changes focused; one topic per pull request.
- Add or update tests for core changes (`crates/kh-core`, `crates/kh-daemon`).
- Match the surrounding code: naming, comment density, error messages in the language of the UI.
- Anything that weakens protection (approval levels, step-up, the separate desktop, the audit log) needs a clear reason in the description.

By contributing you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
