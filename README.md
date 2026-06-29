# chromium_parser

## Features
- Identity & account — profile key/name, signed-in Google account, gaia id, hosted
- (Workspace) domain, supervised/managed flags, ephemeral status.
- History — URLs, titles, visit and typed counts, last-visit times.
- Bookmarks — the full bookmark tree.
- Downloads — target path, source/tab URL, MIME type, byte counts, danger type, the extension that initiated it, and open state.
- Logins — site, username, signon realm, usage counts and dates (no passwords).
- Cookies — per-domain counts (total / secure / httpOnly / session), no values.
- Extensions — id, name, version, state, install location, permissions, update URL, plus a heuristic "risky extensions" view (broad host access / sensitive permissions).
- Synced devices — other machines signed into the account (name, model, OS, form factor, Chrome version).
- Security posture — Safe Browsing (standard/enhanced), password saving, leak detection — each reported only when the profile explicitly set it.
- Autofill — saved addresses and saved-card metadata (no full numbers).
- Search engines and top sites.
- HTTP cache — the disk (blockfile) cache: cached URLs, status codes, headers, and
- decompressed response bodies, with a filterable search.
