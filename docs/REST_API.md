# REST API

A small REST alternative to the GraphQL endpoint, for quickly scripting the
common case: **creating CTFs and tasks (with tags/categories)**. It is not a
full mirror of the GraphQL API — it covers listing/creating CTFs and
listing/creating tasks, and nothing more.

Internally every call is forwarded to the GraphQL endpoint with your API key,
so permissions, HedgeDoc pad creation and live UI updates all behave identically
to a GraphQL client.

## Authentication

Every request needs an API key in the `X-API-Key` header (see
[API_KEYS.md](API_KEYS.md) for how to create one). The key's owner and role
determine what you may do — use a `user_manager` or `user_admin` key to create
CTFs and tasks.

```
X-API-Key: ctfnote_1a2b3c...
```

Base URL: `https://ctfnote.ireland.re/api`

## Endpoints

### `GET /api/ctfs`
List CTFs.
```bash
curl -s https://ctfnote.ireland.re/api/ctfs -H "X-API-Key: $KEY"
# [ { "id": 42, "title": "MyCTF 2026", "startTime": "...", "endTime": "..." }, ... ]
```

### `POST /api/ctfs`
Create a CTF. `title`, `startTime`, `endTime` are required (times are ISO 8601);
`weight`, `description`, `ctfUrl`, `ctftimeUrl`, `logoUrl` are optional.
```bash
curl -s https://ctfnote.ireland.re/api/ctfs -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"title":"MyCTF 2026","startTime":"2026-10-01T18:00:00Z","endTime":"2026-10-03T18:00:00Z"}'
# 201 -> { "id": 43, "title": "MyCTF 2026", ... }
```

### `GET /api/ctfs/:ctfId/tasks`
List the tasks in a CTF, including their tags.
```bash
curl -s https://ctfnote.ireland.re/api/ctfs/42/tasks -H "X-API-Key: $KEY"
# [ { "id": 7, "title": "web/babycsp", "flag": "", "description": "...", "tags": ["web"] }, ... ]
```

### `POST /api/ctfs/:ctfId/tasks`
Create a task. `title` is required. Tags (a.k.a. categories) may be given as
`tags` / `categories` (arrays) or `tag` / `category` (single string) — all are
merged. `description` and `flag` are optional.
```bash
curl -s https://ctfnote.ireland.re/api/ctfs/42/tasks -H "X-API-Key: $KEY" \
  -H 'Content-Type: application/json' \
  -d '{"title":"pwn/ret2win","category":"pwn","description":"nc host 1337"}'
# 201 -> { "id": 8, "title": "pwn/ret2win", "tags": ["pwn"] }
```

Bulk-add example (Python):
```python
import requests
BASE, KEY = "https://ctfnote.ireland.re/api", "ctfnote_..."
H = {"X-API-Key": KEY}
ctf_id = 42
tasks = [
    {"title": "web/login", "category": "web"},
    {"title": "rev/crackme", "categories": ["rev", "easy"], "flag": ""},
]
for t in tasks:
    r = requests.post(f"{BASE}/ctfs/{ctf_id}/tasks", json=t, headers=H)
    print(r.status_code, r.json())
```

## Status codes

| Code | Meaning |
|------|---------|
| 201  | Created |
| 200  | OK (GET) |
| 207  | Task created, but tag assignment failed (see `warning`) |
| 400  | Missing/invalid body (e.g. no `title`) |
| 401  | Missing `X-API-Key` header |
| 403  | Key valid but not permitted (role / CTF access) |
| 404  | CTF not found |

Errors are JSON: `{ "error": "..." }`.
