# API keys (programmatic access)

CTFNote's GraphQL API normally authenticates with a JWT from the `login`
mutation, which expires after 30 days. This fork adds **API keys**: long-lived
credentials that do not expire until you revoke them — ideal for scripts, bots,
and automation (e.g. bulk-adding tasks).

An API key authenticates as the user that created it and carries that user's
role. Create a key from an account with enough privileges for what your script
needs (a `user_manager` or `user_admin` account to create CTFs and tasks).

## How it works

- Keys live in the `ctfnote_private.api_key` table (migration `57-api-keys.sql`).
- A request presents its key in the **`X-API-Key`** header (not `Authorization`,
  which is reserved for JWTs).
- On each request the API resolves the key to `(user_id, role)` and applies the
  same `jwt.claims.*` PostgreSQL settings a JWT would, so all existing
  permission checks apply unchanged (`api/src/index.ts` → `makeApiKeyPgSettings`).

## Creating a key

Key management is exposed over GraphQL and requires a normal (JWT) login first —
you bootstrap one key interactively, then use it forever.

```bash
CTFNOTE=https://ctfnote.ireland.re

# 1. Log in to get a short-lived JWT
JWT=$(curl -s "$CTFNOTE/graphql" -H 'Content-Type: application/json' \
  --data '{"query":"mutation($l:String!,$p:String!){login(input:{login:$l,password:$p}){jwt}}",
           "variables":{"l":"USERNAME","p":"PASSWORD"}}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["login"]["jwt"])')

# 2. Mint a non-expiring API key (the token is shown ONLY once)
curl -s "$CTFNOTE/graphql" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT" \
  --data '{"query":"mutation($d:String!){createApiKey(input:{description:$d}){string}}",
           "variables":{"d":"automation bot"}}'
# => {"data":{"createApiKey":{"string":"ctfnote_1a2b3c..."}}}
```

> PostGraphile wraps a scalar-returning function in a payload; the token comes
> back on the `string` field of `createApiKey`.

## Using a key

Send it in `X-API-Key` — no login, no expiry:

```bash
API_KEY=ctfnote_1a2b3c...

# find a CTF id
curl -s "$CTFNOTE/graphql" -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data '{"query":"{ ctfs { nodes { id title } } }"}'

# add a task
curl -s "$CTFNOTE/graphql" -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data '{"query":"mutation{createTask(input:{ctfId:42,title:\"web/x\",tags:[\"web\"]}){task{id title}}}"}'
```

Python:

```python
import requests
API, KEY = "https://ctfnote.ireland.re/graphql", "ctfnote_1a2b3c..."

def gql(query, variables=None):
    r = requests.post(API, json={"query": query, "variables": variables or {}},
                      headers={"X-API-Key": KEY})
    r.raise_for_status()
    d = r.json()
    if d.get("errors"):
        raise RuntimeError(d["errors"])
    return d["data"]

ctf_id = gql("{ ctfs { nodes { id title } } }")["ctfs"]["nodes"][0]["id"]
gql("""mutation($c:Int!,$t:String!,$tags:[String],$d:String){
         createTask(input:{ctfId:$c,title:$t,tags:$tags,description:$d}){task{id}}}""",
    {"c": ctf_id, "t": "pwn/ret2win", "tags": ["pwn"], "description": "nc host 1337"})
```

## Listing and revoking keys

Tokens are never retrievable after creation; you can only list metadata and revoke.

```graphql
# List your keys (requires a JWT or one of your API keys)
query { myApiKeys { nodes { id description created lastUsed } } }

# Revoke by id (admins may revoke any key)
mutation { revokeApiKey(input: {id: 3}) { integer } }
```

## Security notes

- A key is a bearer credential equivalent to its owner's account. Store it like
  a password; anyone with it has that user's access.
- Revoke immediately if leaked — `revokeApiKey` (or delete the row) takes effect
  on the next request, with no secret-rotation needed.
- Keys are stored in plaintext in `ctfnote_private.api_key` (that schema is not
  exposed via the API). Restrict database access accordingly.
