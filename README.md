# isabelle-core

[![Build Status](https://jenkins.interpretica.io/buildStatus/icon?job=isabelle-core%2Fmain)](https://jenkins.interpretica.io/job/isabelle-core/job/main/)

Isabelle is a Rust-based framework for building safe and performant servers for the variety of use cases.

## Features

- Unified item storage with addition, editing and deletion support.
- Collection hooks allowing plugins to do additional checks or synchronization.
- Security checks.
- E-Mail sending support.
- Google Calendar integration.
- Login/logout functionality.
- One-time password support.
- Signing in with Google and Apple.
- Self-describing HTTP API: an OpenAPI 3.1 document generated from the running
  deployment, plugin routes included.

## API description

The full HTTP surface of a *running* deployment is described by an OpenAPI
3.1 document the server generates on request:

- `GET /openapi.json` — the document itself.
- `GET /docs` — the same thing rendered as a static page (no scripts, no
  external assets, works offline).

Both are public. A description is not a credential: every endpoint it names
still authenticates its own callers, so publishing it opens nothing. It does
say which plugin routes exist and which collections the store holds — a
deployment that would rather not publish that starts core with
`--openapi-private`, which serves both to administrators only.

It is generated rather than committed because half of the surface only exists
at runtime: each `extra_route` / `extra_unprotected_route` /
`extra_rest_route` in `internals.js` becomes a real path at startup, and the
`collection` parameter is constrained to the collections the store actually
holds. The short list below covers the endpoints core itself always has.

## Endpoints

1. GET /is_logged_in: check the login status.

Result:

```json
{
	"username": "<username>",
	"id": <user id>,
	"role": [ "role_is_admin" ],
	"site_name": "Test",
	"site_logo": "Test Logo"
	"licensed_to": "Test Company"
}
```

2. POST /login (username, password inside the post request):

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

3. POST /logout:

4. GET /itm/list (collection, [id], [id_min], [id_max], [skip], [limit], [sort_key], [filter]): read the item from the collection

```json
{
	"map": [ <id>: {} ],
	"total_count": <value>
}
```

5. POST /itm/edit ("item" inside the post request and inside the query string, "collection" and "merge" = false/true in query): edit the item in collection.

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

6. POST /itm/del (collection, id): delete the item from the collection

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

## Signing in with Google or Apple

Core speaks the OpenID Connect authorization-code flow, so an account can be
signed into with a Google or Apple identity instead of a password. Nothing is
enabled by default: a provider exists for a deployment exactly when its entry
exists in the encrypted secret store, and there is no second switch to leave
in the wrong position.

### Configuring a provider

`GET /auth/config` and `POST /auth/config` are the administrator-only pair for
this (proteos puts a form on them under Settings → Sign-in). The read returns
each provider's public settings and whether a secret is stored — never the
secret itself. The write takes only the fields being changed, and checks the
result before storing it, so an unreadable Apple key is refused at the moment
someone saves it rather than weeks later at a token endpoint. `POST
/auth/config/forget` removes a provider, which is also how it is switched off.

Because a client secret can never be read back, an empty one in a write means
"leave what is stored alone" — an empty box on a screen that was never allowed
to show the value is not a decision to delete it.

Underneath, each provider is one entry in the encrypted secret store, so
`POST /secret/edit` works too and is what a script would use.

**Google** — the entry is named `oauth_google`:

| key | what it is |
| --- | --- |
| `client_id` | the OAuth client ID from the Google Cloud console |
| `client_secret` | its secret |
| `redirect_uri` | optional; see below |

**Apple** — the entry is named `oauth_apple`. Apple issues no client secret;
it wants a short-lived JWT signed with a key you register, so what is stored
is the key itself:

| key | what it is |
| --- | --- |
| `client_id` | the Services ID, e.g. `io.example.web` |
| `team_id` | the Apple developer team |
| `key_id` | the identifier of the Sign in with Apple key |
| `private_key` | the contents of its `.p8` file, PEM and all |
| `redirect_uri` | optional; see below |

### The redirect URI

This is the address the *browser* comes back to, and it has to be registered
with the provider character for character. Left unset, core uses
`<--pub-url>/api/auth/<provider>/callback` — where the shipped nginx
configuration puts it. A deployment that serves core somewhere else sets
`redirect_uri` explicitly. Apple will not register an `http://` address at
all, so Apple sign-in needs TLS even in development.

### What it does

- `GET /auth/providers` — what a login screen should offer. No session
  needed, and it says only that a provider is configured, never with what.
- `GET /auth/config`, `POST /auth/config`, `POST /auth/config/forget` —
  reading and writing the above. Administrators only.
- `GET /auth/{provider}/start?next=/where` — a redirect to the provider.
- `GET|POST /auth/{provider}/callback` — where the provider returns the
  browser. On success a session cookie is issued and the browser goes to
  `next`; otherwise to the same place with `auth_error` set to one of
  `denied`, `unverified`, `registration_closed`, `inactive`, `mismatched` or
  `failed`. The detail behind a refusal is logged rather than put in a URL.

### What a provider is trusted for

The identity, and nothing else — who the account is and what address it has.
Roles and activity belong to the record here, so no provider can make anyone
an administrator or revive a disabled account.

An address the provider will not vouch for is not an identity, and is
refused. A verified one signs into the account that already holds it; if
there is none, one is created when `allow_self_registration` permits it. The
provider's own identifier for the account is remembered on first sign-in, and
a later sign-in presenting a different one for the same address is refused —
so an address that changes hands at the provider cannot pick up the record
left behind.

## Dependencies

- Python 3 is needed for Google Calendar integration

## Building

Building Isabelle is as easy as Cargo invocation:

```sh
cargo build
```

## Running

Use `run.sh` script:

```sh
./run.sh
```

## License

MIT
