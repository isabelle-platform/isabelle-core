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
- Self-describing HTTP API: an OpenAPI 3.1 document generated from the running
  deployment, plugin routes included.

## API description

The full HTTP surface of a *running* deployment is described by an OpenAPI
3.1 document the server generates on request:

- `GET /openapi.json` — the document itself.
- `GET /docs` — the same thing rendered as a static page (no scripts, no
  external assets, works offline).

Both require an administrator session, because the document names every
collection in the store and every plugin route the deployment registered.

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
