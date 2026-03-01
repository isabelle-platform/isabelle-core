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

## Endpoints

These are available in all services based on Isabelle.

More at [OpenAPI Spec](./specs/openapi/openapi.yaml)

### `GET /is_logged_in`

> [!NOTE]
> check the login status.

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

### `POST /login`

Params: `(username, password inside the post request)`

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

### `POST /logout`

### `GET /itm/list`

Params: `(collection, [id], [id_min], [id_max], [skip], [limit], [sort_key], [filter])`

> [!NOTE]
> read the item from the collection

```json
{
	"map": [ <id>: {} ],
	"total_count": <value>
}
```

### `POST /itm/edit`

Params: `("item" inside the post request and inside the query string, "collection" and "merge" = false/true in query)`

> [!NOTE]
> edit the item in collection

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

### `POST /itm/del`

Params: `(collection, id)`

> [!NOTE]
> delete the item from the collection

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

[MIT](./LICENSE)
