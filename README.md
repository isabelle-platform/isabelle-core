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
