# isabelle-core

[![Build Status](https://jenkins.interpretica.io/buildStatus/icon?job=isabelle-core%2Fmain)](https://jenkins.interpretica.io/job/isabelle-core/job/main/)

Isabelle is a Rust-based framework for building safe and performant servers for the variety of use cases.

## Features

+ Unified item storage with addition, editing and deletion support.
+ Collection hooks allowing plugins to do additional checks or synchronization.
+ Security checks.
+ E-Mail sending support.
+ Google Calendar integration.
+ Login/logout functionality.
+ One-time password support.

## Endpoints

### 1. `GET /is_logged_in`

> [!NOTE]
> check the login status.

**Result:**

```json
{
	"username": "<username>",
	"id": <user id>,
	"role": [ "role_is_admin" ],
	"site_name": "Test",
	"site_logo": "Test Logo",
	"licensed_to": "Test Company",
}
```

### 2. `POST /login`

> [!IMPORTANT]
> Params: `(username, password inside the post request)`

> [!NOTE]
> Username/password Login

**Result:**

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

### 3. `POST /logout`

> [!NOTE]
> Terminating current session.

<!--
**Result:**

```json
{
	"": "",
}
```
-->

### 4. `GET /itm/list`

> [!NOTE]
> read the item from the collection

> [!IMPORTANT]
> Params: `(collection, [id], [id_min], [id_max], [skip], [limit], [sort_key], [filter])`

**Result:**

```json
{
	"map": [ <id>: {} ],
	"total_count": <value>,
}
```

### 5. `POST /itm/edit`

> [!NOTE]
> edit the item in collection.

> [!IMPORTANT]
> Params: `("item" inside the post request and inside the query string, "collection" and "merge" = false/true in query)`

**Result:**

```json
{
	"succeeded": true/false,
	"error": "detailed error",
}
```

### 6. `POST /itm/del`

> [!NOTE]
> delete the item from the collection

> [!IMPORTANT]
> Params: `(collection, id)`

**Result:**

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
