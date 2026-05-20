/*
 * Isabelle project
 *
 * Copyright 2023-2026 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 */

//! Plugin-free isabelle-core binary. Useful for development and smoke
//! tests — the resulting `isabelle-core` runs the full HTTP server but
//! with an empty plugin registry, so most business-logic-bearing
//! endpoints will respond with `NotImplemented`.
//!
//! Production deployments use a per-flavour shell crate that pulls the
//! plugins it needs and calls [`isabelle_core::run`] with the appropriate
//! `register_actor` chain.

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    isabelle_core::run(|_reg, _core| {
        // No plugins in the standalone dev binary.
    })
    .await
}
