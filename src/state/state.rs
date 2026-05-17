/*
 * Isabelle project
 *
 * Copyright 2023-2024 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
use crate::state::data::*;
use std::sync::Arc;

/// Server-wide state shared across actix worker arbiters.
///
/// Phase-4 lock decomposition: `Data` is wrapped in plain `Arc` — no outer
/// `parking_lot::ReentrantMutex` anymore. All runtime-mutable fields inside
/// `Data` use interior mutability (`parking_lot::Mutex` on caches, secrets,
/// plugin pool, route cache). HTTP handlers get a `&Data` directly via
/// `&data.server` and never serialise on a single global lock — only on
/// the specific subsystem they touch.
pub struct State {
    pub server: Arc<Data>,
}

impl Clone for State {
    fn clone(&self) -> Self {
        State {
            server: self.server.clone(),
        }
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            server: Arc::new(Data::new()),
        }
    }
}

unsafe impl Send for State {}
