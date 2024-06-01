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
use std::cell::RefCell;
use std::sync::Arc;
use crate::state::data::*;

use parking_lot::ReentrantMutex;

pub struct State {
    pub server: Arc<ReentrantMutex<RefCell<Data>>>,
}

impl Clone for State {
    // Define the clone method
    fn clone(&self) -> Self {
        // Create a new instance with the same value
        State {
            server: self.server.clone(),
        }
    }
}

impl State {
    pub fn new() -> Self {
        let srv = Data::new();
        Self {
            server: Arc::new(ReentrantMutex::new(RefCell::new(srv))),
        }
    }
}

unsafe impl Send for State {}
