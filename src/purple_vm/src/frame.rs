/*
  Copyright 2018 The Purple Library Authors
  This file is part of the Purple Library.

  The Purple Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Library. If not, see <http://www.gnu.org/licenses/>.
*/

use address::Address;
use primitives::control_flow::CfOperator;
use stack::Stack;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Frame<T: Clone> {
    pub locals: Stack<T>,
    pub scope_type: Option<CfOperator>,
    pub return_address: Option<Address>,
}

impl<T: fmt::Debug + Clone> Frame<T> {
    pub fn new(
        scope_type: Option<CfOperator>,
        return_address: Option<Address>,
        argv: Option<Vec<T>>,
    ) -> Frame<T> {
        let mut locals = Stack::new();

        if let Some(argv) = argv {
            // Push args to locals stack
            for arg in argv {
                locals.push(arg);
            }
        }

        Frame {
            locals: locals,
            scope_type: scope_type,
            return_address: return_address,
        }
    }
}
