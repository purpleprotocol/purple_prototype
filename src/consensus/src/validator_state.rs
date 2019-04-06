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

use causality::Stamp;

#[derive(Clone, Debug)]
pub struct ValidatorState {
    /// Whether or not the validator is allowed
    /// to send an event.
    pub(crate) allowed_to_send: bool,

    /// The stamp of the latest event that
    /// has been send by the validator.
    pub(crate) latest_stamp: Stamp,
}

impl ValidatorState {
    pub fn new(allowed_to_send: bool, init_stamp: Stamp) -> ValidatorState {
        ValidatorState {
            allowed_to_send,
            latest_stamp: init_stamp,
        }
    }
}
