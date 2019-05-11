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

#[derive(Clone, Debug, PartialEq)]
pub enum ValidationResp {
    /// The event is valid.
    Valid,

    /// The node id of the pushed event does not
    /// belong to an active validator.
    NotValidator,

    /// The validator is not allowed to send an event.
    NotAllowedToSend,

    /// The stamp of the event is not valid.
    InvalidStamp,

    /// The validity of the event cannot be determined.
    CannotDetermineValidity,
}
