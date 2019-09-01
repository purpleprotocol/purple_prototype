/*
  Copyright (C) 2018-2019 The Purple Core Developers.
  This file is part of the Purple Core Library.

  The Purple Core Library is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  The Purple Core Library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with the Purple Core Library. If not, see <http://www.gnu.org/licenses/>.
*/

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum ConsensusErr {
    /// Could not find a validator with the given id.
    NoValidatorWithId,

    /// The validator is not allowed to send an event.
    NotAllowedToSend,

    /// The validator doesn't have any more events that it can send.
    NoMoreEvents,

    /// The pool does not have remaining events that it can produce.
    NoMoreEventsPool,
}
