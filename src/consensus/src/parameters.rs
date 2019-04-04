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

/// The number of other events from distinct nodes
/// that an event must be followed by in order to
/// be eligible to vote on a `CandidateSet`.
pub fn eligibility_requirement(node_count: u16) -> u16 {
    ((node_count as f32 + 1.0) / 2.0).trunc() as u16
}

/// The number of other events from distinct nodes
/// that a node's last event must be followed by in
/// order to be eligible to send a `Heartbeat` event.
pub fn heartbeat_requirement(node_count: u16) -> u16 {
    ((node_count as f32 + 1.0) / 3.0).trunc() as u16
}

/// The number of other events from distinct nodes
/// that a voting event must be followed by in order
/// to propose for a `CandidateSet`.
pub fn proposal_requirement(node_count: u16) -> u16 {
    ((node_count as f32 + 1.0) / 2.0).trunc() as u16
}

/// The number of required proposals for a `CandidateSet`
/// in order to be considered valid for inclusion into
/// the total order.
pub fn required_proposal(node_count: u16) -> u16 {
    node_count + 1
}

/// The number if `Heartbeat` events that a node is required
/// to issue before it is eligible to send a `Leave` event.
///
/// This is `trunc(2^8 * log_n(node_count))`.
pub fn leave_requirement(node_count: u16) -> u16 {
    (2.0f32.powf(8.0f32) * (node_count as f32).ln()).trunc() as u16
}

/// The maximum number of `Heartbeat` that a node is allowed
/// to issue before it **must** send a `Leave` event.
///
/// This is `trunc(2^10 * log_n(node_count))`.
pub fn leave_limit(node_count: u16) -> u16 {
    (2.0f32.powf(10.0f32) * (node_count as f32).ln()).trunc() as u16
}
