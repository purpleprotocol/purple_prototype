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

use NodeId;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: Option<NodeId>,
    pub ip: SocketAddr
}

impl Peer {
    pub fn new(id: Option<NodeId>, ip: SocketAddr) -> Peer {
        Peer {
            id: id,
            ip: ip
        }
    }

    pub fn set_id(&mut self, id: NodeId) {
        self.id = Some(id);
    } 
}