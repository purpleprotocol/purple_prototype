/*
  Copyright (C) 2018-2020 The Purple Core Developers.
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

use tokio::io::{AsyncRead, AsyncWrite, Result as TokioResult, Error};
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionType {
    /// A `Client` connection type
    Client,
    
    /// A `Server` connection type
    Server,
}

/// Multiplexed socket wrapper over an ordered, reliable  
/// protocol such as TCP. For usage with tokio.
pub struct YamuxSock<S: AsyncRead + AsyncWrite> {
    /// Inner socket
    inner: S,

    /// The type of the connection
    mode: ConnectionType,
}

impl<S: AsyncRead + AsyncWrite> YamuxSock<S> {
    pub fn new(sock: S, mode: ConnectionType) -> Self {
        YamuxSock { inner: sock, mode }
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for YamuxSock<S> {
    fn poll_read(
        self: Pin<&mut Self>, 
        cx: &mut Context, 
        buf: &mut [u8]
    ) -> Poll<TokioResult<usize>> {
        unimplemented!();
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncWrite for YamuxSock<S> {
    fn poll_write(
        self: Pin<&mut Self>, 
        cx: &mut Context, 
        buf: &[u8]
    ) -> Poll<Result<usize, Error>> {
        unimplemented!();
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), Error>> {
        unimplemented!();
    }

    fn poll_shutdown(
        self: Pin<&mut Self>, 
        cx: &mut Context
    ) -> Poll<Result<(), Error>> {
        unimplemented!();
    }
}