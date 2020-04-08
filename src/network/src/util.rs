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

use tokio::io; //, Result as TokioResult, Error};
use futures_io::{AsyncRead, AsyncWrite, Result as TokioResult, Error};
use std::pin::Pin;
use std::task::{Context, Poll};

/// `futures-io` based socket wrapper over tokio 2.0 socket.
pub struct FuturesIoSock<S: io::AsyncRead + io::AsyncWrite + Unpin> {
    /// Owned socket
    sock: S,
}

impl<S: io::AsyncRead + io::AsyncWrite + Unpin> FuturesIoSock<S> {
    pub fn new(sock: S) -> Self {
        Self { sock }
    }
}

impl<S: io::AsyncRead + io::AsyncWrite + Unpin> AsyncRead for FuturesIoSock<S> {
    fn poll_read(
        mut self: Pin<&mut Self>, 
        ctx: &mut Context, 
        buf: &mut [u8]
    ) -> Poll<TokioResult<usize>> {
        Pin::new(&mut self.sock).poll_read(ctx, buf)
    }
}

impl<S: io::AsyncRead + io::AsyncWrite + Unpin> AsyncWrite for FuturesIoSock<S> {
    fn poll_write(
        mut self: Pin<&mut Self>, 
        ctx: &mut Context, 
        buf: &[u8]
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.sock).poll_write(ctx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.sock).poll_flush(ctx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>, 
        ctx: &mut Context
    ) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.sock).poll_shutdown(ctx)
    }
} 