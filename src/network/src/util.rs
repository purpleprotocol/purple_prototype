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

use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite}; //, Result as TokioResult, Error};
use futures_io::{AsyncRead, AsyncWrite, Result as TokioResult, Error};
use std::pin::Pin;
use std::task::{Context, Poll};

/// `futures-io` based socket wrapper over tokio 2.0 socket.
pub struct FuturesIoSock<'a, S: TokioAsyncRead + TokioAsyncWrite + Unpin> {
    /// Owned socket
    sock: S,
    
    /// Inner socket ref
    inner_ref: Pin<&'a mut S>,
}

impl<'a, S: TokioAsyncRead + TokioAsyncWrite + Unpin> FuturesIoSock<'a, S> {
    pub fn new(sock: S) -> Self {
        let inner_ref = Pin::new(&mut sock);
        FuturesIoSock { sock, inner_ref }
    }
}

impl<'a, S: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncRead for FuturesIoSock<'a, S> {
    fn poll_read(
        self: Pin<&mut Self>, 
        ctx: &mut Context, 
        buf: &mut [u8]
    ) -> Poll<TokioResult<usize>> {
        self.inner_ref.poll_read(ctx, buf)
    }
}

impl<'a, S: TokioAsyncRead + TokioAsyncWrite + Unpin> AsyncWrite for FuturesIoSock<'a, S> {
    fn poll_write(
        self: Pin<&mut Self>, 
        ctx: &mut Context, 
        buf: &[u8]
    ) -> Poll<Result<usize, Error>> {
        self.inner_ref.poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Result<(), Error>> {
        self.inner_ref.poll_flush(ctx)
    }

    fn poll_close(
        self: Pin<&mut Self>, 
        ctx: &mut Context
    ) -> Poll<Result<(), Error>> {
        self.inner_ref.poll_shutdown(ctx)
    }
} 