use core::task::{Poll, Waker};

use tokio::io::{split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

pub struct BufferedStream<const N: usize> {
    buffer: [u8; N],
    read_offset: usize,
    size: usize,
    is_closed: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

pub fn buffered_stream<const N: usize>(
) -> (ReadHalf<BufferedStream<N>>, WriteHalf<BufferedStream<N>>) {
    split(BufferedStream::new_unsplit())
}

impl<const N: usize> BufferedStream<N> {
    pub fn new_unsplit() -> Self {
        Self {
            buffer: [0; N],
            read_offset: 0,
            size: 0,
            is_closed: false,
            read_waker: None,
            write_waker: None,
        }
    }

    pub fn close(&mut self) {
        self.is_closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
    }
}

impl<const N: usize> AsyncRead for BufferedStream<N> {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.size == 0 && self.is_closed {
            return Poll::Ready(Ok(()));
        }

        if self.size == 0 {
            self.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        let to_move = (N - self.read_offset).min(self.size).min(buf.remaining());
        buf.put_slice(&self.buffer[self.read_offset..self.read_offset + to_move]);
        self.read_offset = (self.read_offset + to_move) % N;
        self.size -= to_move;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl<const N: usize> AsyncWrite for BufferedStream<N> {
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.is_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }

        let write_offset = (self.read_offset + self.size) % N;
        let to_write = (N - write_offset).min(N - self.size).min(buf.len());
        if to_write != 0 {
            self.buffer[write_offset..to_write + write_offset].copy_from_slice(&buf[..to_write]);
            self.size += to_write;
            if let Some(waker) = self.read_waker.take() {
                waker.wake();
            }
        } else if !buf.is_empty() {
            self.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(to_write))
    }

    fn poll_flush(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.size == 0 {
            Poll::Ready(Ok(()))
        } else {
            self.write_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.is_closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        self.poll_flush(cx)
    }
}
