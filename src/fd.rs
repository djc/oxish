use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::net::UnixStream as StdUnixStream,
    },
};

use core::pin::Pin;
use core::ptr::null_mut;
use core::task::{ready, Context, Poll};

use tokio::{
    io::{unix::AsyncFd, AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::UnixStream,
};

fn make_iovec() -> libc::iovec {
    libc::iovec {
        iov_base: [0].as_mut_ptr().cast(),
        iov_len: 1,
    }
}

fn make_msghdr(
    iov: &mut libc::iovec,
    buf: &mut [u8; unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _],
) -> libc::msghdr {
    libc::msghdr {
        msg_name: null_mut(),
        msg_namelen: 0,
        msg_iov: iov,
        msg_iovlen: 1,
        msg_control: buf.as_mut_ptr().cast(),
        #[allow(trivial_numeric_casts)]
        msg_controllen: buf.len() as _,
        msg_flags: 0,
    }
}

//TODO: can be replaced with [0; _] once MSRV is bumped high enough
fn zero_array<const N: usize>() -> [u8; N] {
    [0; N]
}

pub(crate) fn send_fd(socket: &mut StdUnixStream, mut fd: RawFd) -> io::Result<()> {
    let mut iov = make_iovec();
    let mut buf = zero_array();
    let mut msgh = make_msghdr(&mut iov, &mut buf);

    let cmsgp = unsafe { libc::CMSG_FIRSTHDR(&raw mut msgh) };

    #[allow(trivial_numeric_casts)]
    unsafe {
        (*cmsgp).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _
    };
    unsafe { (*cmsgp).cmsg_level = libc::SOL_SOCKET };
    unsafe { (*cmsgp).cmsg_type = libc::SCM_RIGHTS };
    unsafe {
        libc::memcpy(
            libc::CMSG_DATA(cmsgp).cast(),
            (&raw mut fd).cast(),
            size_of::<RawFd>(),
        )
    };

    if unsafe { libc::sendmsg(socket.as_raw_fd(), &raw mut msgh, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub(crate) async fn recv_fd(socket: &mut UnixStream) -> io::Result<RawFd> {
    socket
        .async_io(Interest::READABLE, || {
            let mut iov = make_iovec();
            let mut buf = zero_array();
            let mut msgh = make_msghdr(&mut iov, &mut buf);

            if unsafe { libc::recvmsg(socket.as_raw_fd(), &raw mut msgh, 0) } == -1 {
                return Err(io::Error::last_os_error());
            }

            let cmsgp = unsafe { libc::CMSG_FIRSTHDR(&raw mut msgh) };

            #[allow(trivial_numeric_casts)]
            if (cmsgp.is_null())
                || (unsafe { (*cmsgp).cmsg_len != libc::CMSG_LEN(size_of::<RawFd>() as _) as _ })
                || (unsafe { (*cmsgp).cmsg_level != libc::SOL_SOCKET })
                || (unsafe { (*cmsgp).cmsg_type != libc::SCM_RIGHTS })
            {
                return Err(io::Error::other("received invalid message"));
            }

            let mut fd: RawFd = 0;

            unsafe {
                libc::memcpy(
                    (&raw mut fd).cast(),
                    libc::CMSG_DATA(cmsgp).cast(),
                    size_of::<RawFd>(),
                )
            };

            Ok(fd)
        })
        .await
}

pub(crate) struct FdStream {
    inner: AsyncFd<OwnedFd>,
}

impl FdStream {
    pub(crate) unsafe fn from_raw(fd: RawFd) -> io::Result<Self> {
        Ok(Self {
            inner: AsyncFd::new(unsafe { OwnedFd::from_raw_fd(fd) })?,
        })
    }
}

impl AsyncRead for FdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                let len = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        unfilled.as_mut_ptr().cast(),
                        unfilled.len(),
                    )
                };

                if len == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(len as usize)
                }
            }) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for FdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;

            match guard.try_io(|inner| {
                let len = unsafe { libc::write(inner.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };

                if len == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(len as usize)
                }
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if unsafe { libc::close(self.inner.as_raw_fd()) } == -1 {
            return Poll::Ready(Err(io::Error::last_os_error()));
        }

        Poll::Ready(Ok(()))
    }
}
