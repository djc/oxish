use core::{
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll},
};
use std::{env, io, process::Stdio};

use proto::channels::{PtyReq, WindowChange};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tracing::debug;

/// A session "terminal" backed by plain pipes
///
/// A real Windows pseudo-terminal (ConPTY) requires spawning the shell with a proc-thread
/// attribute list, which `std::process::Command` cannot express, so until that is implemented
/// the shell runs with pipes for its standard streams; terminal modes, the window size and
/// resize requests are accepted but ignored.
pub(crate) struct Terminal {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    stderr: ChildStderr,
}

impl Terminal {
    pub(crate) fn spawn(req: &PtyReq<'_>, env: &[(String, String)]) -> io::Result<Self> {
        debug!(?req, ?env, "spawning new session with pipes");
        let shell = env::var("SHELL")
            .or_else(|_| env::var("ComSpec"))
            .unwrap_or_else(|_| "cmd.exe".into());
        let mut cmd = Command::new(&shell);

        for (k, v) in env {
            cmd.env(k, v);
        }
        if !req.term.is_empty() {
            cmd.env("TERM", req.term.as_ref());
        }

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        Ok(Self {
            stdin: child.stdin.take().expect("stdin was piped"),
            stdout: child.stdout.take().expect("stdout was piped"),
            stderr: child.stderr.take().expect("stderr was piped"),
            child,
        })
    }

    /// Resize the PTY window (in response to a window-change request)
    pub(crate) fn resize(&self, size: &WindowChange) -> io::Result<()> {
        debug!(?size, "ignoring window resize without ConPTY support");
        Ok(())
    }

    /// Write data to the shell's standard input
    pub(crate) async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.stdin.write_all(data).await
    }

    /// Read data from the shell (its standard output or standard error)
    ///
    /// Yields `Ok(0)` only once both streams have reached end-of-file.
    pub(crate) fn poll_read(
        &mut self,
        buf: &mut [u8],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = ReadBuf::new(buf);
        let mut pending = false;
        for stream in [
            Pin::new(&mut self.stdout) as Pin<&mut dyn AsyncRead>,
            Pin::new(&mut self.stderr) as Pin<&mut dyn AsyncRead>,
        ] {
            match stream.poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => match read_buf.filled().len() {
                    0 => continue, // end-of-file on this stream
                    len => return Poll::Ready(Ok(len)),
                },
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => pending = true,
            }
        }

        match pending {
            true => Poll::Pending,
            false => Poll::Ready(Ok(0)),
        }
    }

    pub(crate) fn poll_kill(mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let future = self.child.kill();
        let pinned = pin!(future);
        pinned.poll(cx)
    }
}
